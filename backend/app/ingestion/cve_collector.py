"""CVE intelligence feed collector — CISA KEV + NVD API v2.

Fetches both sources concurrently, normalises, upserts into DB,
calculates BWVS + priority_rank, and appends a ledger block.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_factory
from app.models.cve import CVE
from app.risk_engine.bwvs import BWVSCalculator
from app.risk_engine.ranking import PriorityRanker
from app.ledger.chain import ledger

logger = logging.getLogger(__name__)
bwvs_calc = BWVSCalculator()
ranker = PriorityRanker()

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _fetch_cisa() -> list[dict]:
    cves: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            for vuln in resp.json().get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if not cve_id:
                    continue
                cves.append({
                    "id": cve_id,
                    "description": vuln.get("shortDescription", ""),
                    "is_kev": True,
                    "exploit_available": True,
                    "exploit_maturity": "weaponised",
                    "published_date": vuln.get("dateAdded"),
                })
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
    return cves


async def _fetch_nvd() -> list[dict]:
    cves: list[dict] = []
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
        "%Y-%m-%dT00:00:00.000"
    )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            start_idx = 0
            while True:
                resp = await client.get(
                    NVD_API_URL,
                    params={
                        "resultsPerPage": 2000,
                        "startIndex": start_idx,
                        "lastModStartDate": seven_days_ago,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                for item in vulns:
                    cve_item = item.get("cve", {})
                    cve_id = cve_item.get("id", "")
                    if not cve_id:
                        continue

                    descs = cve_item.get("descriptions", [])
                    desc = next(
                        (d["value"] for d in descs if d.get("lang") == "en"), ""
                    )

                    metrics = cve_item.get("metrics", {})
                    v31 = metrics.get("cvssMetricV31", [{}])
                    cvss_data = v31[0].get("cvssData", {}) if v31 else {}
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")

                    cves.append({
                        "id": cve_id,
                        "description": desc,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "published_date": cve_item.get("published"),
                        "modified_date": cve_item.get("lastModified"),
                        "cwe_ids": [
                            w.get("value")
                            for pd in cve_item.get("weaknesses", [])
                            for w in pd.get("description", [])
                        ],
                    })

                total_results = data.get("totalResults", 0)
                start_idx += len(vulns)
                if start_idx >= total_results:
                    break
    except Exception as exc:
        logger.warning("NVD fetch failed: %s", exc)
    return cves


async def run() -> None:
    """Main collection run — called by scheduler."""
    cisa_cves, nvd_cves = await asyncio.gather(_fetch_cisa(), _fetch_nvd())

    merged: dict[str, dict] = {}
    for c in nvd_cves:
        merged[c["id"]] = c
    for c in cisa_cves:
        cid = c["id"]
        if cid in merged:
            merged[cid].update({k: v for k, v in c.items() if v})
        else:
            merged[cid] = c

    new_count = 0
    updated_count = 0

    async with async_session_factory() as db:
        try:
            for cve_data in merged.values():
                cve_id = cve_data["id"]
                existing = await db.execute(select(CVE).where(CVE.id == cve_id))
                existing_cve = existing.scalar_one_or_none()

                bwvs_result = bwvs_calc.calculate(
                    cvss_score=cve_data.get("cvss_score", 0.0),
                    exploit_maturity=cve_data.get("exploit_maturity", "unknown"),
                )
                bwvs_score = bwvs_result["bwvs_score"]

                pub_date = None
                if cve_data.get("published_date"):
                    try:
                        pub_date = datetime.fromisoformat(
                            str(cve_data["published_date"]).replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                priority = ranker.calculate_priority(bwvs_score, pub_date)

                mod_date = None
                if cve_data.get("modified_date"):
                    try:
                        mod_date = datetime.fromisoformat(
                            str(cve_data["modified_date"]).replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                if existing_cve:
                    if mod_date and existing_cve.modified_date and mod_date > existing_cve.modified_date:
                        existing_cve.description = cve_data.get("description", existing_cve.description)
                        existing_cve.cvss_score = cve_data.get("cvss_score", existing_cve.cvss_score)
                        existing_cve.cvss_vector = cve_data.get("cvss_vector", existing_cve.cvss_vector)
                        existing_cve.is_kev = cve_data.get("is_kev", existing_cve.is_kev)
                        existing_cve.exploit_available = cve_data.get("exploit_available", existing_cve.exploit_available)
                        existing_cve.exploit_maturity = cve_data.get("exploit_maturity", existing_cve.exploit_maturity)
                        existing_cve.modified_date = mod_date
                        existing_cve.bwvs_score = bwvs_score
                        existing_cve.priority_rank = priority
                        updated_count += 1
                else:
                    cve = CVE(
                        id=cve_id,
                        description=cve_data.get("description", ""),
                        cvss_score=cve_data.get("cvss_score"),
                        cvss_vector=cve_data.get("cvss_vector"),
                        is_kev=cve_data.get("is_kev", False),
                        exploit_available=cve_data.get("exploit_available", False),
                        exploit_maturity=cve_data.get("exploit_maturity"),
                        published_date=pub_date,
                        modified_date=mod_date,
                        cwe_ids=cve_data.get("cwe_ids"),
                        bwvs_score=bwvs_score,
                        priority_rank=priority,
                    )
                    db.add(cve)
                    new_count += 1

            await ledger.append(
                event_type="cve_ingested",
                entity_id=None,
                payload={
                    "new_count": new_count,
                    "updated_count": updated_count,
                    "sources": ["CISA_KEV", "NVD"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                db=db,
            )
            await db.commit()
            logger.info(
                "CVE collection complete: %d new, %d updated", new_count, updated_count
            )
        except Exception:
            await db.rollback()
            raise
