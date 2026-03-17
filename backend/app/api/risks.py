from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.schemas.cve import CVEOut, CVEDetailOut, CVERiskOut, CVECreate, PaginatedCVEOut
from app.schemas.risk import BWVSResultOut, RiskSummaryOut, CVEScoreRequest, TopRisksResponse
from app.risk_engine.bwvs import BWVSCalculator
from app.risk_engine.ranking import PriorityRanker

router = APIRouter()
bwvs_calc = BWVSCalculator()
priority_ranker = PriorityRanker()


@router.get("/top10", response_model=TopRisksResponse)
async def get_top10(db: AsyncSession = Depends(get_db)) -> TopRisksResponse:
    result = await db.execute(
        select(CVE).order_by(CVE.priority_rank.desc().nullslast()).limit(10)
    )
    cves = result.scalars().all()
    risks = [
        CVERiskOut(
            cve_id=c.id,
            bwvs_score=c.bwvs_score or 0.0,
            risk_level=bwvs_calc.risk_level(c.bwvs_score or 0.0),
            priority_rank=c.priority_rank or 0.0,
        )
        for c in cves
    ]
    return TopRisksResponse(risks=risks)


@router.get("/summary", response_model=RiskSummaryOut)
async def get_summary(db: AsyncSession = Depends(get_db)) -> RiskSummaryOut:
    total = (await db.execute(select(func.count(CVE.id)))).scalar() or 0
    avg_bwvs = (await db.execute(select(func.avg(CVE.bwvs_score)))).scalar() or 0.0

    critical = (await db.execute(
        select(func.count(CVE.id)).where(CVE.bwvs_score >= 80)
    )).scalar() or 0
    high = (await db.execute(
        select(func.count(CVE.id)).where(CVE.bwvs_score >= 60, CVE.bwvs_score < 80)
    )).scalar() or 0
    medium = (await db.execute(
        select(func.count(CVE.id)).where(CVE.bwvs_score >= 40, CVE.bwvs_score < 60)
    )).scalar() or 0
    low = (await db.execute(
        select(func.count(CVE.id)).where(CVE.bwvs_score < 40)
    )).scalar() or 0

    return RiskSummaryOut(
        total_cves=total, critical=critical, high=high,
        medium=medium, low=low, average_bwvs=round(avg_bwvs, 2),
    )


@router.post("/calculate", response_model=BWVSResultOut)
async def calculate_bwvs(data: CVEScoreRequest) -> BWVSResultOut:
    result = bwvs_calc.calculate(
        cvss_score=data.cvss_score,
        exploit_maturity=data.exploit_maturity,
        exposure=data.exposure,
        asset_criticality=data.asset_criticality,
        business_impact=data.business_impact,
    )
    return BWVSResultOut(
        cve_id=data.cve_id,
        bwvs_score=result["bwvs_score"],
        risk_level=result["risk_level"],
        breakdown=result["breakdown"],
    )


@router.get("/cves", response_model=PaginatedCVEOut)
async def list_cves(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    min_bwvs: float | None = None,
    is_kev: bool | None = None,
    severity: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> PaginatedCVEOut:
    query = select(CVE).order_by(CVE.bwvs_score.desc().nullslast())
    count_q = select(func.count(CVE.id))

    if min_bwvs is not None:
        query = query.where(CVE.bwvs_score >= min_bwvs)
        count_q = count_q.where(CVE.bwvs_score >= min_bwvs)
    if is_kev is not None:
        query = query.where(CVE.is_kev == is_kev)
        count_q = count_q.where(CVE.is_kev == is_kev)
    if search:
        query = query.where(CVE.id.ilike(f"%{search}%") | CVE.description.ilike(f"%{search}%"))
        count_q = count_q.where(CVE.id.ilike(f"%{search}%") | CVE.description.ilike(f"%{search}%"))

    total = (await db.execute(count_q)).scalar() or 0
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)

    return PaginatedCVEOut(
        items=[CVEOut.model_validate(c) for c in result.scalars().all()],
        total=total, page=page, limit=limit,
    )


@router.post("/cves", response_model=CVEDetailOut, status_code=201)
async def create_cve(
    data: CVECreate, db: AsyncSession = Depends(get_db),
) -> CVEDetailOut:
    existing = await db.execute(select(CVE).where(CVE.id == data.id))
    if existing.scalar_one_or_none():
        raise HTTPException(409, f"CVE {data.id} already exists")

    bwvs_result = bwvs_calc.calculate(
        cvss_score=data.cvss_score or 0.0,
        exploit_maturity=data.exploit_maturity or "unknown",
    )
    bwvs_score = bwvs_result["bwvs_score"]

    priority_rank = priority_ranker.calculate_priority(
        bwvs_score=bwvs_score,
        published_date=data.published_date,
        epss_score=data.epss_score or 0.0,
    )

    cve = CVE(
        id=data.id,
        description=data.description,
        cvss_score=data.cvss_score,
        cvss_vector=data.cvss_vector,
        epss_score=data.epss_score,
        is_kev=data.is_kev,
        published_date=data.published_date,
        modified_date=data.modified_date,
        affected_products=data.affected_products,
        cwe_ids=data.cwe_ids,
        exploit_available=data.exploit_available,
        exploit_maturity=data.exploit_maturity,
        bwvs_score=bwvs_score,
        priority_rank=priority_rank,
    )
    db.add(cve)
    await db.flush()
    return CVEDetailOut.model_validate(cve)


@router.get("/cves/{cve_id}", response_model=CVEDetailOut)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)) -> CVEDetailOut:
    result = await db.execute(select(CVE).where(CVE.id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(404, "CVE not found")
    return CVEDetailOut.model_validate(cve)


@router.delete("/cves/{cve_id}", status_code=204)
async def delete_cve(
    cve_id: str, db: AsyncSession = Depends(get_db),
) -> Response:
    result = await db.execute(select(CVE).where(CVE.id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(404, "CVE not found")
    await db.delete(cve)
    await db.flush()
    return Response(status_code=204)
