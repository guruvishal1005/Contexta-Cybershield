"""Business-Weighted Vulnerability Score (BWVS) calculator.

Formula (with ML_Threat always 0.0, renormalised weights):
  BWVS = (CVSS*0.235 + Exploit*0.235 + Exposure*0.118
          + Asset_Criticality*0.235 + Business_Impact*0.177) * 10

Risk thresholds: 80-100 Critical, 60-79 High, 40-59 Medium, 0-39 Low.
"""

EXPLOIT_MAP: dict[str, float] = {
    "weaponised": 1.0,
    "functional": 0.8,
    "proof-of-concept": 0.5,
    "unknown": 0.2,
    "none": 0.0,
}

EXPOSURE_MAP: dict[str, float] = {
    "internet_facing": 1.0,
    "dmz": 0.7,
    "internal": 0.4,
    "isolated": 0.1,
    "unknown": 0.3,
}

W_CVSS = 0.235
W_EXPLOIT = 0.235
W_EXPOSURE = 0.118
W_ASSET_CRIT = 0.235
W_BUSINESS = 0.177


class BWVSCalculator:
    def calculate(
        self,
        cvss_score: float = 0.0,
        exploit_maturity: str = "unknown",
        exposure: str = "unknown",
        asset_criticality: int = 5,
        business_impact: float = 5.0,
    ) -> dict:
        cvss_norm = max(0.0, min(10.0, cvss_score)) / 10.0
        exploit_norm = EXPLOIT_MAP.get(exploit_maturity.lower(), 0.2)

        if isinstance(exposure, bool):
            exposure_norm = 1.0 if exposure else 0.4
        else:
            exposure_norm = EXPOSURE_MAP.get(str(exposure).lower(), 0.3)

        crit_norm = max(1, min(10, asset_criticality)) / 10.0
        biz_norm = max(0.0, min(10.0, business_impact)) / 10.0

        raw = (
            cvss_norm * W_CVSS
            + exploit_norm * W_EXPLOIT
            + exposure_norm * W_EXPOSURE
            + crit_norm * W_ASSET_CRIT
            + biz_norm * W_BUSINESS
        )
        bwvs = round(raw * 10, 2) * 10
        bwvs = round(max(0.0, min(100.0, bwvs)), 2)

        return {
            "bwvs_score": bwvs,
            "risk_level": self.risk_level(bwvs),
            "breakdown": {
                "cvss": round(cvss_norm, 4),
                "exploit": round(exploit_norm, 4),
                "exposure": round(exposure_norm, 4),
                "asset_criticality": round(crit_norm, 4),
                "business_impact": round(biz_norm, 4),
                # ML_Threat: populated from ml_service.get_ml_threat_score()
                # when ML_SERVICE_URL is set. Score is only used when
                # confidence >= CONFIDENCE_THRESHOLD (0.6).
                # Set to 0.0 here as fallback — ml_service.py handles the actual call.
                "ml_threat": 0.0,
            },
        }

    @staticmethod
    def risk_level(bwvs: float) -> str:
        if bwvs >= 80:
            return "Critical"
        if bwvs >= 60:
            return "High"
        if bwvs >= 40:
            return "Medium"
        return "Low"
