"""Priority ranking for CVEs.

Priority = BWVS * Freshness * TrendFactor
Freshness = pow(0.5, age_days / 7)
TrendFactor = 1.0 + min(epss_score, 1.0)
"""

from datetime import datetime, timezone


class PriorityRanker:
    def calculate_priority(
        self,
        bwvs_score: float,
        published_date: datetime | None = None,
        epss_score: float = 0.0,
    ) -> float:
        if published_date:
            if published_date.tzinfo is None:
                published_date = published_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - published_date).days
        else:
            age_days = 30

        freshness = pow(0.5, age_days / 7)
        trend_factor = 1.0 + min(epss_score, 1.0)

        priority = bwvs_score * freshness * trend_factor
        return round(priority, 4)
