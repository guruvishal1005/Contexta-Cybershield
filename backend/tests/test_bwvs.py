"""BWVS Calculator unit tests — five input sets per spec."""

from app.risk_engine.bwvs import BWVSCalculator

calc = BWVSCalculator()


def test_max_all_factors():
    result = calc.calculate(
        cvss_score=10.0,
        exploit_maturity="weaponised",
        exposure="internet_facing",
        asset_criticality=10,
        business_impact=10.0,
    )
    assert abs(result["bwvs_score"] - 100.0) <= 0.5
    assert result["risk_level"] == "Critical"


def test_min_all_factors():
    result = calc.calculate(
        cvss_score=0.0,
        exploit_maturity="none",
        exposure="isolated",
        asset_criticality=1,
        business_impact=0.0,
    )
    assert result["bwvs_score"] < 15.0
    assert result["risk_level"] == "Low"


def test_ml_threat_stays_zero():
    result = calc.calculate(
        cvss_score=7.5,
        exploit_maturity="functional",
        exposure="internal",
        asset_criticality=8,
        business_impact=6.0,
    )
    assert result["breakdown"]["ml_threat"] == 0.0
    assert result["bwvs_score"] > 0


def test_mid_range_realistic_1():
    result = calc.calculate(
        cvss_score=7.5,
        exploit_maturity="functional",
        exposure="dmz",
        asset_criticality=7,
        business_impact=6.5,
    )
    assert 50 <= result["bwvs_score"] <= 80
    assert result["risk_level"] in ("Medium", "High")


def test_mid_range_realistic_2():
    result = calc.calculate(
        cvss_score=4.0,
        exploit_maturity="proof-of-concept",
        exposure="internal",
        asset_criticality=5,
        business_impact=3.0,
    )
    assert 20 <= result["bwvs_score"] <= 50
    assert result["risk_level"] in ("Low", "Medium")
