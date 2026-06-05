SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "safe": 5,
}

SEVERITY_SCORE = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "safe": 0,
}

LEVEL_LABELS = {
    "safe": "安全",
    "low": "低危",
    "medium": "中危",
    "high": "高危",
    "critical": "严重",
}


def normalize_severity(value: str) -> str:
    v = (value or "info").lower().strip()
    if v in SEVERITY_ORDER:
        return v
    aliases = {
        "严重": "critical",
        "高危": "high",
        "中危": "medium",
        "低危": "low",
        "信息": "info",
    }
    return aliases.get(v, "info")


def aggregate_risk(findings: list[dict]) -> tuple[str, int]:
    if not findings:
        return "safe", 0
    worst = min(findings, key=lambda f: SEVERITY_ORDER.get(normalize_severity(f.get("severity", "info")), 4))
    sev = normalize_severity(worst.get("severity", "info"))
    base = SEVERITY_SCORE.get(sev, 10)
    count_bonus = min(len(findings) * 2, 20)
    score = min(100, base + count_bonus)
    if score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 45:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "safe"
    return level, score


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(normalize_severity(f.get("severity", "info")), 4),
    )
