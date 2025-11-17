from typing import Dict


def classify_domain_score(normalized: float, scores: Dict[str, float]) -> str:
    # Base level from global score
    if normalized < 0.2:
        level = "Low"
    elif normalized < 0.5:
        level = "Medium"
    else:
        level = "High"

    vt = scores.get("vendor_vt", 0.0) or 0.0
    pt = scores.get("vendor_phishtank", 0.0) or 0.0
    abuse = scores.get("vendor_abuseipdb", 0.0) or 0.0
    asn = scores.get("asn_reputation", 0.0) or 0.0

    # Strong vendor signals
    if vt > 0.3 or pt > 0 or abuse > 0.05:
        return "High"

    # ASN suspicious → at least Medium
    if asn > 0:
        if level == "Low":
            return "Medium"

    return level


def classify_email_score(
    overall_score: float,
    domain_level: str,
    email_scores: Dict[str, float],
    reasons: Dict[str, str],
) -> str:
    # Start from domain threat level, then escalate
    level = domain_level

    local_score = email_scores.get("email_localpart", 0.0) or 0.0

    # If mailbox obviously fake or no MX → high
    if any(
        "NO MX" in r or "No MX" in r or "Domain does not resolve" in r
        for r in reasons.values()
    ):
        return "High"

    # Highly malicious pattern in local part
    if local_score > 0:
        if level == "Low":
            level = "Medium"
        elif level == "Medium":
            level = "High"

    # Very high overall score always high
    if overall_score >= 0.8:
        return "High"

    return level
