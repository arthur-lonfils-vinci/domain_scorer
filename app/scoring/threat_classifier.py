from typing import Dict


def classify_domain_score(normalized: float, scores: Dict[str, float]) -> str:
    if normalized < 0.2:
        level = "Low"
    elif normalized < 0.5:
        level = "Medium"
    else:
        level = "High"

    vt = scores.get("vendor_vt", 0.0)
    pt = scores.get("vendor_phishtank", 0.0)
    abuse = scores.get("vendor_abuseipdb", 0.0)

    if vt > 0.3 or pt > 0 or abuse > 0.05:
        return "High"

    return level


def classify_email_score(
    final_score: float,
    domain_layers: Dict[str, dict],
    user_layer: Dict[str, dict],
) -> str:

    root_score = domain_layers["root"]["score"]

    if root_score < 0.2:
        level = "Low"
    elif root_score < 0.5:
        level = "Medium"
    else:
        level = "High"

    # Local-part anomalies upgrade severity
    local_score = user_layer["features"].get("email_localpart", 0.0)
    if local_score > 0:
        if level == "Low":
            level = "Medium"
        elif level == "Medium":
            level = "High"

    # Final override
    if final_score >= 0.8:
        return "High"

    return level
