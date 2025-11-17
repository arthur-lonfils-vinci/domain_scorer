import re
from typing import Dict, Any, Tuple

from app.analyzers.domain_analyzer import extract_domains, analyze_domain
from app.scoring.score_engine import score_email_only
from app.scoring.threat_classifier import classify_email_score

from app.cache import get_cache, set_cache

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_email(email: str) -> Tuple[str, str]:
    return email.split("@", 1)


# ----------------------------------------------------------------------
# 3-layer EMAIL ANALYSIS
# ----------------------------------------------------------------------
def analyze_email(email: str) -> Dict[str, Any]:
    cache_key = f"email:{email}"
    if cached := get_cache(cache_key):
        return cached

    if not EMAIL_REGEX.match(email):
        result = {
            "target": email,
            "type": "email",
            "score": 1.0,
            "threat": "High",
            "error": "Invalid email syntax"
        }
        set_cache(cache_key, result)
        return result

    # Parse
    local, domain = parse_email(email)
    fqdn, root = extract_domains(domain)

    # ---------------------------
    # 1) User layer
    # ---------------------------
    email_norm, email_scores, email_reasons = score_email_only(
        fqdn=fqdn,
        root=root,
        user=email
    )

    user_layer = {
        "target": email,
        "score": email_norm,
        "features": email_scores,
        "reasons": email_reasons,
    }

    # ---------------------------
    # 2) Domain layers
    # ---------------------------
    domain_layers = analyze_domain(domain)["layers"]

    root_score = domain_layers["root"]["score"]
    fqdn_score = domain_layers["fqdn"]["score"]

    # ---------------------------
    # FINAL NORMALIZED SCORE
    # ---------------------------
    fqdn_weight = 0.1  # subdomain should NOT dominate email trust
    final_raw = (
        root_score * 1.0 +
        fqdn_score * fqdn_weight +
        email_norm * 0.5
    )

    final_score = max(0.0, min(1.0, round(final_raw, 3)))

    # ---------------------------
    # Threat classification
    # ---------------------------
    threat = classify_email_score(
        final_score,
        domain_layers,
        user_layer,
    )

    result = {
        "target": email,
        "type": "email",
        "local_part": local,
        "domain": domain,
        "fqdn": fqdn,
        "root_domain": root,

        "score": final_score,
        "threat": threat,

        "layers": {
            "user": user_layer,
            "fqdn": domain_layers["fqdn"],
            "root": domain_layers["root"],
        },
    }

    set_cache(cache_key, result)
    return result
