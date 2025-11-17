import re
import socket
from typing import Dict, Any, Tuple

from app.scoring.score_engine import score_email_only
from app.scoring.threat_classifier import classify_email_score
from app.analyzers.domain_analyzer import analyze_domain
from app.features.local.dns_utils import resolve_dns
from app.cache import get_cache, set_cache

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_email(email: str) -> Tuple[str, str]:
    local, domain = email.split("@", 1)
    return local, domain


def check_mx_exists(domain: str) -> Tuple[int, str | None]:
    try:
        answers = resolve_dns(domain, "MX")
        return len(answers), None
    except Exception as e:  # noqa: BLE001
        return 0, f"MX lookup error: {e}"


def detect_spoof(email: str, domain: str, mx_count: int) -> Tuple[int, list[str]]:
    reasons: list[str] = []
    suspicious = 0

    if mx_count == 0:
        suspicious += 1
        reasons.append("Domain has NO MX → possible spoof")

    try:
        socket.gethostbyname(domain)
    except Exception:  # noqa: BLE001
        suspicious += 1
        reasons.append("Domain does not resolve → spoofed sender domain")

    return suspicious, reasons


def mailbox_exists(email: str) -> Tuple[bool, str]:
    """
    Very rough heuristic: if domain has no MX, mailbox likely doesn't exist.
    """
    _, domain = parse_email(email)
    try:
        answers = resolve_dns(domain, "MX")
        if len(answers) == 0:
            return False, "No MX → mailbox cannot exist"
        return True, "MX exists (mailbox likely exists)"
    except Exception:  # noqa: BLE001
        return False, "MX lookup error"


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
            "error": "Invalid email syntax",
        }
        set_cache(cache_key, result)
        return result

    local, domain = parse_email(email)

    # 1. Analyze domain
    domain_result = analyze_domain(domain)

    # 2. Email-only feature scores
    email_normalized, email_scores, email_reasons = score_email_only(email)

    # 3. Spoof + MX/mailbox heuristics
    mx_count, mx_err = check_mx_exists(domain)
    mailbox_ok, mailbox_reason = mailbox_exists(email)
    spoof_score, spoof_reasons = detect_spoof(email, domain, mx_count)

    spoof_penalty = min(0.3 * spoof_score, 0.6)  # same idea as before

    # Final numeric score
    overall_score = min(
        1.0,
        domain_result["score"]
        + spoof_penalty
        + email_normalized * 0.5,  # email features are additional
    )

    # Combine reasons into one mapping for classifier & CLI
    combined_reasons: Dict[str, str] = {}

    # Domain reasons
    combined_reasons.update(domain_result.get("feature_reasons", {}))

    # Email feature reasons
    for name, reason in email_reasons.items():
        combined_reasons[name] = reason

    # Add meta-reasons
    combined_reasons["email_mx"] = f"MX count={mx_count} ({mx_err or 'ok'})"
    combined_reasons["email_mailbox"] = f"Mailbox existence: {mailbox_reason}"
    if spoof_reasons:
        combined_reasons["email_spoof"] = "; ".join(spoof_reasons)

    # Threat classification
    threat = classify_email_score(
        overall_score,
        domain_result["threat"],
        email_scores,
        combined_reasons,
    )

    # Combine feature scores for nice CLI output
    combined_scores: Dict[str, float] = {}
    combined_scores.update(domain_result["feature_scores"])
    for name, val in email_scores.items():
        combined_scores[name] = val

    result: Dict[str, Any] = {
        "target": email,
        "type": "email",
        "score": round(overall_score, 3),
        "threat": threat,
        "domain": domain,
        "local_part": local,
        "feature_scores": combined_scores,
        "feature_reasons": combined_reasons,
        "domain_analysis": domain_result,
        "email_feature_scores": email_scores,
    }

    set_cache(cache_key, result)
    return result
