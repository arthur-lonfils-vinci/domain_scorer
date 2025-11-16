import re
import socket

from app.features import hybrid_score, resolve_dns
from app.cache import get_cache, set_cache

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_email(email: str):
    """Return (local_part, domain, error)."""
    if not EMAIL_REGEX.match(email):
        return None, None, "Invalid email syntax"
    local, domain = email.split("@", 1)
    return local, domain, None


def check_mx_exists(domain: str):
    try:
        answers = resolve_dns(domain, "MX")
        return len(answers), None
    except Exception as e:  # noqa: BLE001
        return 0, f"MX lookup error: {e}"


def spf_alignment(from_domain: str, mail_server_domain: str) -> bool:
    """
    Placeholder PoC: SPF alignment.
    In a real system you compare 'From' domain with Return-Path / envelope sender domain.
    """
    return from_domain.lower() == mail_server_domain.lower()


def detect_spoof(email: str, domain: str, mx_count: int):
    """
    Core spoof-detection logic (very PoC).
    """
    reasons = []
    suspicious = 0

    if mx_count == 0:
        suspicious += 1
        reasons.append("Domain has NO MX → likely spoofed / throwaway sender")

    try:
        socket.gethostbyname(domain)
    except Exception:  # noqa: BLE001
        suspicious += 1
        reasons.append("Domain does not resolve → spoofed sender domain")

    return suspicious, reasons


def mailbox_exists(email: str):
    """
    Optional PoC check (never 100% reliable).
    Very simple heuristic: if domain has MX, assume mailbox may exist.
    """
    local, domain, err = parse_email(email)
    if err:
        return False, "Invalid email"

    try:
        answers = resolve_dns(domain, "MX")
        if len(answers) == 0:
            return False, "No MX → mailbox cannot exist"
        return True, "MX exists (mailbox may exist)"
    except Exception:  # noqa: BLE001
        return False, "MX lookup error"


def classify_email_threat(domain_result: dict, email_result: dict) -> str:
    """
    Return threat level for an email based on:
    - domain hybrid threat
    - email score
    - spoofing / MX issues
    """
    domain_threat = domain_result.get("threat", "Low")
    score = email_result.get("score", 1.0)
    reasons = email_result.get("reasons", [])

    # Strong explicit signals
    if any("Invalid email format" in r for r in reasons):
        return "High"
    if any("NO MX" in r or "No MX" in r for r in reasons):
        return "High"
    if any("does not resolve" in r for r in reasons):
        return "High"

    # Domain-level threat
    if domain_threat == "High":
        return "High"
    if domain_threat == "Medium":
        return "Medium"

    # Fallback on numeric score
    if score >= 0.6:
        return "High"
    if score >= 0.3:
        return "Medium"

    return "Low"


def email_score(email: str) -> dict:
    """
    Combined scoring for an email:
    - domain score (hybrid)
    - spoof detection
    - MX-based mailbox heuristic
    """
    cache_key = f"email:{email}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    local, domain, err = parse_email(email)
    if err:
        result = {
            "email": email,
            "domain": None,
            "score": 1.0,
            "reasons": [f"Invalid email format ({err})"],
            "threat": "High",
        }
        set_cache(cache_key, result)
        return result

    # 1. Domain hybrid score
    domain_result = hybrid_score(domain)
    domain_score = domain_result["score"]
    domain_threat = domain_result.get("threat", "Low")

    # 2. MX / mailbox heuristic
    mx_count, mx_err = check_mx_exists(domain)
    mailbox_ok, m_reason = mailbox_exists(email)

    # 3. Spoof detection
    spoof_score, spoof_reasons = detect_spoof(email, domain, mx_count)
    spoof_penalty = min(0.3 * spoof_score, 0.6)

    # FINAL SCORE (0–1)
    final_score = min(1.0, domain_score + spoof_penalty)

    reasons = [
        f"Domain score = {domain_score}",
        f"Domain threat = {domain_threat}",
        f"MX count = {mx_count} ({mx_err if mx_err else 'ok'})",
        f"Mailbox existence: {m_reason}",
    ] + spoof_reasons + domain_result["reasons"]

    result = {
        "email": email,
        "domain": domain,
        "score": round(final_score, 2),
        "reasons": reasons,
    }

    result["threat"] = classify_email_threat(domain_result, result)

    set_cache(cache_key, result)
    return result
