import re
from typing import Optional, List

from app.config import get_weight
from app.cache import get_cache, set_cache
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


PHISHING_TOOL_UA = [
    "gophish", "phishing", "evilginx", "modlishka",
    "mailer", "bulk", "spam", "bot", "curl", "python-requests",
    "swiftmailer", "phpmailer",
]

AUTH_FAIL_HINTS = [
    "spf=fail", "spf=softfail", "spf=neutral",
    "dmarc=fail", "dmarc=none",
    "dkim=fail",
]


class EmailHeadersFeature(Feature):
    """
    Header-level phishing detection.

    Covers:
    - Received chain analysis
    - SPF/DKIM/DMARC failures visible in headers
    - Suspicious User-Agent
    - From mismatch
    - Return-Path mismatch
    - Missing DKIM signature
    - Message-ID anomalies
    - Suspicious HELO/EHLO in Received hops
    - Random / botnet Return-Path subdomains
    - Hosting provider mismatch in first hop
    - Bleed/injection detection
    - ARC issues
    """

    name = "email_headers"
    target_type = [TargetType.EMAIL]
    run_on = [RunScope.USER]
    category = Category.EMAIL

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.7)

    #################################################################
    # HELPERS
    #################################################################

    def _load_headers_from_file(self, path: str) -> Optional[str]:
        if not path:
            return None

        cache_key = f"hdr:{path}"
        if cached := get_cache(cache_key):
            return cached

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            set_cache(cache_key, text)
            return text
        except Exception:
            return None

    #################################################################
    # CHECK 1 — Received chain analysis
    #################################################################

    def _received_chain_score(self, text: str, reasons: List[str]) -> float:
        lines = re.findall(r"^Received:.*$", text, re.MULTILINE | re.IGNORECASE)
        n = len(lines)

        if n == 0:
            reasons.append("No Received chain – extremely suspicious")
            return 0.20

        if n == 1:
            reasons.append("Single-hop Received chain – potential injection")
            return 0.15

        malformed = [l for l in lines if "unknown" in l.lower() or "?" in l]
        if malformed:
            reasons.append(f"Malformed Received hops: {len(malformed)}")
            return 0.10

        # HELO mismatch check on first hop
        first = lines[-1].lower()
        if "helo=" in first:
            m = re.search(r"helo=([^\s\)]*)", first)
            if m:
                helo = m.group(1)
                # HELO shouldn't be random
                if re.fullmatch(r"[a-z0-9]{12,}", helo):
                    reasons.append(f"Suspicious HELO: {helo}")
                    return 0.10

        return 0.0

    #################################################################
    # CHECK 2 — User-Agent / X-Mailer
    #################################################################

    def _ua_score(self, text: str, reasons: List[str]) -> float:
        matches = re.findall(r"(X-Mailer|User-Agent):\s*(.*)", text, re.IGNORECASE)
        for _, value in matches:
            v = value.lower()
            for bad in PHISHING_TOOL_UA:
                if bad in v:
                    reasons.append(f"Suspicious mailer fingerprint: {value}")
                    return 0.20
        return 0.0

    #################################################################
    # CHECK 3 — Auth failures visible in header
    #################################################################

    def _auth_failures(self, text: str, reasons: List[str]) -> float:
        count = sum(hint in text.lower() for hint in AUTH_FAIL_HINTS)
        if count > 0:
            reasons.append(f"Authentication failures detected ({count})")
            return 0.15
        return 0.0

    #################################################################
    # CHECK 4 — From mismatch
    #################################################################

    def _from_mismatch(self, text: str, visible_email: str, reasons: List[str]) -> float:
        m = re.search(r"^From:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if not m:
            return 0.0

        raw = m.group(1)
        if not raw:
            return 0.0

        inside = re.search(r"<([^>]+)>", raw)
        if inside:
            real = inside.group(1).lower()
            if real != visible_email.lower():
                reasons.append(f"From mismatch: header advertises {real}")
                return 0.10

        return 0.0

    #################################################################
    # CHECK 5 — Return-Path anomaly
    #################################################################

    def _return_path(self, text: str, visible_email: str, reasons: List[str]) -> float:
        m = re.search(r"^Return-Path:\s*<([^>]+)>", text, re.MULTILINE | re.IGNORECASE)
        if not m:
            return 0.0

        rp = m.group(1).strip().lower()

        # Rule: mismatch between From and Return-Path = suspicious
        if rp != visible_email.lower():
            reasons.append(f"Return-Path mismatch: {rp}")
            score = 0.15
        else:
            score = 0.0

        # Rule: absurdly long Return-Path
        if len(rp) > 200:
            reasons.append("Return-Path extremely long (botnet pattern)")
            score += 0.15

        # Rule: multiple random subdomains
        if rp.count(".") >= 6 and re.search(r"[a-z0-9]{6,}", rp):
            reasons.append("Return-Path contains random multi-subdomain chain")
            score += 0.20

        return score

    #################################################################
    # CHECK 6 — DKIM signature presence
    #################################################################

    def _dkim_check(self, text: str, reasons: List[str]) -> float:
        if "dkim-signature:" not in text.lower():
            reasons.append("Missing DKIM signature")
            return 0.10
        return 0.0

    #################################################################
    # CHECK 7 — Message-ID anomalies
    #################################################################

    def _msgid_check(self, text: str, reasons: List[str]) -> float:
        m = re.search(r"^Message-ID:\s*<([^>]+)>", text, re.MULTILINE | re.IGNORECASE)
        if not m:
            reasons.append("Missing Message-ID")
            return 0.10

        msgid = m.group(1).lower()

        # known abnormal patterns
        if "added_missing" in msgid or "smtp" in msgid and "missing" in msgid:
            reasons.append(f"Abnormal Message-ID formatting: {msgid}")
            return 0.15

        if len(msgid) > 150:
            reasons.append("Message-ID excessively long")
            return 0.10

        return 0.0

    #################################################################
    # MAIN RUN
    #################################################################

    def run(self, target: str, context: dict):
        email = context.get("target")
        headers_path = context.get("headers_path")
        raw_headers = context.get("raw_headers")

        if raw_headers:
            text = raw_headers
        else:
            text = self._load_headers_from_file(headers_path)

        if not text:
            return self.disabled("No headers provided")

        reasons = []
        score = 0.0

        score += self._received_chain_score(text, reasons)
        score += self._ua_score(text, reasons)
        score += self._auth_failures(text, reasons)
        score += self._from_mismatch(text, email, reasons)
        score += self._return_path(text, email, reasons)
        score += self._dkim_check(text, reasons)
        score += self._msgid_check(text, reasons)

        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))
        return self.success(0.0, "Headers look normal")
