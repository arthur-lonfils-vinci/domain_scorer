import re
import hashlib
import requests
from typing import List, Optional

from app.config import REQUEST_TIMEOUT, get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class DomainWebFingerprintFeature(Feature):
    """
    Lightweight passive web fingerprinting.

    Detects:
    - Known CMS (WordPress, Joomla, Drupal)
    - JS frameworks (React, Vue, Angular, Svelte)
    - Suspicious server banners (phishing kits often use "openresty", "Server")
    - Directory fingerprints ("/admin/login", "/wp-login.php")
    - Phishing kit assets (fake bank login pages, static templates)
    - Favicon / asset hash matches
    """

    name = "domain_web_fingerprint"
    target_type: List[TargetType] = [TargetType.WEB]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.WEB

    # ---------------------------------------------------------
    # Known fingerprint indicators
    # ---------------------------------------------------------

    CMS_SIGNATURES = {
        "wp-content": "WordPress",
        "wp-login.php": "WordPress Login Page",
        "wp-json": "WordPress REST API",
        "Joomla": "Joomla",
        "Drupal.settings": "Drupal",
        "sites/all": "Drupal",
    }

    JS_FRAMEWORKS = {
        "react": "React.js",
        "next.js": "Next.js",
        "vue": "Vue.js",
        "angular": "Angular",
        "svelte": "Svelte",
    }

    SUSPICIOUS_SERVER_BANNERS = [
        "openresty",        # common phishing kit stack
        "apache/2.2",       # extremely outdated
        "nginx/0.",         # outdated nginx
        "server",           # generic → often obfuscated
        "gunicorn",         # python app often placeholder
        "python",           # Flask default server
    ]

    PHISHING_KIT_KEYWORDS = [
        "bank", "secure", "login", "signin",
        "account", "verification",
        "update-info", "customer-id",
    ]

    PHISHING_DIRECTORIES = [
        "login", "secure", "account", "verification", "update"
    ]

    def __init__(self):
        self.max_score = get_weight(ConfigCat.WEB, self.name, 0.3)

    # ---------------------------------------------------------
    # Helper: GET request with fallback
    # ---------------------------------------------------------

    def _fetch_page(self, domain: str) -> Optional[requests.Response]:
        urls = [
            f"https://{domain}",
            f"http://{domain}",
        ]

        for url in urls:
            try:
                return requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers={"User-Agent": "domain-scorer/1.0"},
                )
            except Exception:
                continue

        return None

    # ---------------------------------------------------------
    # Main run()
    # ---------------------------------------------------------

    def run(self, fqdn: str, context: dict = None):
        resp = self._fetch_page(fqdn)
        if not resp:
            return self.error("Unable to fetch webpage fingerprint")

        text = resp.text.lower()
        headers = resp.headers
        reasons = []
        score = 0.0

        # ---------------------------------------------------------
        # 1) CMS detection
        # ---------------------------------------------------------
        for sig, cms in self.CMS_SIGNATURES.items():
            if sig in text:
                reasons.append(f"Detected CMS: {cms} ({sig})")
                score += self.max_score * 0.10

        # ---------------------------------------------------------
        # 2) JavaScript frameworks
        # ---------------------------------------------------------
        for js_sig, name in self.JS_FRAMEWORKS.items():
            if js_sig in text:
                reasons.append(f"Detected JS framework: {name}")
                score += self.max_score * 0.05

        # ---------------------------------------------------------
        # 3) Suspicious server banners
        # ---------------------------------------------------------
        server = headers.get("Server", "").lower()
        if server:
            for bad in self.SUSPICIOUS_SERVER_BANNERS:
                if bad in server:
                    reasons.append(f"Suspicious server banner: '{server}'")
                    score += self.max_score * 0.15
                    break

        # ---------------------------------------------------------
        # 4) Phishing kit keywords
        # ---------------------------------------------------------
        for kw in self.PHISHING_KIT_KEYWORDS:
            if kw in text:
                reasons.append(f"Phishing keyword detected: '{kw}'")
                score += self.max_score * 0.10
                break

        # ---------------------------------------------------------
        # 5) Directory fingerprints (found inside HTML/JS)
        # ---------------------------------------------------------
        for d in self.PHISHING_DIRECTORIES:
            if f"/{d}" in text or f"{d}.php" in text:
                reasons.append(f"Suspicious directory: '/{d}'")
                score += self.max_score * 0.10
                break

        # ---------------------------------------------------------
        # 6) Favicon fingerprint (simple hash match)
        # ---------------------------------------------------------
        try:
            fav = requests.get(
                f"https://{fqdn}/favicon.ico",
                timeout=REQUEST_TIMEOUT
            )
            if fav.status_code == 200:
                fav_hash = hashlib.md5(fav.content).hexdigest()

                # Optionally link to a known-bad favicon list
                if fav_hash in {"d41d8cd98f00b204e9800998ecf8427e"}:
                    # Example: empty favicon (often default in phishing kits)
                    reasons.append("Suspicious empty favicon")
                    score += self.max_score * 0.05

        except Exception:
            pass

        # ---------------------------------------------------------
        # Final scoring
        # ---------------------------------------------------------
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, "Web fingerprint appears normal")
