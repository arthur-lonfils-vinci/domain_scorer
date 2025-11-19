import hashlib
from typing import List

import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT, get_weight
from app.features.types import TargetType, RunScope, Category, ConfigCat


class FaviconHashFeature(Feature):
    name = "favicon_hash"
    target_type: List[TargetType] = [TargetType.WEB]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.WEB

    def __init__(self):
        self.max_score = get_weight(ConfigCat.WEB, self.name, 0.05)

    def _fetch_favicon(self, fqdn: str):
        """Try HTTPS → HTTP fallback."""
        urls = [
            f"https://{fqdn}/favicon.ico",
            f"http://{fqdn}/favicon.ico",
        ]

        last_exc = None
        for url in urls:
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200:
                    return resp.content, None
                last_exc = f"HTTP {resp.status_code}"
            except Exception as e:
                last_exc = e
                continue

        return None, last_exc

    def run(self, target: str, context: dict):
        fqdn = context.get("fqdn", target)

        content, error = self._fetch_favicon(fqdn)

        # Favicon missing → small heuristic penalty
        if content is None:
            return self.success(
                self.max_score * 0.4,
                f"favicon missing ({error})"
            )

        # Hash favicon
        h = hashlib.md5(content).hexdigest()
        return self.success(0.0, f"favicon hash={h}")
