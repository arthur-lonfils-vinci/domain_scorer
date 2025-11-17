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

    def run(self, domain: str):
        try:
            resp = requests.get(f"https://{domain}/favicon.ico", timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return self.success(self.max_score, f"favicon missing | HTTP: {resp.status_code}")
            h = hashlib.md5(resp.content).hexdigest()
            return self.success(0.0, f"favicon hash={h}")
        except Exception as e:  # noqa: BLE001
            return self.error(f"favicon error: {e}")
