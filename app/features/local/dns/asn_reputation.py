import socket
from typing import List

import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT, get_weight
from app.features.types import TargetType, RunScope, Category, ConfigCat

BAD_ASNS = {"AS9009", "AS206092", "AS20473", "AS14061"}


class ASNReputationFeature(Feature):
    name = "asn_reputation"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.ASN

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    def run(self, domain: str):
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:  # noqa: BLE001
            return self.error(f"ASN: cannot resolve ({e})")

        try:
            resp = requests.get(
                f"https://api.bgpview.io/ip/{ip}", timeout=REQUEST_TIMEOUT
            )
            if resp.status_code != 200:
                return self.error(f"ASN HTTP: ({resp.status_code})")

            data = resp.json().get("data", {})
            asn_info = data.get("asn", {})
            asn = asn_info.get("asn")
            name = asn_info.get("name", "")

            if not asn:
                return self.success(0.0, f"ASN unknow {name}")

            score = self.max_score if str(asn) in BAD_ASNS else 0.0
            return self.success(score, f"- ASN: {asn} \n - Name: {name}")

        except Exception as e:  # noqa: BLE001
            return self.error(f"ASN: cannot resolve ({e})")
