import socket
import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT


BAD_ASNS = {"AS9009", "AS206092", "AS20473", "AS14061"}


class ASNReputationFeature(Feature):
    name = "asn_reputation"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:  # noqa: BLE001
            return {"score": 0.0, "reason": f"ASN: cannot resolve ({e})"}

        try:
            resp = requests.get(
                f"https://api.bgpview.io/ip/{ip}", timeout=REQUEST_TIMEOUT
            )
            if resp.status_code != 200:
                return {
                    "score": 0.0,
                    "reason": f"ASN lookup HTTP {resp.status_code}",
                }

            data = resp.json().get("data", {})
            asn_info = data.get("asn", {})
            asn = asn_info.get("asn")
            name = asn_info.get("name", "")

            if not asn:
                return {"score": 0.0, "reason": f"ASN unknown ({name})"}

            score = self.max_score if str(asn) in BAD_ASNS else 0.0
            return {"score": score, "reason": f"ASN={asn}, Name={name}"}

        except Exception as e:  # noqa: BLE001
            return {"score": 0.0, "reason": f"ASN error: {e}"}
