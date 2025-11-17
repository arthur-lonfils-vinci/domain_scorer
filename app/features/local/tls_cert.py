import ssl
import socket
import datetime

from app.config import get_weight
from app.features.base import Feature


class TLSCertFeature(Feature):
    name = "tls_cert"
    target_type = "domain"
    run_on = "fqdn"

    def __init__(self):
        self.max_score = get_weight("domain", self.name, 0.1)

    def run(self, domain: str):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            not_before = datetime.datetime.strptime(
                cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
            )
            not_after = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            validity = (not_after - not_before).days
            score = self.max_score if validity < 90 else 0.0
            return self.success(score, f"TLS validity={validity} days")
        except Exception as e:  # noqa: BLE001
            # Some domains legitimately have no HTTPS – mild suspicion only.
            return self.error(f"TLS error: {e}")
