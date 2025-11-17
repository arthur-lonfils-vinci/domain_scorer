import ssl
import socket
import datetime
from app.features.base import Feature


class TLSCertFeature(Feature):
    name = "tls_cert"
    max_score = 0.05
    target_type = "domain"

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
            return {"score": score, "reason": f"TLS validity={validity} days"}
        except Exception as e:  # noqa: BLE001
            # Some domains legitimately have no HTTPS – mild suspicion only.
            return {"score": self.max_score * 0.5, "reason": f"TLS error: {e}"}
