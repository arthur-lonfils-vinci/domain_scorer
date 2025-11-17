import ssl
import socket

from app.config import get_weight
from app.features.base import Feature


class TLSIssuerFeature(Feature):
    name = "tls_issuer"
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

            issuer = dict(x[0] for x in cert.get("issuer", []))
            cn = issuer.get("commonName", "")
            # For now, no scoring on issuer name, just info.
            return self.success(0.0, f"TLS Issuer={cn}")
        except Exception as e:  # noqa: BLE001
            return self.error(f"TLS issuer error: {e}")
