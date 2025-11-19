import ssl
import socket
from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class TLSIssuerFeature(Feature):
    """
    Extract the TLS certificate issuer CN.

    ⚠ No scoring is applied here.
      This feature exists ONLY to provide context in reports.
    """

    name = "tls_issuer"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.TLS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.1)

    # ---------------------------------------------------------

    def run(self, fqdn: str, context: dict):
        # Attempt TLS handshake (safe wrapper)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((fqdn, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
        except Exception:
            return self.disabled("TLS not available or handshake failed")

        # Extract issuer CN safely
        issuer = cert.get("issuer", [])
        issuer_dict = {}
        for part in issuer:
            # issuer is a tuple of tuples
            for key, value in part:
                issuer_dict[key] = value

        cn = issuer_dict.get("commonName", None)

        if not cn:
            return self.success(0.0, "Issuer CN missing or empty")

        return self.success(0.0, f"Issuer CN = {cn}")
