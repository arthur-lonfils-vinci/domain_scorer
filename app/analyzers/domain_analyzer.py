from typing import Dict, Any
import tldextract

from app.scoring.score_engine import score_domain_layers
from app.scoring.threat_classifier import classify_domain_score


def extract_domains(domain: str):
    ext = tldextract.extract(domain)
    fqdn = domain
    root = ext.domain + "." + ext.suffix
    return fqdn, root


def analyze_domain(domain: str) -> Dict[str, Any]:
    fqdn, root = extract_domains(domain)

    layers = score_domain_layers(fqdn, root)

    # Final score is ROOT + attenuated FQDN (subdomain is less relevant)
    final_score = round(
        layers["root"]["score"] * 1.0 +
        layers["fqdn"]["score"] * 0.4,  # subdomains matter less
        3
    )

    threat = classify_domain_score(final_score, layers)

    return {
        "target": fqdn,
        "root_domain": root,
        "type": "domain",

        "score": final_score,
        "threat": threat,

        "layers": layers,
    }
