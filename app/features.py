import requests
import whois
import datetime
import dns.resolver
import socket
from collections import Counter
import math
import tldextract
import ssl
import hashlib

from app.cache import get_cache, set_cache
from app.config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY, SHODAN_API_KEY

# ==========================================
# CONFIG
# ==========================================

# DNS resolvers: system + public
DNS_RESOLVERS = [None, "8.8.8.8", "1.1.1.1"]

# Maximum possible contribution per feature (global score space)
MAX_FEATURE_SCORES = {
    "vendor_vt": 0.7,
    "vendor_phishtank": 0.1,
    "vendor_abuseipdb": 0.1,
    "vendor_urlscan": 0.1,
    "domain_age": 0.1,
    "dns_a_record": 0.05,
    "lexical_entropy": 0.05,
    "tls_cert": 0.05,
    "mx_record": 0.05,
    "spf_dkim": 0.05,
    "asn_reputation": 0.05,
    "shodan_enrichment": 0.1,
    "robots_txt": 0.05,
    "favicon_hash": 0.05,
    "tls_issuer": 0.05,
    "tld_risk": 0.2,
}

# ASN often seen abused (PoC list)
BAD_ASNS = {"AS9009", "AS206092", "AS20473", "AS14061"}


# ==========================================
# HELPERS
# ==========================================

def risk_on_error(key: str) -> float:
    """
    Assign a penalty for a feature when it fails.
    80% of its max contribution.
    """
    return round(MAX_FEATURE_SCORES.get(key, 0.0) * 0.8, 3)


def resolve_dns(domain: str, record_type: str):
    """
    Try multiple DNS resolvers with fallback.
    Raises Exception on total failure.
    """
    last_exc = None
    for r in DNS_RESOLVERS:
        try:
            resolver = dns.resolver.Resolver()
            if r:
                resolver.nameservers = [r]
            return resolver.resolve(domain, record_type, lifetime=3)
        except Exception as e:  # noqa: BLE001
            last_exc = e
            continue
    raise Exception(f"DNS resolution failed for all resolvers: {last_exc}")


# ==========================================
# VENDOR FEATURES
# ==========================================

def vt_domain_score(domain: str) -> dict:
    """
    VirusTotal reputation.
    score = scaled into global space (max 0.7).
    """
    cache_key = f"vt:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code != 200:
            result = {
                "score": risk_on_error("vendor_vt"),
                "reason": f"Error {resp.status_code}",
            }
            set_cache(cache_key, result)
            return result

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        raw_ratio = malicious / total  # 0–1

        scaled = raw_ratio * MAX_FEATURE_SCORES["vendor_vt"]
        reason = f"Malicious={malicious}, Suspicious={stats.get('suspicious', 0)}, Total={total}"

        result = {
            "score": round(scaled, 3),
            "reason": reason,
            "raw_ratio": round(raw_ratio, 3),
        }
        set_cache(cache_key, result)
        return result

    except Exception as e:  # noqa: BLE001
        result = {
            "score": risk_on_error("vendor_vt"),
            "reason": f"VT error: {e}",
        }
        set_cache(cache_key, result)
        return result


def phishtank_domain_score(domain: str) -> dict:
    cache_key = f"pt:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    url = f"http://checkurl.staging.phishtank.com/checkurl//?url={domain}&format=json"
    try:
        resp = requests.get(url, timeout=4)
        if resp.status_code != 200:
            result = {
                "score": risk_on_error("vendor_phishtank"),
                "reason": f"Error {resp.status_code}",
            }
            set_cache(cache_key, result)
            return result

        data = resp.json()
        if data.get("results", {}).get("valid", False):
            result = {"score": MAX_FEATURE_SCORES["vendor_phishtank"], "reason": "PhishTank flagged"}
        else:
            result = {"score": 0.0, "reason": "Not in PhishTank DB"}

        set_cache(cache_key, result)
        return result

    except Exception as e:  # noqa: BLE001
        result = {
            "score": risk_on_error("vendor_phishtank"),
            "reason": f"PhishTank error: {e}",
        }
        set_cache(cache_key, result)
        return result


def abuseipdb_score(domain: str) -> dict:
    try:
        ips = socket.gethostbyname_ex(domain)[2]
    except Exception:  # noqa: BLE001
        return {
            "score": risk_on_error("vendor_abuseipdb"),
            "reason": "Cannot resolve IP",
        }

    max_score = 0.0
    reasons = []
    for ip in ips:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            if resp.status_code != 200:
                reasons.append(f"{ip}: error {resp.status_code}")
                continue

            score_raw = resp.json().get("data", {}).get("abuseConfidenceScore", 0)
            max_score = max(max_score, score_raw / 100.0)
            reasons.append(f"{ip}: AbuseScore={score_raw}")
        except Exception as e:  # noqa: BLE001
            return {
                "score": risk_on_error("vendor_abuseipdb"),
                "reason": f"AbuseIPDB error: {e}",
            }

    scaled = min(max_score * MAX_FEATURE_SCORES["vendor_abuseipdb"], MAX_FEATURE_SCORES["vendor_abuseipdb"])
    return {"score": round(scaled, 3), "reason": "; ".join(reasons) or "No AbuseIPDB data"}


def urlscan_domain_score(domain: str) -> dict:
    try:
        headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}"},
            headers=headers,
            timeout=5,
        )
        if resp.status_code != 200:
            return {
                "score": risk_on_error("vendor_urlscan"),
                "reason": f"Error {resp.status_code}",
            }

        count = resp.json().get("total", 0)
        score = MAX_FEATURE_SCORES["vendor_urlscan"] if count > 0 else 0.0
        return {"score": score, "reason": f"URLScan results: {count}"}

    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("vendor_urlscan"),
            "reason": f"URLScan error: {e}",
        }


def asn_lookup(ip: str):
    """Resolve ASN info via BGPView (free)."""
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        resp = requests.get(url, timeout=3)
        if resp.status_code != 200:
            return None, "ASN lookup error"
        data = resp.json().get("data", {})
        asn_info = data.get("asn", {})
        asn = asn_info.get("asn")
        name = asn_info.get("name", "")
        return asn, name
    except Exception as e:  # noqa: BLE001
        return None, f"ASN lookup error: {e}"


def asn_reputation_score(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)
        asn, name = asn_lookup(ip)
        if not asn:
            return {"score": 0.0, "reason": f"ASN unknown ({name})"}

        score = MAX_FEATURE_SCORES["asn_reputation"] if asn in BAD_ASNS else 0.0
        reason = f"ASN={asn}, Name={name}"
        return {"score": score, "reason": reason}
    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("asn_reputation"),
            "reason": f"ASN rep error: {e}",
        }


def shodan_score(domain: str) -> dict:
    """Shodan port/vuln enrichment."""
    if not SHODAN_API_KEY:
        return {"score": None, "reason": "No API key"}

    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=5)

        if resp.status_code != 200:
            return {"score": None, "reason": f"Error {resp.status_code}"}

        data = resp.json()
        vulns = data.get("vulns", [])
        ports = data.get("ports", [])

        vuln_score = min(len(vulns) * 0.01, 0.05)  # up to 0.05
        port_score = 0.05 if any(p in [22, 23, 3389] for p in ports) else 0.0

        total = min(vuln_score + port_score, MAX_FEATURE_SCORES["shodan_enrichment"])
        reason = f"CVE count={len(vulns)}, Open ports={ports}"

        return {"score": round(total, 3), "reason": reason}
    except Exception as e:  # noqa: BLE001
        return {"score": None, "reason": f"Shodan error: {e}"}


# ==========================================
# INTERNAL FEATURES
# ==========================================

def dns_a_record_score(domain: str) -> dict:
    try:
        answers = resolve_dns(domain, "A")
        count = len(answers)
        score = MAX_FEATURE_SCORES["dns_a_record"] if count <= 1 else 0.0
        return {"score": score, "reason": f"A record count {count}"}
    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("dns_a_record"),
            "reason": f"DNS error: {e}",
        }


def domain_age_score(domain: str) -> dict:
    cache_key = f"whois:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        if not created:
            result = {
                "score": risk_on_error("domain_age"),
                "reason": "Missing WHOIS creation date",
            }
            set_cache(cache_key, result)
            return result

        if created.tzinfo:
            created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        days = (datetime.datetime.utcnow() - created).days

        score = MAX_FEATURE_SCORES["domain_age"] if days < 7 else 0.0
        reason = f"Domain age {days} days"

        result = {"score": score, "reason": reason}
        set_cache(cache_key, result)
        return result

    except Exception as e:  # noqa: BLE001
        # Trim long WHOIS banners
        msg = str(e)
        if len(msg) > 300:
            msg = msg[:297] + "..."
        result = {
            "score": risk_on_error("domain_age"),
            "reason": f"WHOIS error: {msg}",
        }
        set_cache(cache_key, result)
        return result


def lexical_entropy_score(domain: str) -> dict:
    ext = tldextract.extract(domain)
    name = ext.domain or ""
    if not name:
        return {"score": 0.0, "reason": "Entropy not computed (empty label)"}

    counts = Counter(name)
    length = len(name)
    probs = [c / length for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    score = MAX_FEATURE_SCORES["lexical_entropy"] if entropy > 4.5 else 0.0
    return {"score": score, "reason": f"Entropy={entropy:.2f}"}


def tls_cert_score(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        validity = (not_after - not_before).days

        score = MAX_FEATURE_SCORES["tls_cert"] if validity < 90 else 0.0
        return {"score": score, "reason": f"TLS validity {validity} days"}

    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("tls_cert"),
            "reason": f"TLS error: {e}",
        }


def mx_record_score(domain: str) -> dict:
    try:
        answers = resolve_dns(domain, "MX")
        count = len(answers)
        score = MAX_FEATURE_SCORES["mx_record"] if count == 0 else 0.0
        return {"score": score, "reason": f"MX count {count}"}
    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("mx_record"),
            "reason": f"MX error: {e}",
        }


def spf_dkim_score(domain: str) -> dict:
    try:
        answers = resolve_dns(domain, "TXT")
        txts = [r.to_text() for r in answers]
        spf = any("v=spf1" in t for t in txts)
        dkim = any("v=DKIM1" in t for t in txts)

        # Missing SPF is more suspicious than missing DKIM alone.
        score = MAX_FEATURE_SCORES["spf_dkim"] if not spf else 0.0
        reason = f"SPF={'yes' if spf else 'no'}, DKIM={'yes' if dkim else 'no'}"
        return {"score": score, "reason": reason}

    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("spf_dkim"),
            "reason": f"SPF/DKIM error: {e}",
        }


def robots_txt_score(domain: str) -> dict:
    try:
        resp = requests.get(f"https://{domain}/robots.txt", timeout=3)
        if resp.status_code == 200:
            return {"score": 0.0, "reason": "robots.txt found"}
        return {
            "score": MAX_FEATURE_SCORES["robots_txt"],
            "reason": "robots.txt missing",
        }
    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("robots_txt"),
            "reason": f"robots error: {e}",
        }


def favicon_hash_score(domain: str) -> dict:
    try:
        resp = requests.get(f"https://{domain}/favicon.ico", timeout=4)
        if resp.status_code != 200:
            return {
                "score": MAX_FEATURE_SCORES["favicon_hash"],
                "reason": "favicon missing",
            }

        h = hashlib.md5(resp.content).hexdigest()  # noqa: S324 (PoC only)
        return {"score": 0.0, "reason": f"favicon hash={h}"}
    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("favicon_hash"),
            "reason": f"favicon error: {e}",
        }


def tls_issuer_score(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_cn = issuer.get("commonName", "")
        return {"score": 0.0, "reason": f"Issuer={issuer_cn}"}

    except Exception as e:  # noqa: BLE001
        return {
            "score": risk_on_error("tls_issuer"),
            "reason": f"TLS issuer error: {e}",
        }


def tld_risk_score(domain: str) -> dict:
    """
    Very light heuristic for pseudo-TLDs like uk.com, us.com etc.
    """
    ext = tldextract.extract(domain)
    suffix = (ext.suffix or "").lower()

    if suffix in {"uk.com", "us.com"}:
        return {
            "score": MAX_FEATURE_SCORES["tld_risk"],
            "reason": f"Suspicious pseudo-TLD: {suffix}",
        }

    return {"score": 0.0, "reason": "TLD normal"}


# ==========================================
# THREAT CLASSIFICATION
# ==========================================

def classify_threat(normalized_score: float, feature_scores: dict, reasons: list[str]) -> str:
    """
    Classify threat based on normalized score and some key red flags.
    """
    # Base tier from overall normalized score
    if normalized_score < 0.15:
        level = "Low"
    elif normalized_score < 0.4:
        level = "Medium"
    else:
        level = "High"

    vt_score = feature_scores.get("vendor_vt") or 0.0
    mx_score = feature_scores.get("mx_record") or 0.0
    spf_score = feature_scores.get("spf_dkim") or 0.0
    asn_score = feature_scores.get("asn_reputation") or 0.0
    shodan_score_val = feature_scores.get("shodan_enrichment") or 0.0
    tld_risk_val = feature_scores.get("tld_risk") or 0.0

    # Strong vendor VT hit -> High
    if vt_score >= MAX_FEATURE_SCORES["vendor_vt"] * 0.5:
        level = "High"

    # Obvious "dead" infra: no DNS, no MX, TLS errors everywhere
    if any("DNS error" in r or "resolution failed" in r for r in reasons):
        level = max(level, "Medium")

    # MX completely missing + SPF bad → suspicious but not auto High
    if mx_score > 0 or spf_score > 0:
        level = max(level, "Medium")

    # Bad ASN, nasty Shodan results, suspicious TLD
    if asn_score > 0 or shodan_score_val > 0.05 or tld_risk_val > 0:
        level = max(level, "Medium")

    return level


# ==========================================
# HYBRID SCORING
# ==========================================

def normalize_score(scores: dict) -> float:
    """
    Normalize total score to 0–1 based on max possible per feature.
    """
    active_keys = [k for k in scores.keys() if k in MAX_FEATURE_SCORES]
    if not active_keys:
        return 0.0

    raw = sum((scores[k] or 0.0) for k in active_keys)
    max_total = sum(MAX_FEATURE_SCORES[k] for k in active_keys)
    if max_total == 0:
        return 0.0

    return round(raw / max_total, 2)


def hybrid_score(domain: str) -> dict:
    """
    Compute normalized hybrid score with all vendors + internal features.
    """
    # Vendor features
    vt = vt_domain_score(domain)
    pt = phishtank_domain_score(domain)
    abuse = abuseipdb_score(domain)
    urlscan = urlscan_domain_score(domain)
    asn_rep = asn_reputation_score(domain)
    shodan_enrich = shodan_score(domain)

    # Internal features
    age = domain_age_score(domain)
    dns_a = dns_a_record_score(domain)
    lexical = lexical_entropy_score(domain)
    tls = tls_cert_score(domain)
    mx = mx_record_score(domain)
    spf_dkim = spf_dkim_score(domain)
    robots = robots_txt_score(domain)
    favicon = favicon_hash_score(domain)
    tls_issuer = tls_issuer_score(domain)
    tld_risk = tld_risk_score(domain)

    scores = {
        "vendor_vt": vt["score"],
        "vendor_phishtank": pt["score"],
        "vendor_abuseipdb": abuse["score"],
        "vendor_urlscan": urlscan["score"],
        "asn_reputation": asn_rep["score"],
        "shodan_enrichment": shodan_enrich["score"] if shodan_enrich["score"] is not None else 0.0,
        "domain_age": age["score"],
        "dns_a_record": dns_a["score"],
        "lexical_entropy": lexical["score"],
        "tls_cert": tls["score"],
        "mx_record": mx["score"],
        "spf_dkim": spf_dkim["score"],
        "robots_txt": robots["score"],
        "favicon_hash": favicon["score"],
        "tls_issuer": tls_issuer["score"],
        "tld_risk": tld_risk["score"],
    }

    normalized_total = normalize_score(scores)

    reasons = [
        f"Vendor VT: {vt['reason']}",
        f"Vendor PhishTank: {pt['reason']}",
        f"Vendor AbuseIPDB: {abuse['reason']}",
        f"Vendor URLScan: {urlscan['reason']}",
        f"ASN reputation: {asn_rep['reason']}",
        f"Shodan enrichment: {shodan_enrich['reason']}",
        f"Domain age: {age['reason']}",
        f"DNS A record: {dns_a['reason']}",
        f"Lexical entropy: {lexical['reason']}",
        f"TLS certificate: {tls['reason']}",
        f"MX record: {mx['reason']}",
        f"SPF/DKIM: {spf_dkim['reason']}",
        f"robots.txt: {robots['reason']}",
        f"favicon hash: {favicon['reason']}",
        f"TLS issuer: {tls_issuer['reason']}",
        f"TLD risk: {tld_risk['reason']}",
    ]

    threat_level = classify_threat(normalized_total, scores, reasons)

    return {
        "score": normalized_total,
        "threat": threat_level,
        "reasons": reasons,
        "feature_scores": scores,
    }


def batch_score(domains: list[str]) -> dict:
    results = {}
    for d in domains:
        try:
            results[d] = hybrid_score(d)
        except Exception as e:  # noqa: BLE001
            results[d] = {"error": str(e)}
    return results
