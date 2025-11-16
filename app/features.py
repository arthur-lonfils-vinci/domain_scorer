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

# Define fallback system DNS
DNS_RESOLVERS = [
    None,  # system default
    "8.8.8.8",
    "1.1.1.1"
]

# Define maximum possible contribution per feature
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
    "tls_issuer": 0.05
}

BAD_ASNS = {
    "AS9009",     # M247 - abused often
    "AS206092",   # Host Sailor / malicious infra
    "AS20473",    # Choopa / Vultr
    "AS14061"     # DigitalOcean (mixed, high abuse)
}

# --------------------------
# Vendor feature functions
# --------------------------

def vt_domain_score(domain):
    """VirusTotal reputation with caching."""
    cache_key = f"vt:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            result = {"score": None, "reason": f"Error {resp.status_code}"}
            set_cache(cache_key, result)
            return result
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        score = stats.get("malicious", 0) / total
        reason = f"Malicious={stats.get('malicious',0)}, Suspicious={stats.get('suspicious',0)}, Total={total}"
        result = {"score": round(score, 2), "reason": reason}
        set_cache(cache_key, result)
        return result
    except Exception as e:
        result = {"score": None, "reason": f"Error querying VT: {e}"}
        set_cache(cache_key, result)
        return result

def phishtank_domain_score(domain):
    """PhishTank reputation check."""
    cache_key = f"phishtank:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    url = f"http://checkurl.staging.phishtank.com/checkurl//?url={domain}&format=json"
    try:
        resp = requests.get(url)
        if resp.status_code != 200:
            result = {"score": None, "reason": f"Error {resp.status_code}"}
            set_cache(cache_key, result)
            return result
        data = resp.json()
        if data.get("results", {}).get("valid", False):
            score = 0.1
            reason = "PhishTank flagged"
        else:
            score = 0.0
            reason = "Not in PhishTank database"
        result = {"score": score, "reason": reason}
        set_cache(cache_key, result)
        return result
    except Exception as e:
        result = {"score": None, "reason": f"Error querying PhishTank: {e}"}
        set_cache(cache_key, result)
        return result

def abuseipdb_score(domain):
    """AbuseIPDB reputation for domain IP(s)."""
    cache_key = f"abuseipdb:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    try:
        ips = socket.gethostbyname_ex(domain)[2]
        max_score = 0.0
        reasons = []
        for ip in ips:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            resp = requests.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                reasons.append(f"{ip}: error {resp.status_code}")
                continue
            data = resp.json().get("data", {})
            score_raw = data.get("abuseConfidenceScore", 0)
            max_score = max(max_score, score_raw / 100)
            reasons.append(f"{ip}: AbuseScore={score_raw}")
        score = min(max_score, 0.1)
        reason = "; ".join(reasons)
        result = {"score": score, "reason": reason}
        set_cache(cache_key, result)
        return result
    except Exception as e:
        result = {"score": None, "reason": f"Error checking AbuseIPDB: {e}"}
        set_cache(cache_key, result)
        return result

def urlscan_domain_score(domain):
    """URLScan.io reputation check."""
    cache_key = f"urlscan:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    url = "https://urlscan.io/api/v1/search/"
    params = {"q": f"domain:{domain}"}
    try:
        headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code != 200:
            result = {"score": None, "reason": f"Error {resp.status_code}"}
            set_cache(cache_key, result)
            return result
        data = resp.json()
        count = data.get("total", 0)
        score = 0.1 if count > 0 else 0.0
        reason = f"URLScan results found: {count}"
        result = {"score": score, "reason": reason}
        set_cache(cache_key, result)
        return result
    except Exception as e:
        result = {"score": None, "reason": f"Error querying URLScan: {e}"}
        set_cache(cache_key, result)
        return result

def asn_lookup(ip):
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
    except Exception as e:
        return None, f"ASN lookup error: {e}"

def asn_reputation_score(domain):
    try:
        ip = socket.gethostbyname(domain)
        asn, name = asn_lookup(ip)
        if not asn:
            return {"score": 0.0, "reason": f"ASN unknown ({name})"}

        score = 0.05 if asn in BAD_ASNS else 0.0
        reason = f"ASN={asn}, Name={name}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"ASN rep error: {e}"}

def shodan_score(domain):
    """Shodan port/vuln enrichment."""
    if not SHODAN_API_KEY:
        return {"score": None, "reason": "No API key"}

    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=4)

        if resp.status_code != 200:
            return {"score": None, "reason": f"Error {resp.status_code}"}

        data = resp.json()
        vulns = data.get("vulns", [])
        ports = data.get("ports", [])

        vuln_score = min(len(vulns) * 0.01, 0.05)  # CVEs max 0.05
        port_score = 0.05 if any(p in [22, 23, 3389] for p in ports) else 0.0

        total = vuln_score + port_score
        reason = f"CVE count={len(vulns)}, Open ports={ports}"

        return {"score": round(total, 2), "reason": reason}
    except Exception as e:
        return {"score": None, "reason": f"Shodan error: {e}"}

# --------------------------
# Internal features
# --------------------------

def resolve_dns(domain, record_type):
    """Try multiple DNS resolvers with fallback."""
    for r in DNS_RESOLVERS:
        try:
            resolver = dns.resolver.Resolver()
            if r:
                resolver.nameservers = [r]
            return resolver.resolve(domain, record_type, lifetime=3)
        except:
            continue
    raise Exception("DNS resolution failed for all resolvers")

def dns_a_record_score(domain):
    try:
        answers = resolve_dns(domain, 'A')
        count = len(answers)
        score = 0.05 if count <= 1 else 0.0
        reason = f"A record count = {count}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"Error resolving A records: {e}"}

def domain_age_score(domain):
    cache_key = f"whois:{domain}"
    cached = get_cache(cache_key)
    if cached:
        return cached
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            result = {"score": 0.0, "reason": "No valid creation date"}
            set_cache(cache_key, result)
            return result
        if created.tzinfo:
            created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        age_days = (datetime.datetime.utcnow() - created).days
        score = 0.1 if age_days < 7 else 0.0
        reason = f"Domain age {age_days} days"
        result = {"score": score, "reason": reason}
        set_cache(cache_key, result)
        return result
    except Exception as e:
        result = {"score": 0.0, "reason": f"Error checking age: {e}"}
        set_cache(cache_key, result)
        return result

def lexical_entropy_score(domain):
    ext = tldextract.extract(domain)
    name = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    counts = Counter(name)
    probs = [c / len(name) for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    score = 0.05 if entropy > 4.5 else 0.0
    reason = f"Entropy={entropy:.2f}"
    return {"score": score, "reason": reason}

def tls_cert_score(domain):
    """Check TLS certificate age / validity; short-lived or missing certs may be suspicious."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        validity_days = (not_after - not_before).days
        score = 0.05 if validity_days < 90 else 0.0  # short validity = suspicious
        reason = f"TLS certificate validity {validity_days} days"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"TLS check error: {e}"}

def mx_record_score(domain):
    """Check if domain has MX records; missing MX might indicate phishing setup."""
    try:
        answers = resolve_dns(domain, 'MX')
        count = len(answers)
        score = 0.05 if count == 0 else 0.0  # missing MX = suspicious
        reason = f"MX record count = {count}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"MX check error: {e}"}

def spf_dkim_score(domain):
    """Check for SPF / DKIM in TXT records; missing these may indicate phishing."""
    try:
        answers = resolve_dns(domain, 'TXT')
        txts = [r.to_text() for r in answers]
        spf = any("v=spf1" in t for t in txts)
        dkim = any("v=DKIM1" in t for t in txts)
        score = 0.05 if not (spf and dkim) else 0.0
        reason = f"SPF={'found' if spf else 'missing'}, DKIM={'found' if dkim else 'missing'}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"SPF/DKIM check error: {e}"}

def robots_txt_score(domain):
    """Check if robots.txt exists; missing can be suspicious."""
    try:
        url = f"https://{domain}/robots.txt"
        resp = requests.get(url, timeout=3)
        score = 0.05 if resp.status_code != 200 else 0.0
        reason = f"robots.txt {'missing' if score > 0 else 'found'}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"robots.txt check error: {e}"}

def favicon_hash_score(domain):
    """Check favicon hash similarity; uncommon hash can indicate phishing."""
    try:
        url = f"https://{domain}/favicon.ico"
        resp = requests.get(url, timeout=3)
        if resp.status_code != 200:
            return {"score": 0.05, "reason": "favicon missing"}
        hash_md5 = hashlib.md5(resp.content).hexdigest()
        # In PoC, just flag if hash length unexpected (placeholder)
        score = 0.0 if len(hash_md5) == 32 else 0.05
        reason = f"favicon hash={hash_md5}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"favicon check error: {e}"}

def tls_issuer_score(domain):
    """Check TLS issuer; free/self-signed certs can be slightly suspicious."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_cn = issuer.get("commonName", "")
        score = 0.05 if "Let's Encrypt" in issuer_cn else 0.0  # example: free certs = minor suspicion
        reason = f"TLS issuer={issuer_cn}"
        return {"score": score, "reason": reason}
    except Exception as e:
        return {"score": 0.0, "reason": f"TLS issuer check error: {e}"}


# --------------------------
# Hybrid scoring
# --------------------------

def normalize_score(scores):
    """Normalize total score to 0-1 based on max possible per feature."""
    total_raw = sum(s or 0 for s in scores.values())
    max_total = sum(MAX_FEATURE_SCORES[f] for f in scores.keys())
    normalized = round(total_raw / max_total, 2)
    return normalized

def hybrid_score(domain):
    """Compute normalized hybrid score with extra features."""
    # Vendors
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

    scores = {
        "vendor_vt": round(vt["score"]*0.7, 2) if vt["score"] is not None else None,
        "vendor_phishtank": pt["score"] if pt["score"] is not None else None,
        "vendor_abuseipdb": abuse["score"] if abuse["score"] is not None else None,
        "vendor_urlscan": urlscan["score"] if urlscan["score"] is not None else None,
        "asn_reputation": asn_rep["score"],
        "shodan_enrichment": shodan_enrich["score"] if shodan_enrich["score"] is not None else None,
        "domain_age": age["score"],
        "dns_a_record": dns_a["score"],
        "lexical_entropy": lexical["score"],
        "tls_cert": tls["score"],
        "mx_record": mx["score"],
        "spf_dkim": spf_dkim["score"],
        "robots_txt": robots["score"],
        "favicon_hash": favicon["score"],
        "tls_issuer": tls_issuer["score"]
    }

    normalized_total = normalize_score(scores)

    reasons = [
        f"Vendor VT: {vt['reason']}" if vt["score"] is not None else f"Vendor VT: ERROR ({vt['reason']})",
        f"Vendor PhishTank: {pt['reason']}" if pt["score"] is not None else f"Vendor PhishTank: ERROR ({pt['reason']})",
        f"Vendor AbuseIPDB: {abuse['reason']}" if abuse["score"] is not None else f"Vendor AbuseIPDB: ERROR ({abuse['reason']})",
        f"Vendor URLScan: {urlscan['reason']}" if urlscan["score"] is not None else f"Vendor URLScan: ERROR ({urlscan['reason']})",
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
        f"TLS issuer: {tls_issuer['reason']}"
    ]

    return {"score": normalized_total, "reasons": reasons, "feature_scores": scores}

def batch_score(domains):
    results = {}
    for d in domains:
        try:
            results[d] = hybrid_score(d)
        except Exception as e:
            results[d] = {"error": str(e)}
    return results
