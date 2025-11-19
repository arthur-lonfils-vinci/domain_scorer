import dns.resolver
import dns.reversename
from typing import Optional, Iterable, List

DNS_RESOLVERS: Iterable[Optional[str]] = (None, "8.8.8.8", "1.1.1.1")


# ======================================================================
#  Core DNS resolver (unchanged)
# ======================================================================

def resolve_dns(domain: str, record_type: str, timeout: float = 3.0):
    """
    Try multiple DNS resolvers with fallback.
    Raises if all fail.
    """
    last_exc = None
    for server in DNS_RESOLVERS:
        try:
            resolver = dns.resolver.Resolver()
            if server:
                resolver.nameservers = [server]
            return resolver.resolve(domain, record_type, lifetime=timeout)
        except Exception as e:  # noqa: BLE001
            last_exc = e
            continue
    raise last_exc or Exception("DNS resolution failed for all resolvers")


def is_nxdomain_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "does not exist" in msg or "nxdomain" in msg or "not found" in msg


# ======================================================================
#  NEW HELPERS
# ======================================================================

def resolve_ptr(ip: str) -> Optional[str]:
    """
    Reverse DNS lookup: IP → PTR hostname.
    Returns None if not found or NXDOMAIN.
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        result = resolve_dns(str(rev_name), "PTR")
        return str(result[0]).rstrip(".")
    except Exception as exc:  # noqa: BLE001
        if is_nxdomain_error(exc):
            return None
        return None


def resolve_a(hostname: str) -> List[str]:
    """
    Forward DNS A lookup.
    Returns list of IPv4 strings or [] on failure.
    """
    try:
        result = resolve_dns(hostname, "A")
        return [str(r) for r in result]
    except Exception:
        return []


def forward_reverse_consistent(ip: str) -> bool:
    """
    Check A → PTR → A coherence:
        IP -> PTR hostname -> A records must contain original IP
    """
    ptr = resolve_ptr(ip)
    if not ptr:
        return False

    forward_ips = resolve_a(ptr)
    return ip in forward_ips


def ptr_suspicious_patterns(ptr: Optional[str]) -> Optional[str]:
    """
    Detect common malicious PTR hostnames:
        static-123-45-67-8
        vps123.example
        ip-172-31-22-10
        cloudserver-22-11
        r-ip123-4-5-6

    Returns the matched reason or None.
    """
    if not ptr:
        return None

    import re

    patterns = {
        r"static-\d+-\d+-\d+-\d+": "Generic static-IP PTR",
        r"vps\d+": "VPS hosting PTR",
        r"ip-\d+-\d+-\d+-\d+": "AWS-style EC2 PTR",
        r"cloud\S*": "Generic cloud PTR",
        r"server-\d+": "Server PTR naming pattern",
    }

    for regex, reason in patterns.items():
        if re.search(regex, ptr.lower()):
            return reason

    return None


def extract_root_domain(fqdn: str) -> str:
    """
    Basic root-domain extraction for PTR comparison.
    """
    parts = fqdn.lower().split(".")
    if len(parts) < 2:
        return fqdn.lower()
    return ".".join(parts[-2:])
