import dns.resolver
from typing import Optional, Iterable

DNS_RESOLVERS: Iterable[Optional[str]] = (None, "8.8.8.8", "1.1.1.1")


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
