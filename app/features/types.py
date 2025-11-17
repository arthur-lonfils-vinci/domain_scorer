from enum import Enum

class TargetType(str, Enum):
    DOMAIN = "domain"
    EMAIL = "email"
    WEB = "web"

class RunScope(str, Enum):
    USER = "user"
    FQDN = "fqdn"
    ROOT = "root"

class ConfigCat(str, Enum):
    EMAIL = "email"
    WEB = "web"
    DOMAIN = "domain"
    VENDORS = "vendors"

class Category(str, Enum):
    VENDORS = "vendors"
    DNS = "dns"
    TLS = "tls"
    WHOIS = "whois"
    HEURISTICS = "heuristics"
    ASN = "asn"
    WEB = "web"
    EMAIL = "email"
    OTHER = "other"
