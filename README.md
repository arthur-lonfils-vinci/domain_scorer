# 🔐 Domain & Email Threat Scoring Engine

A modular, scalable, vendor-agnostic threat analysis engine that evaluates:

- Domains
- Subdomains
- Emails (with local-part heuristics)
- DNS, TLS, WHOIS, ASN data
- External threat Intel vendors

The system is designed to be **extensible**, **vendor-pluggable**, and **maintainable**.

---

# 🌍 Architecture Overview

```
project/
│
├── analyzers/           → High-level entrypoints (Domain + Email logic)
│   ├── domain_analyzer.py
│   └── email_analyzer.py
│
├── scoring/             → Normalization + Threat classification
│   ├── score_engine.py
│   └── threat_classifier.py
│
├── features/            → Modular scoring features
│   ├── base.py          → Base class for all features
│   ├── registry.py      → Auto-loads features dynamically
│   │
│   ├── extern/          → External vendor integrations
│   │   ├── virustotal.py
│   │   ├── phishtank.py
│   │   ├── abuseipdb.py
│   │   └── urlscan.py
│   │
│   └── local/           → Local scoring mechanisms
│       ├── dns_*        → DNS-based analysis
│       ├── tls_*        → TLS checks
│       ├── domain_age.py
│       ├── lexical_entropy.py
│       ├── favicon_hash.py
│       ├── robots_txt.py
│       └── email_localpart.py
│
├── web.py               → FastAPI service
├── cli.py               → Terminal interface
├── cache.py             → Cache library
├── config.py            → API keys & constants
└── README.md
```

---

# 🧠 How the Engine Works

## 1. The Analyzer Layer

### Domain Analyzer
`domain_analyzer.py` orchestrates domain evaluation:

- Runs **all domain features**
- Normalizes their scores
- Classifies threat level
- Returns a fully structured result

### Email Analyzer
`email_analyzer.py` extends domain analysis:

- Extracts local-part and domain
- Runs domain analysis
- Runs email-only features
- Detects spoofing (MX, DNS, mailbox existence)
- Applies email-specific threat rules

---

# ⚙️ The Feature System

Every feature is a class inheriting from:

```py
class Feature:
    name = "my_feature"
    max_score = 0.1
    target_type = "domain"  # or "email" or "both"

    def run(self, target: str) -> dict:
        return {"score": 0.05, "reason": "some explanation"}
```

## Automatic Registration

`features/registry.py` discovers all feature classes in:

- `features/local/`
- `features/extern/`

No need to manually register.

### Adding a New Feature

1. Create a file under `features/local/` or `features/extern/`
2. Define a class extending `Feature`
3. Done — the system loads it automatically

---

# 📊 Scoring Process

1. Each feature returns:
   - **score** (0 → max_score)
   - **reason**
2. Score Engine (`score_engine.py`):
   - Sums all feature scores
   - Normalizes them to 0–1
3. Threat Classifier (`threat_classifier.py`):
   - Applies rules based on:
     - vendor signals
     - MX/SPF
     - local-part patterns
     - ASN risks
     - high scoring combinations

---

# 🖥 CLI Usage

## Basic
```sh
python cli.py example.com
```

## Force Type
```sh
python cli.py john@weird.com --type email
python cli.py google.com --type domain
```

## JSON output
```sh
python cli.py domain.com --json
```

## Explanation Mode (grouped features)
```sh
python cli.py target --explain
```

This shows a tree:

```
Threat Explanation Breakdown
└── External Vendors
    ├── vendor_vt → score=0.000
    └── vendor_urlscan → score=0.100
└── DNS
    └── mx_record → score=0.050
```

---

# 🌐 API Usage

Run server:

```sh
uvicorn web:app --reload
```

Endpoints:

```
/score/domain/{domain}
/score/email/{email}
/score?identifier={domain_or_email}
```

Returns structured JSON.

---

# 🛡 Threat Classification

Threat level is computed after scoring:

- **Low** → domain/email looks legitimate  
- **Medium** → caution (entropy, suspicious TLD, weak signals)  
- **High** → vendor threat intel hit, missing DNS, spoofing indicators, malformed local-part  

---

# 📦 Caching

The system caches:

- DNS / WHOIS
- Vendor API responses
- Full email results

Backends:

- `diskcache` (automatic)
- fallback in-memory Python dict

---

# 🚀 Extending the Engine

To add new features:

1. Create a Python file in:
   - `features/local/` (no API)
   - `features/extern/` (API-based)

2. Declare a Feature subclass.

3. It is auto-detected on the next run.

The engine is designed to scale smoothly.

---

# ✔ Project Goals Achieved

- Modular feature-driven architecture  
- Clean analyzers separating Domain/Email  
- Weighted scoring for every feature  
- Threat classification with human explanations  
- CLI & Web interface built on same backend  
- Extensible + scalable
