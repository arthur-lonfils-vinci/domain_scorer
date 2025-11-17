# 🔐 Domain, Web & Email Threat Scoring Engine

A modular, extensible, OSINT-driven engine for evaluating the trustworthiness of:

* 🌍 **Domains & Subdomains**
* 📧 **Emails** (including local-part heuristics)
* 🕸 **Web Fingerprinting**
* 🔎 **DNS / TLS / WHOIS / ASN**
* 🛰 **External Threat Intelligence Vendors**

The system is built to be:

* **Modular** — every detection is a plug-and-play feature
* **Vendor-Pluggable** — VirusTotal, PhishTank, AbuseIPDB, …
* **Extensible** — add new heuristics with one class
* **High-Visibility** — CLI table, JSON, API responses
* **Scalable** — caching, multi-layer scoring, future ML support

---

# Architecture Overview

```
app/
│
├── analyzers/            → Orchestrate full Domain / Email analysis
│   ├── domain_analyzer.py
│   └── email_analyzer.py
│
├── scoring/              → Score normalization + threat classification
│   ├── score_engine.py
│   └── threat_classifier.py
│
├── features/             → All pluggable scoring modules
│   ├── base.py           → Base Feature class (scoring contract)
│   ├── registry.py       → Auto-loads all features
│   ├── types.py          → TargetType, RunScope, Category enums
│   │
│   ├── extern/           → External OSINT / threat intel
│   │   ├── virustotal.py
│   │   ├── phishtank.py
│   │   ├── abuseipdb.py
│   │   ├── urlscan.py
│   │   ├── ssl_ct_reputation.py
│   │   └── ip_hosting_risk.py
│   │
│   └── local/            → Local analytical features
│       ├── dns/          → DNS / WHOIS / PTR / TLD / MX…
│       ├── email/        → Local-part, headers, impersonation…
│       └── web/          → robots.txt, favicon, fingerprinting
│
├── web.py                → FastAPI application
├── cli.py                → Rich-powered CLI interface
├── cache.py              → Caching engine (persistent)
├── config.yaml           → Feature weights (per category)
└── config.py             → Config loader & API keys
```

---

# 🧠 How the Engine Works

The system evaluates a target using **multi-layer scoring**:

### 1️⃣ Feature Engine

Every detection module returns:

```python
{
  "score": float | None,   # None = unavailable / disabled
  "reason": str,
  "ok": bool               # True = success, False = suspicious or unavailable
}
```

Each feature has:

* **TargetType** → `domain`, `email`, `web`
* **RunScope** → `root`, `fqdn`, `user`
* **Weight** loaded from `config.yaml`

### 2️⃣ Scoring Engine

`score_engine.py`:

* Aggregates domain/user/web feature scores
* Normalizes using per-feature max weight
* Tracks explanations, reasons, and raw values

### 3️⃣ Threat Classification

`threat_classifier.py`:

* Domain behavioral classification
* Email spoofing/logical anomalies
* Vendor overrides (VirusTotal, PhishTank, …)
* Multi-layer correlations (local part + domain risk, etc.)

---

# 🧩 The Feature System

### Base class

```python
class Feature:
    name = "example"
    max_score = 0.2
    target_type = TargetType.DOMAIN
    run_on = RunScope.FQDN
    category = Category.DNS

    def run(self, target: str):
        ...
```

### Automatic Discovery

Every file in:

```
features/local/**/*
features/extern/**/*
```

is scanned automatically.
No manual registry.

### Adding a feature

1. Create a file under `features/local/xyz.py`
2. Create a class inheriting from `Feature`
3. Set:

   * `name`
   * `max_score` (or load from config)
   * `target_type`
   * `run_on`
4. The system loads it automatically.

---

# ✨ Implemented Features

### 🔍 DNS & WHOIS

* A record presence
* MX presence
* SPF/DKIM analysis
* Domain age
* TLD reputation
* WHOIS privacy check
* Reverse PTR check *(new)*
* Auth alignment *(SPF, DKIM, MX)*

### 🛡 External Vendors

* VirusTotal
* URLScan
* AbuseIPDB
* PhishTank
* SSL CT logs reputation *(new)*
* IP hosting risk *(new)*

### 📧 Email Heuristics

* Local-part entropy & digit ratio
* Mailbox existence
* MX-based spoofing
* Disposable provider detection
* Brand impersonation
* Cross-domain mismatch
* Email headers deep analysis *(new)*

### 🌐 Web Indicators

* robots.txt
* favicon fingerprint
* Website fingerprint *(new)*

---

# 🔮 Upcoming Features (already drafted)

These are present in code structure and config but still under implementation:

| Feature                 | File                 | Description                         |
| ----------------------- | -------------------- | ----------------------------------- |
| Typosquatting detection | domain_typosquat.py  | Homoglyph / swap / OCR confusion    |
| Extended TLD Risk       | tld_risk_extended.py | Free ccTLD abuse + new risky gTLDs  |
| CT Reputation           | ssl_ct_reputation.py | Fresh certs, LE abuse, CT clusters  |
| Hosting Abuse           | ip_hosting_risk.py   | Bulletproof hosts, VPN nodes        |
| Domain Privacy          | domain_privacy.py    | WHOIS privacy on new domains        |
| Email Headers           | email_headers.py     | Hop-chain anomalies, forged mailers |

---

# ⚙️ CLI Usage

### Basic

```sh
python -m app.cli example.com
```

### Force analysis mode

```sh
python -m app.cli target@example.com --type email
python -m app.cli domain.com --type domain
```

### Provide email headers

```sh
python -m app.cli target@example.com --header mail_headers.txt
```

### JSON output

```sh
python -m app.cli domain.com --json
```

### Explanation mode

```sh
python -m app.cli target --explain
```

Shows a tree-structured explanation:

```
Root Domain Layer
  ├── dns_a_record         → score=0.100
  ├── vendor_vt            → score=0.300
  └── reverse_ptr_check    → score=0.250
```

---

# 🌐 API Usage

Start server:

```sh
uvicorn app.web:app --reload
```

Endpoints:

```
/score/domain/{domain}
/score/email/{email}
/score?identifier=
```

Returns structured JSON with:

* scores
* reasons
* weights
* layers
* threat level
* vendor intelligence

---

# 🧩 Configuration System

All feature weights live in `config.yaml`, organized per **category**:

```yaml
domain:
  dns_a_record: 0.1
  mx_reputation: 0.3
  reverse_ptr_check: 0.25

email:
  email_headers: 0.7
  email_localpart: 0.5

web:
  domain_web_fingerprint: 0.4
```

Weights load automatically at startup.

---

# 🧰 Caching Engine

* Persistent caching via `.cache/cache.db`
* Automatic caching of:

  * DNS
  * WHOIS
  * Vendor API calls
  * Full domain/email results
* Reduces vendor cost & latency

---

# 🚀 Extending the Engine

To add your own module:

1. Create a new file in
   `app/features/local/...`
   or
   `app/features/extern/...`

2. Add a Feature subclass

3. Choose:

   * `target_type`
   * `run_on`
   * weight in `config.yaml`

4. Done — auto-loaded.

---

# 🎯 Project Goals

* Modular scoring engine
* Domain, email & web analytics
* Typed feature system (TargetType, RunScope, Category)
* Human-readable CLI output
* API-ready JSON
* Extensible threat heuristics
* Vendor-pluggable OSINT
* ML-ready architecture

---

# 🧱 Future Roadmap

* Local Redis / SQLite persistent intelligence DB
* HTML reporting mode (API & CLI)
* Interactive CLI
* ML-assisted phishing scoring (optional mode)
* Threat cluster correlation
* Vector DB (embeddings) for similarity search

