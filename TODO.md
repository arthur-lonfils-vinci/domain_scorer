# 🚀 TODO Roadmap

*A structured overview of pending feature implementations, enhancements, and upcoming capabilities.*

---

# 🔧 **1. Remaining Feature Implementations**

Below is the list of still-unimplemented scoring features, grouped with clear descriptions, motivations, and metadata.

---

## **1.1 reverse_ptr_check.py**

📁 *features/local/dns/reverse_ptr_check.py*
🎯 **Weight:** `0.25`
⚡ **Impact:** Strong heuristic

### ✔️ What it checks

* Forward-confirmed reverse DNS: **A → PTR → A** coherence
* PTR containing suspicious patterns:

  * `static-123-45-67-8`
  * `vps123`, `server-12-34-56-78`
  * `ip-172-xx`, AWS/OVH generic PTRs
* PTR **not containing the domain** (misconfigured mail server)

### ❓ Why it matters

Attackers very rarely configure PTR correctly.
Broken PTR is one of the strongest phishing indicators.

---

## **1.2 ssl_ct_reputation.py**

📁 *features/extern/ssl_ct_reputation.py*
🎯 **Weight:** `0.3`
⚡ **Impact:** Very high (zero-day malicious domain detection)

### ✔️ What it checks

Queries Certificate Transparency logs (crt.sh, Google CT):

* Certificates issued **very recently** (< 24h)
* Rapid re-issuance suggesting **key compromise**
* Suspicious certificate authorities
* Domain appears alongside **known malicious CT patterns**

### ❓ Why it matters

Most phishing domains deploy fresh Let's Encrypt certificates minutes before sending attacks.

---

## ✉**1.3 email_headers.py**

📁 *features/local/email/email_headers.py*
🎯 **Weight:** `0.7`
⚡ **Impact:** Massive (when headers available)

### ✔️ What it checks

* Received hop-chain anomalies
* SPF/DMARC failures observed **inside** headers
* Suspicious user agents:

  * `PHPMailer`, `GoPhish`, `MailChimp`
* Forged or missing `Message-ID`

### 🛠 CLI Integration

Add header file support:

```
--header / -h  path/to/mail_headers.txt
```

### ❓ Why it matters

Authentic email headers follow consistent chains.
Phishing kits do not.

---

## **1.4 domain_typosquat.py**

📁 *features/local/dns/domain_typosquat.py*
🎯 **Weight:** `0.3`

### ✔️ What it checks

Detects common typosquatting patterns:

* Homoglyphs: `google` → `g00gle`
* Character substitutions: `paypal` → `paypa1`
* Adjacent-key swaps
* `vinci.be` → `vlnci.be`

### ❓ Why it matters

One of the most common phishing techniques ever.

---

## **1.5 ip_hosting_risk.py**

📁 *features/extern/ip_hosting_risk.py*
🎯 **Weight:** `0.2`

### ✔️ What it checks

Fetches risk indicators based on WHOIS + ASN:

* Bulletproof hosting
* Stolen/S3 bucket cloud storage
* High-abuse hosting providers
* VPN hosting (NordVPN, Mullvad, ProtonVPN…)

### ❓ Why it matters

Malicious infrastructure clusters often reuse the same networks.

---

## **1.6 tld_risk_extended.py**

📁 *features/local/dns/tld_risk_extended.py*
🎯 **Weight:** `0.2`

### ✔️ What it checks

Flags suspicious TLDs:

* Free high-abuse ccTLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`
* New phishing wave TLDs: `.zip`, `.mov`
* New emerging malicious TLD trends

### ❓ Why it matters

Cheap/free TLDs dominate phishing ecosystems.

---

## **1.7 domain_privacy.py**

📁 *features/local/dns/domain_privacy.py*
🎯 **Weight:** `0.2`

### ✔️ What it checks

* WHOIS privacy enabled on **new** domains
* Abusive registrars (NameSilo, AlibabaCloud, Hostinger…)
* Patterns of privacy + cheap registrar → high-risk

### ❓ Why it matters

Most phishing domains hide WHOIS data immediately.

---

---

# 🗃️ **2. Data Persistence Layer (Local Database)**

### Objective

Introduce local storage for persistent and non-persistent data:

| Type              | Examples                                   | Storage Option                   |
| ----------------- | ------------------------------------------ | -------------------------------- |
| Short-lived cache | CT logs, vendor lookups                    | Redis / SQLite                   |
| Permanent         | Email fingerprints, URL reputation history | PostgreSQL / SQLite              |
| ML embeddings     | Feature vectors                            | Vector DB (ChromaDB, SQLite-vec) |

### Decisions to finalize

* Should caching remain ephemeral (Redis)?
* Should long-term intelligence persist locally (PostgreSQL)?
* Should ML mode require a vector DB?

---

# 🖥️ **3. CLI UX Improvements**

### Planned UI Enhancements

* Rich-powered progress bars
* Spinners while calling external vendors
* Interactive mode (`--interactive`)
* Collapsible sections
* Color-coded severity
* Better error reporting

### Example idea

```
[⏳] Checking DNS records...
[✔] Checking TLS certificates...
[❗] Vendor timeout: VirusTotal
```

---

# 🌐 **4. HTML/CSS Response Mode (API)**

### Goal

Provide a **fully visual HTML report** for API responses.

Examples:

* Threat summary cards
* Feature detail table
* Color-coded score bars
* Export as PDF/HTML

Possible approaches:

* Jinja2 template rendering
* HTML + Tailwind
* /report/html endpoint

---

# 🤖 **5. Machine Learning Exploration (Optional Mode)**

### Potential Benefits

* Detect phishing email structure
* Detect suspicious domain patterns
* Identify anomalies beyond heuristics

### Challenges

* Requires higher performance
* Model hosting vs offline inference
* Vector database for embeddings
* “Free” setup likely requires:

  * Open-source models
  * Local inference (ONNX, GGUF)
  * Optional mode: `--use-ml`

### Suggested architecture

* ML scoring is **additive**, not replacing heuristics.
* Feature → vector → classifier
* Output: ML confidence score (0–1)

---

# ✔️ Summary Checklist

| Feature                 | Status     |
| ----------------------- | ---------- |
| reverse_ptr_check       | ⏳ pending  |
| ssl_ct_reputation       | ⏳ pending  |
| email_headers           | ⏳ pending  |
| domain_typosquat        | ⏳ pending  |
| ip_hosting_risk         | ⏳ pending  |
| tld_risk_extended       | ⏳ pending  |
| domain_privacy          | ⏳ pending  |
| Local DB layer          | ⏳ pending  |
| CLI visual improvements | ⏳ pending  |
| HTML report mode        | ⏳ pending  |
| ML scoring (optional)   | ⏳ research |
