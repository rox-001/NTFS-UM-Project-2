# Secure File Transfer Monitoring System 

A Python-based Blue Team security tool designed to monitor filesystem activity in real time, detect unauthorized movement of sensitive or restricted files, verify file integrity via cryptographic hashing (SHA-256), generate policy alerts, and stream security telemetry to a local SPLUNK-style dashboard.
---
In other words, a easy to use and efficient(fun) way to track files if you deal with a lot of them on daily basis.


## 🎯 Objectives & Capabilities

- **Real-Time Filesystem Monitoring:** Tracks `CREATED`, `MODIFIED`, `MOVED`, and `DELETED` file events across configured target directories.
- **Unauthorized Movement & Exfiltration Detection:**
  - Maintains strict policy lists of sensitive directories and high-risk file types.
  - Detects suspicious outbound transfer vectors (USB / removable media, UNC network shares, cloud storage sync folders).
- **Cryptographic File Integrity Verification:**
  - Computes pre- and post-transfer hash digests (SHA-256 / SHA-512 / MD5) using Python's built-in `hashlib`.
  - Flags tampering, corruption, or unexpected content alterations (`INTACT` vs `TAMPERED`).
- **Telemetry, Alerting & Audit Logging:**
  - 3-tier severity classification: `INFO`, `WARNING`, `CRITICAL`.
  - Structured, machine-readable JSON-line audit logs in `logs/audit.log`.
  - Real-time terminal alerts via `colorama` with high-visibility banners for policy violations.
- **SPLUNK-Style Local Dashboard:**
  - Local Flask web UI (`http://127.0.0.1:5000`) with auto-refreshing telemetry, searchable/filterable logs, and live alert feeds.
  - Zero external network dependencies (100% localhost).
- **Noise Suppression & Write-Burst Debouncing:**
  - Eliminates duplicate operating system write-buffer flushes during large file transfers.
  - Prevents recursive log feedback loops.

---

## 🏗️ Architecture & Workflow

```
[ Filesystem Event ] (watchdog)
        │
        ▼
[ Noise & Internal Filter ] ──> Ignore own logs, .git, OS metadata (~$*, .tmp, desktop.ini)
        │
        ▼
[ Write-Burst Debounce ] ────> Suppress rapid OS buffer flushes within debounce window
        │
        ▼
[ Event Classification ] ────> Check Sensitive Extensions / Directories & Suspicious Destinations
        │                       ├── CRITICAL: Sensitive file moved to USB/Cloud/Network or Deleted
        │                       ├── WARNING : Sensitive file Created/Modified
        │                       └── INFO    : Normal file activity
        │
        ▼
[ Integrity Hashing ] ───────> Compute SHA-256 (pre/post transfer comparison)
        │
        ├───> [ Structured Logger ] ───> logs/audit.log (JSON Lines) + Console
        ├───> [ Alerter ] ─────────────> logs/alerts.log + Terminal Banner
        └───> [ Web Dashboard ] ────────> http://localhost:5000 (Live SPLUNK View)
```

---

## 📁 Project Structure

```
├── config.py                 # Central configuration (monitored paths, policies, thresholds)
├── monitor.py                # Watchdog filesystem observer & debouncing pipeline
├── detector.py               # Classification logic for sensitive files and exfiltration paths
├── hasher.py                 # Cryptographic hashing & pre/post transfer integrity verification
├── logger.py                 # Structured JSON audit logging & console output
├── alerter.py                # Policy violation alerting & banner generation
├── reporter.py               # Automated audit report generator
├── main.py                   # Central CLI entry point
├── dashboard/
│   ├── app.py                # Local Flask server providing REST API endpoints
│   ├── templates/index.html  # SPLUNK-inspired dashboard UI
│   └── static/style.css      # Dark-mode dashboard stylesheet
├── logs/                     # Audit & alert logs (audit.log, alerts.log)
├── reports/                  # Generated summary and violation reports
├── tests/                    # Automated test suite (43 unit & integration tests)
└── requirements.txt          # Python dependencies
```

---

## 🚀 Installation & Requirements

### Prerequisites
- Python 3.9+ (Python 3.10+ recommended)
- Standard pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/rox-001/NTFS-UM-Project-2.git
cd NTFS-UM-Project-2

# Install dependencies
pip install -r requirements.txt
```

> **Note:** Cryptographic hashing relies on Python's built-in `hashlib` standard library module, requiring zero third-party downloads or external API access.

---

## ⚙️ Configuration

All monitoring rules and policies are customized in [`config.py`](config.py):

### 1. Monitored Target Folders
```python
MONITORED_DIRECTORIES = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    # Add custom directories:
    # r"C:\Data\Transfers",
]
```

### 2. Sensitive File Criteria
```python
SENSITIVE_EXTENSIONS = [
    ".key", ".pem", ".pfx", ".docx", ".xlsx", ".pdf",
    ".db", ".sqlite", ".sql", ".csv", ".json", ".env",
]

SENSITIVE_DIRECTORIES = [
    # Dedicated restricted directories:
    # r"C:\ConfidentialData",
]
```

### 3. Suspicious Exfiltration Destinations
```python
SUSPICIOUS_DRIVE_LETTERS = ["D:\\", "E:\\", "F:\\", "G:\\"]  # Removable drives
SUSPICIOUS_PATH_KEYWORDS = ["OneDrive", "Dropbox", "Google Drive", "iCloud", "Temp"]
SUSPICIOUS_NETWORK_PREFIXES = ["\\\\"]  # UNC network shares
```

---

## 💻 Usage

### 1. Start Monitoring (Terminal Only)
```bash
python main.py --monitor
```

### 2. Start Monitoring with SPLUNK-Style Web Dashboard
```bash
python main.py --monitor --dashboard
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```
Features:
- Real-time event log table with color-coded severity badges.
- Live alert feed in the side panel.
- Summary telemetry cards: Total Events, INFO, WARNINGS, CRITICAL, Tampered Files.
- Instant search and severity filtering without reloading the page.

### 3. Generate Security Audit Report
```bash
python main.py --report
```
Compiles a structured report in the `reports/` directory containing summary metrics, policy violation breakdown, and chronological logs.

### 4. Verify Single File Hash
```bash
python main.py --test-hash "path/to/file.docx"
```

---

## 🧪 Testing

Run the automated test suite (43 unit & integration tests):
```bash
python -m pytest tests -v
```
(If you've got time...)
---

## 🛡️ Blue Team Security Techniques Implemented (A bit extra stuff)

- **Data Loss Prevention (DLP):** Tracks unauthorized movement of corporate and confidential file types to external endpoints.
- **Tamper Detection:** Computes cryptographic pre/post hashes to verify that transferred files have not been modified or corrupted in transit.
- **Insider Threat Monitoring:** Captures operating system username and triggering process metadata for every file transfer event.
- **Air-Gapped & Offline Ready:** Built completely self-contained with no external cloud API dependencies.
