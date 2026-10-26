# FileSentinel DLP — Secure File Transfer Monitoring System

A Python-based Blue Team security tool designed to monitor filesystem activity in real time, detect unauthorized movement of sensitive or restricted files, verify file integrity via cryptographic hashing (SHA-256), generate policy alerts, and stream security telemetry to a local SPLUNK-style dashboard and **native Windows desktop application**.

---

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
- **Native Windows Desktop Application:**
  - Runs inside a dedicated native desktop window (powered by `pywebview`).
  - **System Tray Icon (`pystray`):** Runs continuously in the background near the clock; closing the window minimizes to the tray.
  - **Native Toast Notifications:** Displays Windows slide-in alert notifications for `WARNING` and `CRITICAL` events.
  - Right-click tray menu to open dashboard, pause/resume monitoring, or export audit reports.
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
        ├───> [ Native Toast Notifier ]> Windows Notification Center
        └───> [ Desktop / Web UI ] ────> Native Desktop Window or http://localhost:5000
```

---

## 📁 Project Structure

```
├── config.py                 # Central configuration (monitored paths, policies, thresholds)
├── monitor.py                # Watchdog filesystem observer & debouncing pipeline
├── detector.py               # Classification logic for sensitive files and exfiltration paths
├── hasher.py                 # Cryptographic hashing & pre/post transfer integrity verification
├── logger.py                 # Structured JSON audit logging & console output
├── alerter.py                # Policy violation alerting & native notification dispatcher
├── reporter.py               # Automated audit report generator
├── main.py                   # Central CLI and desktop app launcher
├── app_desktop.py            # Native Windows Desktop App with System Tray & Toasts
├── assets/                   # Application icons (icon.png, icon.ico)
├── dashboard/
│   ├── app.py                # Local Flask server providing REST API endpoints
│   ├── templates/index.html  # SPLUNK-inspired dashboard UI
│   └── static/style.css      # Dark-mode dashboard stylesheet
├── logs/                     # Audit & alert logs (audit.log, alerts.log)
├── reports/                  # Generated summary and violation reports
├── tests/                    # Automated test suite (43 unit & integration tests)
├── requirements.txt          # Python dependencies
├── repomix.config.json       # Repomix configuration
└── repomix-output.xml        # Single-file packed codebase representation
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

## 💻 Usage

### 1. Launch the Native Windows Desktop App (Recommended)
```bash
python main.py --desktop
# or
python app_desktop.py
```
* Spawns a dedicated native window with the live SPLUNK-style dashboard.
* Adds a shield icon to the **Windows System Tray** (near the taskbar clock).
* Minimizing or closing the window keeps monitoring active in the background.
* Triggers native **Windows Toast Notifications** whenever a suspicious file event occurs.

### 2. Start Headless Monitoring (Console Only)
```bash
python main.py --monitor
```

### 3. Start Monitoring + Browser Dashboard
```bash
python main.py --monitor --dashboard
# Open http://127.0.0.1:5000 in your browser
```

### 4. Generate Security Audit Report
```bash
python main.py --report
```
Compiles a structured report in the `reports/` directory containing summary metrics, policy violation breakdown, and chronological logs.

### 5. Verify Single File Hash
```bash
python main.py --test-hash "path/to/file.docx"
```

---

## 🧪 Testing

Run the automated test suite (43 unit & integration tests):
```bash
python -m pytest tests -v
```

---

## 🛡️ Blue Team Security Techniques Implemented

- **Data Loss Prevention (DLP):** Tracks unauthorized movement of corporate and confidential file types to external endpoints.
- **Tamper Detection:** Computes cryptographic pre/post hashes to verify that transferred files have not been modified or corrupted in transit.
- **Insider Threat Monitoring:** Captures operating system username and triggering process metadata for every file transfer event.
- **Air-Gapped & Offline Ready:** Built completely self-contained with no external cloud API dependencies.
