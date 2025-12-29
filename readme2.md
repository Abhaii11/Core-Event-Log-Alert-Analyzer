# Core Event Log Alert Analyzer

[![Django](https://img.shields.io/badge/Django-4.0+-092E20?style=flat&logo=django)](https://www.djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-SOC%20Pipeline-red?style=flat)](https://en.wikipedia.org/wiki/Security_operations_center)

**Core Event Log Alert Analyzer** is a modular **Security Operations Center (SOC) platform** designed to simulate the full lifecycle of modern threat detection. It ingests raw log data, applies rule-based logic to detect attacks, correlates scattered alerts into actionable security events, and manages incident response.

The platform places a heavy emphasis on **data integrity**, implementing a blockchain-style audit trail to ensure that evidence and analyst actions are cryptographically verifiable.

---

## 📖 Table of Contents
- [Key Features](#-key-features)
- [Detection Capabilities](#-detection-capabilities)
- [System Architecture](#-system-architecture)
- [Configuration & Tuning](#-configuration--tuning)
- [Installation](#-installation)
- [Security Model](#-security-model)

---

## 🚀 Key Features

### 1. Forensic-Ready Ingestion (`soc_ingest`)
* **Immutable Evidence**: Raw logs are stored as `RawLogEntry` records. Once ingested, the log message and source are locked to preserve the chain of custody.
* **Multi-Source Import**: Supports bulk upload of text files and manual entry for ad-hoc analysis.
* **State Tracking**: Each log line tracks its own processing status (`Unprocessed` vs. `Processed`) to guarantee 100% coverage.

### 2. Automated Analysis Engine (`soc_analyzer`)
* **Rule-Based Detection**: A Python-based engine inspects logs for known attack patterns using the `AnalysisResult` dataclass.
* **Dynamic Severity**: Alerts are automatically classified (e.g., *High Severity* for brute force, *Critical* for privilege escalation) based on the matched rule.

### 3. Intelligent Correlation (`soc_correlation`)
* **Noise Reduction**: The system aggregates related alerts into `CorrelatedEvents` using a configurable time window (default: 15 minutes).
* **Risk Scoring**: A composite risk score is calculated for each event based on the volume and severity of the underlying alerts.

### 4. Incident Response (`soc_incidents`)
* **One-Click Escalation**: Promotes high-risk `CorrelatedEvents` into formal `Incidents` with unique IDs (e.g., `INC-2025-001`).
* **Workflow Management**: Tracks incidents through `Open` → `Investigating` → `Mitigated` → `Closed` states.

---

## 🛡 Detection Capabilities

The platform includes built-in detection rules defined in `soc_analyzer/rules.py`. These rules can be toggled on/off via the admin configuration.

| Attack Type | Detection Logic | Severity | Config Flag |
| :--- | :--- | :--- | :--- |
| **Brute Force** | Keywords: `failed password`, `authentication failure` | **High** | `enable_brute_force` |
| **Privilege Escalation** | Keywords: `sudo:`, `privilege escalation` | **Critical** | `enable_unauthorized_access` |
| **Account Enum** | Keywords: `user does not exist`, `invalid username` | **Medium** | N/A (Always Active) |
| **Web Scanning** | Paths: `/wp-admin`, `/.env`, `xmlrpc.php` | **Medium** | `enable_scanning` |
| **Reconnaissance** | High volume of `404`, `400`, `401` errors | **Low** | `enable_scanning` |

> **Note:** The detection engine is highly customizable. Rules return an `AnalysisResult` containing specific rule names (e.g., `AUTH_FAIL_BRUTE_FORCE`, `WEBSCAN_SENSITIVE_PATH`) for precise tracking.

---

## 🏗 System Architecture

The project follows a clean, modular app structure:

| App / Module | Responsibility |
| :--- | :--- |
| **`soc_core`** | Global settings, middleware, and project orchestration. |
| **`soc_ingest`** | Handles raw log intake, validation, and evidence locking. |
| **`soc_analyzer`** | Contains the `rules.py` detection engine and analysis models. |
| **`soc_correlation`** | Groups analyzed alerts into `CorrelatedEvent` objects. |
| **`soc_incidents`** | Manages the human response workflow and ticketing system. |
| **`soc_audit`** | Provides the secure, immutable logging mechanism. |
| **`soc_admin`** | Manages system-wide configurations and analyst profiles. |

---

## ⚙ Configuration & Tuning

The platform's behavior is dynamically controlled via the `SOCConfig` singleton model, allowing admins to tune the system without code changes.

* **Correlation Window**: Adjust `correlation_window_minutes` to define how "close" alerts must be to group together.
* **Alert Thresholds**: Set minimum counts for promotion (e.g., `threshold_critical`, `threshold_high`) to filter out noise.
* **Rule Toggles**: Enable or disable specific detection families (`enable_brute_force`, `enable_scanning`) to reduce false positives.

---

## 🔒 Security Model: The Immutable Audit Trail

A standout feature is the **`soc_audit`** module, which ensures total accountability.

1.  **Tamper-Proofing**: The `AuditLogEntry` model overrides `save()` and `delete()` to prevent modification of existing records.
2.  **Cryptographic Chaining**:
    Each log entry contains a `content_hash` generated from its data *and* the hash of the previous entry:
    ```python
    # soc_audit/models.py
    payload = f"{seq}|{prev_hash}|{analyst_id}|{action}|{description}..."
    self.content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    ```
    This creates a blockchain-like structure where any alteration to a past log breaks the hash chain for all subsequent entries.

---

## 💻 Installation

1.  **Clone & Setup**
    ```bash
    git clone [https://github.com/your-repo/core-event-log-alert-analyzer.git](https://github.com/your-repo/core-event-log-alert-analyzer.git)
    cd core-event-log-alert-analyzer
    python -m venv venv
    source venv/bin/activate
    ```

2.  **Install Dependencies**
    ```bash
    pip install django
    ```

3.  **Initialize Database**
    ```bash
    python manage.py migrate
    python manage.py createsuperuser
    ```

4.  **Launch**
    ```bash
    python manage.py runserver
    ```
