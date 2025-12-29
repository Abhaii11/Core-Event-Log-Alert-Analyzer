# Core Event Log Alert Analyzer

**Core Event Log Alert Analyzer** is a comprehensive **Security Operations Center (SOC) platform** built with Django. It simulates a complete threat detection pipeline, enabling security analysts to ingest raw logs, detect malicious patterns, correlate alerts into events, and manage the incident response lifecycle.

Designed with strict data integrity requirements, it features a **cryptographically verifiable audit trail** to ensure accountability for all analyst actions.

## 🚀 Key Features

### 1. Raw Log Ingestion (`soc_ingest`)
* **Evidence Preservation**: Ingested logs are stored as `RawLogEntry` records. Critical fields (message, source, timestamp) are **immutable** upon creation to preserve chain of custody.
* **Multi-Channel Import**: Supports bulk file uploads (parsing text files line-by-line) and manual log entry submission.
* **Lifecycle Tracking**: Tracks the status of every log line (`Unprocessed` vs. `Processed`) to ensure no data is overlooked.

### 2. Automated Threat Analysis (`soc_analyzer`)
* **Detection Engine**: Runs rule-based logic on unprocessed logs to identify threats.
* **Threat Classification**: Categorizes alerts into specific attack types:
    * Brute-force login
    * Account enumeration
    * Web scanning
    * Unauthorized access
* **Severity Scoring**: Assigns severity levels (Low, Medium, High, Critical) to aid in triage.

### 3. Event Correlation (`soc_correlation`)
* **Intelligent Grouping**: Aggregates related alerts into `CorrelatedEvent` objects based on time windows and source assets, reducing alert fatigue.
* **Risk Scoring**: Calculates a composite risk score based on the volume and severity of aggregated alerts.
* **Noise Reduction**: Configurable thresholds automatically filter out low-risk events.

### 4. Incident Management (`soc_incidents`)
* **Incident Promotion**: One-click workflow to promote high-risk `CorrelatedEvents` into `Incidents`.
* **Case Management**: distinct lifecycle states (`Open`, `Investigating`, `Mitigated`, `Closed`) with assignment tracking.
* **Investigation History**: Maintains a granular history of all status changes and analyst notes for post-mortem analysis.

### 5. Immutable Audit Trail (`soc_audit`)
* **Tamper-Proof Logging**: Critical actions (login, upload, incident updates) are recorded in `AuditLogEntry`.
* **Cryptographic Chaining**: Uses **SHA-256 hashing** to link log entries. Each entry contains a hash of the previous entry, making it impossible to alter or delete past records without breaking the chain.

---

## 🛠 SOC Workflow

The platform follows a linear security operations pipeline:

1.  **Ingest**: Analysts upload log files. The system parses them into immutable evidence records.
2.  **Analyze**: The analysis engine scans new logs for known attack patterns.
3.  **Correlate**: The correlation engine groups individual alerts into meaningful security events.
4.  **Respond**: High-fidelity events are promoted to incidents for human investigation and mitigation.

---

## 🏗 System Architecture

| Module | Description |
| :--- | :--- |
| **`soc_ingest`** | Raw data intake, validation, and evidence storage. |
| **`soc_analyzer`** | Detection logic and alert generation. |
| **`soc_correlation`** | Event aggregation and risk scoring. |
| **`soc_incidents`** | Incident response workflow and ticketing. |
| **`soc_audit`** | Secure, blockchain-style activity logging. |
| **`soc_core`** | Project settings and configuration. |

---

## 💻 Installation

### Prerequisites
* Python 3.10+
* Django 4.0+

### Setup Guide

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/your-repo/core-event-log-alert-analyzer.git](https://github.com/your-repo/core-event-log-alert-analyzer.git)
    cd core-event-log-alert-analyzer
    ```

2.  **Set up the environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install django
    ```

3.  **Initialize the database**
    ```bash
    python manage.py migrate
    ```

4.  **Create an Administrator**
    ```bash
    python manage.py createsuperuser
    ```

5.  **Run the platform**
    ```bash
    python manage.py runserver
    ```
    Access the dashboard at `http://127.0.0.1:8000/`.

---

## 🔒 Security & Compliance

The `soc_audit` application ensures compliance with strict auditing standards. 

* **Immutability**: The `AuditLogEntry` model overrides `save()` and `delete()` methods to prevent modification of existing logs.
* **Verification**: The `content_hash` field ensures that the sequence of events (Prev Hash + Content) remains unbroken.
