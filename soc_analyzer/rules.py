from dataclasses import dataclass

from soc_ingest.models import RawLogEntry
from soc_admin.models import SOCConfig


@dataclass
class AnalysisResult:
    attack_type: str
    severity: str
    is_suspicious: bool
    rule_name: str
    notes: str = ""


def analyze_raw_alert(raw: RawLogEntry) -> AnalysisResult:
    """
    Very simple rule-based detection engine that inspects a single raw alert.

    This mimics SIEM-style correlation rules using pattern matching on the raw log text
    and source type. It intentionally keeps the original RawLogEntry immutable.
    """
    text = (raw.raw_message or "").lower()
    source = (raw.log_source or "").lower()

    cfg = SOCConfig.get()
    if cfg.enable_brute_force and any(keyword in text for keyword in ["failed password", "authentication failure", "invalid password"]):
        return AnalysisResult(
            attack_type="brute_force",
            severity="high",
            is_suspicious=True,
            rule_name="AUTH_FAIL_BRUTE_FORCE",
            notes="Repeated or suspicious authentication failures detected in auth logs.",
        )

    # Account enumeration
    if any(keyword in text for keyword in ["user does not exist", "unknown user", "invalid username"]):
        return AnalysisResult(
            attack_type="account_enum",
            severity="medium",
            is_suspicious=True,
            rule_name="ACCOUNT_ENUM",
            notes="Login attempts against non-existent accounts may indicate enumeration.",
        )

    if cfg.enable_scanning and ("http" in source or "nginx" in source or "apache" in source):
        if any(path in text for path in ["/wp-admin", "/phpmyadmin", "/.git", "/.env", "/xmlrpc.php"]):
            return AnalysisResult(
                attack_type="web_scanning",
                severity="medium",
                is_suspicious=True,
                rule_name="WEBSCAN_SENSITIVE_PATH",
                notes="Requests to sensitive or probing paths suggest web scanning.",
            )
        if any(code in text for code in [" 404 ", " 400 ", " 401 "]):
            return AnalysisResult(
                attack_type="web_scanning",
                severity="low",
                is_suspicious=True,
                rule_name="WEBSCAN_ERROR_NOISE",
                notes="High volume of HTTP errors may be reconnaissance.",
            )

    if cfg.enable_unauthorized_access and any(keyword in text for keyword in ["sudo:", "privilege escalation", "su: authentication succeeded"]):
        return AnalysisResult(
            attack_type="unauthorized_access",
            severity="critical",
            is_suspicious=True,
            rule_name="UNAUTH_PRIV_ESC",
            notes="Potential unauthorized privileged access.",
        )

    # Default benign / unknown classification
    return AnalysisResult(
        attack_type="unknown",
        severity="low",
        is_suspicious=False,
        rule_name="NO_MATCH",
        notes="No detection rule matched; treated as benign/unknown.",
    )


