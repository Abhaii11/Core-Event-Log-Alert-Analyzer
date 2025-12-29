from django.db import models

from soc_ingest.models import RawLogEntry


class RawAlertAnalysis(models.Model):
    """
    Stores the analyzed result of a single raw alert/log entry.

    This simulates a SIEM detection engine output linked back to the raw evidence.
    """

    ATTACK_BRUTE_FORCE = "brute_force"
    ATTACK_ACCOUNT_ENUM = "account_enum"
    ATTACK_WEB_SCANNING = "web_scanning"
    ATTACK_UNAUTHORIZED_ACCESS = "unauthorized_access"
    ATTACK_UNKNOWN = "unknown"

    ATTACK_TYPE_CHOICES = [
        (ATTACK_BRUTE_FORCE, "Brute-force login"),
        (ATTACK_ACCOUNT_ENUM, "Account enumeration"),
        (ATTACK_WEB_SCANNING, "Web scanning"),
        (ATTACK_UNAUTHORIZED_ACCESS, "Unauthorized access"),
        (ATTACK_UNKNOWN, "Unknown / benign"),
    ]

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    raw_alert = models.OneToOneField(
        RawLogEntry,
        on_delete=models.CASCADE,
        related_name="analysis",
    )
    detected_at = models.DateTimeField(auto_now_add=True)
    attack_type = models.CharField(max_length=32, choices=ATTACK_TYPE_CHOICES)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    is_suspicious = models.BooleanField(default=False)
    rule_name = models.CharField(max_length=128, help_text="Name of the detection rule that matched.")
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-detected_at"]
        verbose_name = "Raw Alert Analysis"
        verbose_name_plural = "Raw Alert Analyses"

    def __str__(self) -> str:
        return f"{self.get_attack_type_display()} ({self.get_severity_display()}) for {self.raw_alert_id}"


