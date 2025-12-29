from django.conf import settings
from django.db import models
from django.utils import timezone

from soc_correlation.models import CorrelatedEvent


class Incident(models.Model):
    """
    Security incident created from a correlated event.

    Represents a real-world SOC incident response workflow with status tracking
    and investigation notes.
    """

    STATUS_OPEN = "open"
    STATUS_INVESTIGATING = "investigating"
    STATUS_MITIGATED = "mitigated"
    STATUS_CLOSED = "closed"

    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_INVESTIGATING, "Investigating"),
        (STATUS_MITIGATED, "Mitigated"),
        (STATUS_CLOSED, "Closed"),
    ]

    incident_id = models.CharField(max_length=32, unique=True, help_text="Unique incident identifier (e.g., INC-2025-001)")
    correlated_event = models.OneToOneField(
        CorrelatedEvent,
        on_delete=models.CASCADE,
        related_name="incident",
        help_text="The correlated security event this incident was created from.",
    )
    attack_type = models.CharField(max_length=32, help_text="Type of attack detected.")
    risk_score = models.FloatField(help_text="Risk score inherited from correlated event.")
    current_status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents",
        help_text="SOC analyst assigned to investigate this incident.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_incidents",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Incident"
        verbose_name_plural = "Incidents"

    def __str__(self) -> str:
        return f"{self.incident_id} - {self.attack_type} ({self.current_status})"


class IncidentHistory(models.Model):
    """
    Audit trail for incident status changes and investigation notes.

    Maintains a complete history of all actions taken on an incident for
    compliance and tracking purposes.
    """

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="history")
    timestamp = models.DateTimeField(default=timezone.now)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="incident_history_entries",
    )
    old_status = models.CharField(max_length=16, blank=True, help_text="Previous status before change.")
    new_status = models.CharField(max_length=16, help_text="New status after change.")
    notes = models.TextField(help_text="Investigation notes or reason for status change.")

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "Incident History Entry"
        verbose_name_plural = "Incident History Entries"

    def __str__(self) -> str:
        return f"{self.incident.incident_id} - {self.old_status} → {self.new_status} at {self.timestamp}"

