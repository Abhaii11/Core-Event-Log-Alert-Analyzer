from django.db import models

from soc_analyzer.models import RawAlertAnalysis


class CorrelatedEvent(models.Model):
    """
    Represents a higher-level security event created by correlating multiple analyzed alerts.
    """

    attack_type = models.CharField(max_length=32)
    source = models.CharField(max_length=128, help_text="Log source or asset associated with this event.")
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    total_alerts = models.PositiveIntegerField()
    risk_score = models.FloatField(help_text="Calculated risk score based on severity and volume.")
    created_at = models.DateTimeField(auto_now_add=True)

    # This event can later be promoted to an incident in a separate module.
    is_promoted_to_incident = models.BooleanField(default=False)

    related_alerts = models.ManyToManyField(
        RawAlertAnalysis,
        related_name="correlated_events",
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Correlated Event"
        verbose_name_plural = "Correlated Events"

    def __str__(self) -> str:
        return f"{self.attack_type} on {self.source} ({self.total_alerts} alerts, risk {self.risk_score:.1f})"


