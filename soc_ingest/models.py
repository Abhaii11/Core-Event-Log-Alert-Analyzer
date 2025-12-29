from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class RawLogEntry(models.Model):
    """
    Single raw log line ingested into the SOC platform.

    This model acts as the SOC's raw alert evidence repository.

    Requirements this model satisfies:
    - Each line stored as-is in `raw_message` with no transformation.
    - Metadata: ingest timestamp, source, uploading analyst, processing status.
    """

    STATUS_UNPROCESSED = "unprocessed"
    STATUS_PROCESSED = "processed"

    PROCESSING_STATUS_CHOICES = [
        (STATUS_UNPROCESSED, "Unprocessed"),
        (STATUS_PROCESSED, "Processed"),
    ]

    ingested_at = models.DateTimeField(auto_now_add=True)
    log_source = models.CharField(max_length=128)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ingested_logs",
    )
    raw_message = models.TextField()
    processing_status = models.CharField(
        max_length=16,
        choices=PROCESSING_STATUS_CHOICES,
        default=STATUS_UNPROCESSED,
        help_text="Processing lifecycle state of this raw alert.",
    )

    class Meta:
        ordering = ["-ingested_at"]
        verbose_name = "Raw Log Entry"
        verbose_name_plural = "Raw Log Entries"

    def __str__(self) -> str:
        return f"[{self.log_source}] {self.raw_message[:80]}"

    def save(self, *args, **kwargs):
        """
        Enforce immutability of evidentiary fields after initial ingestion.

        - raw_message, log_source, uploaded_by, ingested_at must not change.
        - processing_status is allowed to change (workflow state).
        """
        if self.pk:
            original = type(self).objects.get(pk=self.pk)
            immutable_fields = ("raw_message", "log_source", "uploaded_by_id", "ingested_at")
            for field in immutable_fields:
                if getattr(original, field) != getattr(self, field):
                    raise ValidationError(
                        "Raw alert evidentiary fields are immutable and cannot be modified after ingestion."
                    )
        super().save(*args, **kwargs)

