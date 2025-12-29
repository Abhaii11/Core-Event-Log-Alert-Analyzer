import hashlib
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class AuditLogEntry(models.Model):
    ACTION_LOGIN = "login"
    ACTION_LOGOUT = "logout"
    ACTION_LOG_UPLOAD = "log_upload"
    ACTION_MANUAL_LOG_ENTRY = "manual_log_entry"
    ACTION_INCIDENT_UPDATE = "incident_update"
    ACTION_INCIDENT_CREATE = "incident_create"
    ACTION_ADMIN_USER_CREATE = "admin_user_create"
    ACTION_ADMIN_USER_UPDATE = "admin_user_update"
    ACTION_ADMIN_USER_PASSWORD_RESET = "admin_user_password_reset"
    ACTION_ADMIN_CONFIG_UPDATE = "admin_config_update"

    ACTION_CHOICES = [
        (ACTION_LOGIN, "Login"),
        (ACTION_LOGOUT, "Logout"),
        (ACTION_LOG_UPLOAD, "Log upload"),
        (ACTION_MANUAL_LOG_ENTRY, "Manual log entry"),
        (ACTION_INCIDENT_UPDATE, "Incident update"),
        (ACTION_INCIDENT_CREATE, "Incident create"),
        (ACTION_ADMIN_USER_CREATE, "Admin user create"),
        (ACTION_ADMIN_USER_UPDATE, "Admin user update"),
        (ACTION_ADMIN_USER_PASSWORD_RESET, "Admin user password reset"),
        (ACTION_ADMIN_CONFIG_UPDATE, "Admin config update"),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    analyst = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    related_type = models.CharField(max_length=64, blank=True)
    related_id = models.CharField(max_length=128, blank=True)
    sequence_number = models.BigIntegerField()
    prev_hash = models.CharField(max_length=64, blank=True)
    content_hash = models.CharField(max_length=64)

    class Meta:
        ordering = ["-sequence_number"]
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log Entries"

    def __str__(self):
        return f"{self.action} by {self.analyst_id} at {self.timestamp}"

    def save(self, *args, **kwargs):
        if self.pk:
            original = type(self).objects.get(pk=self.pk)
            immutable_fields = ("analyst_id", "action", "description", "ip_address", "related_type", "related_id", "timestamp", "sequence_number", "prev_hash", "content_hash")
            for f in immutable_fields:
                if getattr(original, f) != getattr(self, f):
                    raise ValidationError("Audit log entries are immutable.")
            super().save(*args, **kwargs)
            return
        last = type(self).objects.order_by("-sequence_number").first()
        self.sequence_number = 1 if not last else last.sequence_number + 1
        self.prev_hash = "" if not last else last.content_hash
        payload = f"{self.sequence_number}|{self.prev_hash}|{self.analyst_id}|{self.action}|{self.description}|{self.ip_address}|{self.related_type}|{self.related_id}|{timezone.now().isoformat()}"
        self.content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        raise ValidationError("Audit log entries cannot be deleted.")


def create_audit_log(analyst, action, description, ip_address=None, related_type="", related_id=""):
    AuditLogEntry.objects.create(
        analyst=analyst,
        action=action,
        description=description,
        ip_address=ip_address or "",
        related_type=related_type or "",
        related_id=str(related_id or ""),
    )
