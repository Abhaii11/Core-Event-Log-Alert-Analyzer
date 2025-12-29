from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .models import create_audit_log, AuditLogEntry


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    ip = request.META.get("REMOTE_ADDR")
    create_audit_log(user, AuditLogEntry.ACTION_LOGIN, "User login", ip_address=ip)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    ip = request.META.get("REMOTE_ADDR") if request else None
    create_audit_log(user, AuditLogEntry.ACTION_LOGOUT, "User logout", ip_address=ip)
