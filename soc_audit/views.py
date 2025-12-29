from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render
from django.urls import reverse_lazy

from .models import AuditLogEntry


def is_admin(user):
    return user.is_authenticated and (user.is_superuser or user.groups.filter(name="Admin").exists())


@user_passes_test(is_admin, login_url=reverse_lazy("soc_auth:login"))
def audit_list(request):
    qs = AuditLogEntry.objects.select_related("analyst").order_by("-sequence_number")
    action = request.GET.get("action") or ""
    if action in dict(AuditLogEntry.ACTION_CHOICES):
        qs = qs.filter(action=action)
    logs = qs[:200]
    return render(
        request,
        "soc_audit/audit_list.html",
        {
            "logs": logs,
            "action": action,
            "action_choices": AuditLogEntry.ACTION_CHOICES,
        },
    )
