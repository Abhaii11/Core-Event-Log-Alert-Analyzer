from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.views import LoginView, LogoutView
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils import timezone
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.decorators import login_required

from soc_analyzer.models import RawAlertAnalysis
from soc_incidents.models import Incident
from soc_admin.models import AnalystProfile


class SOCLoginView(LoginView):
    """Secure login view for SOC analysts using Django's built-in auth."""

    template_name = "soc_auth/login.html"
    redirect_authenticated_user = True


class SOCLogoutView(LogoutView):
    """Logs out SOC analysts and clears the session."""

    next_page = reverse_lazy("soc_auth:login")


def is_analyst(user):
    return user.is_authenticated and (user.is_superuser or user.groups.filter(name="Analyst").exists())


@user_passes_test(is_analyst, login_url=reverse_lazy("soc_auth:login"))
def dashboard(request):
    """High-level SOC dashboard only accessible to authenticated analysts."""
    total_alerts = RawAlertAnalysis.objects.count()
    total_incidents = Incident.objects.count()
    open_incidents = Incident.objects.filter(
        current_status__in=[Incident.STATUS_OPEN, Incident.STATUS_INVESTIGATING]
    ).count()
    critical_alerts = RawAlertAnalysis.objects.filter(severity=RawAlertAnalysis.SEVERITY_CRITICAL).count()

    context = {
        "title": "SOC Overview",
        "metrics": {
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_alerts": critical_alerts,
        },
        "last_updated": timezone.now(),
    }
    return render(request, "soc_auth/dashboard.html", context)


@user_passes_test(is_analyst, login_url=reverse_lazy("soc_auth:login"))
def dashboard_data(request):
    total_alerts = RawAlertAnalysis.objects.count()
    total_incidents = Incident.objects.count()
    open_incidents = Incident.objects.filter(
        current_status__in=[Incident.STATUS_OPEN, Incident.STATUS_INVESTIGATING]
    ).count()
    critical_alerts = RawAlertAnalysis.objects.filter(severity=RawAlertAnalysis.SEVERITY_CRITICAL).count()

    severities = [choice[0] for choice in RawAlertAnalysis.SEVERITY_CHOICES]
    severity_counts = [
        RawAlertAnalysis.objects.filter(severity=s).count() for s in severities
    ]

    statuses = [choice[0] for choice in Incident.STATUS_CHOICES]
    status_counts = [Incident.objects.filter(current_status=s).count() for s in statuses]

    return JsonResponse(
        {
            "metrics": {
                "total_alerts": total_alerts,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "critical_alerts": critical_alerts,
            },
            "charts": {
                "alert_severity": {
                    "labels": severities,
                    "data": severity_counts,
                },
                "incident_status": {
                    "labels": statuses,
                    "data": status_counts,
                },
            },
            "last_updated": timezone.now().isoformat(),
        }
    )


@login_required
def alerts(request):
    """Alert feed view requiring authentication."""
    sample_alerts = [
        {
            "id": "AL-1012",
            "severity": "Critical",
            "source": "EDR",
            "description": "Suspicious PowerShell execution on DC01",
        },
        {
            "id": "AL-1013",
            "severity": "High",
            "source": "Firewall",
            "description": "Large outbound data transfer to unknown IP",
        },
    ]
    return render(request, "soc_auth/alerts.html", {"alerts": sample_alerts})


@login_required
def incidents(request):
    """Incident list view requiring authentication."""
    sample_incidents = [
        {
            "id": "INC-5001",
            "status": "Investigating",
            "owner": "analyst1",
            "summary": "Possible credential stuffing against OWA",
        },
        {
            "id": "INC-5002",
            "status": "Contained",
            "owner": "analyst2",
            "summary": "Malware beacon from HR workstation",
        },
    ]
    return render(request, "soc_auth/incidents.html", {"incidents": sample_incidents})


def is_admin(user):
    return user.is_authenticated and user.groups.filter(name="Admin").exists()


@user_passes_test(is_admin, login_url=reverse_lazy("soc_auth:login"))
def admin_console(request):
    """Example admin-only page using Django groups for role-based access."""
    return render(request, "soc_auth/admin_console.html")

@login_required
def password_change_required(request):
    form = SetPasswordForm(user=request.user, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        profile, _ = AnalystProfile.objects.get_or_create(user=request.user)
        profile.must_change_password = False
        profile.save(update_fields=["must_change_password"])
        return render(request, "soc_auth/login.html", {"form": None})
    return render(request, "soc_auth/password_change_required.html", {"form": form})


