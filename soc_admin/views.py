from django.contrib.auth.models import Group, User
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from soc_audit.models import create_audit_log, AuditLogEntry
from soc_analyzer.models import RawAlertAnalysis
from soc_incidents.models import Incident
from .decorators import admin_required
from .forms import AnalystCreateForm, AnalystUpdateForm, AnalystPasswordResetForm, SOCConfigForm
from .models import SOCConfig, AnalystProfile


@admin_required
def dashboard(request):
    analysts_group, _ = Group.objects.get_or_create(name="Analyst")
    total_analysts = User.objects.filter(groups=analysts_group).count()
    active_analysts = User.objects.filter(groups=analysts_group, is_active=True).count()
    total_incidents = Incident.objects.count()
    critical_alerts = RawAlertAnalysis.objects.filter(severity=RawAlertAnalysis.SEVERITY_CRITICAL).count()
    return render(
        request,
        "soc_admin/dashboard.html",
        {
            "total_analysts": total_analysts,
            "active_analysts": active_analysts,
            "total_incidents": total_incidents,
            "critical_alerts": critical_alerts,
        },
    )


@admin_required
def analyst_list(request):
    analysts_group, _ = Group.objects.get_or_create(name="Analyst")
    users = User.objects.filter(groups=analysts_group).order_by("username")
    return render(request, "soc_admin/analyst_list.html", {"users": users})


@admin_required
def analyst_create(request):
    form = AnalystCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            user = User.objects.create_user(
                username=form.cleaned_data["username"],
                email=form.cleaned_data.get("email") or "",
                password=form.cleaned_data.get("password") or None,
                is_active=form.cleaned_data.get("is_active") or False,
            )
            role = form.cleaned_data["role"]
            analysts_group, _ = Group.objects.get_or_create(name="Analyst")
            admin_group, _ = Group.objects.get_or_create(name="Admin")
            user.groups.add(analysts_group)
            if role == "Admin":
                user.groups.add(admin_group)
                user.is_staff = True
                user.save(update_fields=["is_staff"])
            AnalystProfile.objects.get_or_create(user=user)
            create_audit_log(
                request.user,
                AuditLogEntry.ACTION_ADMIN_USER_CREATE,
                f"Created user {user.username}",
                ip_address=request.META.get("REMOTE_ADDR"),
                related_type="user",
                related_id=user.id,
            )
        return redirect("soc_admin:analyst_list")
    return render(request, "soc_admin/analyst_form.html", {"form": form, "mode": "create"})


@admin_required
def analyst_update(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    role = "Admin" if user.groups.filter(name="Admin").exists() else "Analyst"
    form = AnalystUpdateForm(request.POST or None, initial={"email": user.email, "is_active": user.is_active, "role": role})
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            user.email = form.cleaned_data.get("email") or ""
            user.is_active = form.cleaned_data.get("is_active") or False
            user.save(update_fields=["email", "is_active"])
            analysts_group, _ = Group.objects.get_or_create(name="Analyst")
            admin_group, _ = Group.objects.get_or_create(name="Admin")
            user.groups.add(analysts_group)
            if form.cleaned_data["role"] == "Admin":
                user.groups.add(admin_group)
                user.is_staff = True
                user.save(update_fields=["is_staff"])
            else:
                user.groups.remove(admin_group)
                user.is_staff = False
                user.save(update_fields=["is_staff"])
            create_audit_log(
                request.user,
                AuditLogEntry.ACTION_ADMIN_USER_UPDATE,
                f"Updated user {user.username}",
                ip_address=request.META.get("REMOTE_ADDR"),
                related_type="user",
                related_id=user.id,
            )
        return redirect("soc_admin:analyst_list")
    return render(request, "soc_admin/analyst_form.html", {"form": form, "mode": "update", "user": user})


@admin_required
def analyst_reset_password(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    form = AnalystPasswordResetForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user.set_password(form.cleaned_data["new_password"])
        user.save(update_fields=["password"])
        profile, _ = AnalystProfile.objects.get_or_create(user=user)
        profile.must_change_password = True
        profile.save(update_fields=["must_change_password"])
        create_audit_log(
            request.user,
            AuditLogEntry.ACTION_ADMIN_USER_PASSWORD_RESET,
            f"Password reset for {user.username}",
            ip_address=request.META.get("REMOTE_ADDR"),
            related_type="user",
            related_id=user.id,
        )
        return redirect("soc_admin:analyst_list")
    return render(request, "soc_admin/password_reset.html", {"form": form, "user": user})


@admin_required
def config_view(request):
    cfg = SOCConfig.get()
    form = SOCConfigForm(request.POST or None, instance=cfg)
    if request.method == "POST" and form.is_valid():
        form.save()
        create_audit_log(
            request.user,
            AuditLogEntry.ACTION_ADMIN_CONFIG_UPDATE,
            "Updated SOC configuration",
            ip_address=request.META.get("REMOTE_ADDR"),
            related_type="config",
            related_id=cfg.id,
        )
        return redirect("soc_admin:config")
    return render(request, "soc_admin/config.html", {"form": form, "updated_at": cfg.updated_at})
