from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from soc_correlation.models import CorrelatedEvent
from soc_audit.models import create_audit_log, AuditLogEntry

from .forms import IncidentStatusUpdateForm
from .models import Incident, IncidentHistory


@login_required
def create_incident(request, event_id):
    """
    Convert a correlated security event into an incident.

    Generates a unique incident ID and links it to the correlated event.
    """
    event = get_object_or_404(CorrelatedEvent, pk=event_id)

    if hasattr(event, "incident"):
        return redirect("soc_incidents:incident_detail", incident_id=event.incident.incident_id)

    with transaction.atomic():
        year = timezone.now().year
        last_incident = Incident.objects.filter(incident_id__startswith=f"INC-{year}-").order_by("-incident_id").first()

        if last_incident:
            last_num = int(last_incident.incident_id.split("-")[-1])
            new_num = last_num + 1
        else:
            new_num = 1

        incident_id = f"INC-{year}-{new_num:04d}"

        incident = Incident.objects.create(
            incident_id=incident_id,
            correlated_event=event,
            attack_type=event.attack_type,
            risk_score=event.risk_score,
            current_status=Incident.STATUS_OPEN,
            created_by=request.user,
        )

        event.is_promoted_to_incident = True
        event.save(update_fields=["is_promoted_to_incident"])

        IncidentHistory.objects.create(
            incident=incident,
            changed_by=request.user,
            old_status="",
            new_status=Incident.STATUS_OPEN,
            notes=f"Incident created from correlated event. Attack type: {event.attack_type}, Source: {event.source}, Risk score: {event.risk_score:.1f}",
        )
        create_audit_log(
            request.user,
            AuditLogEntry.ACTION_INCIDENT_CREATE,
            f"Created incident {incident.incident_id}",
            ip_address=request.META.get("REMOTE_ADDR"),
            related_type="incident",
            related_id=incident.incident_id,
        )

    return redirect("soc_incidents:incident_detail", incident_id=incident.incident_id)


@login_required
def incident_list(request):
    """List all incidents with filtering by status and attack type."""
    qs = Incident.objects.select_related("assigned_to", "created_by", "correlated_event").prefetch_related("history")

    status = request.GET.get("status") or ""
    attack_type = request.GET.get("attack_type") or ""

    if status in dict(Incident.STATUS_CHOICES):
        qs = qs.filter(current_status=status)
    if attack_type:
        qs = qs.filter(attack_type__icontains=attack_type)

    incidents = qs[:100]

    return render(
        request,
        "soc_incidents/incident_list.html",
        {
            "incidents": incidents,
            "status": status,
            "attack_type": attack_type,
            "status_choices": Incident.STATUS_CHOICES,
        },
    )


@login_required
def incident_detail(request, incident_id):
    """View incident details, history, and update status."""
    incident = get_object_or_404(
        Incident.objects.select_related("assigned_to", "created_by", "correlated_event").prefetch_related(
            "history__changed_by", "correlated_event__related_alerts__raw_alert"
        ),
        incident_id=incident_id,
    )

    if request.method == "POST":
        form = IncidentStatusUpdateForm(request.POST)
        if form.is_valid():
            old_status = incident.current_status
            new_status = form.cleaned_data["new_status"]
            notes = form.cleaned_data["notes"]

            with transaction.atomic():
                incident.current_status = new_status
                incident.save(update_fields=["current_status"])

                IncidentHistory.objects.create(
                    incident=incident,
                    changed_by=request.user,
                    old_status=old_status,
                    new_status=new_status,
                    notes=notes,
                )
                create_audit_log(
                    request.user,
                    AuditLogEntry.ACTION_INCIDENT_UPDATE,
                    f"Updated incident {incident.incident_id} {old_status}→{new_status}",
                    ip_address=request.META.get("REMOTE_ADDR"),
                    related_type="incident",
                    related_id=incident.incident_id,
                )

            return redirect("soc_incidents:incident_detail", incident_id=incident.incident_id)
    else:
        form = IncidentStatusUpdateForm(initial={"new_status": incident.current_status})

    history = incident.history.all()[:50]

    return render(
        request,
        "soc_incidents/incident_detail.html",
        {
            "incident": incident,
            "form": form,
            "history": history,
        },
    )

