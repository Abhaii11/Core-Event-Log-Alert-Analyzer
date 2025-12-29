from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from soc_analyzer.models import RawAlertAnalysis

from .engine import correlate_alerts
from .models import CorrelatedEvent
from soc_admin.models import SOCConfig


@login_required
def run_correlation(request):
    """
    Run correlation on recent analyzed alerts to reduce noise and create events.
    """
    # Only consider suspicious analyzed alerts to avoid noise.
    analyzed = RawAlertAnalysis.objects.filter(is_suspicious=True).select_related(
        "raw_alert", "raw_alert__uploaded_by"
    )

    cfg = SOCConfig.get()
    groups = correlate_alerts(analyzed, window_minutes=cfg.correlation_window_minutes)

    created_events = 0

    for group in groups:
        # Apply simple thresholds based on severity and volume.
        highest_severity = max(a.severity for a in group["alerts"])
        total = group["total_alerts"]

        if highest_severity == "critical" and total < cfg.threshold_critical:
            continue
        elif highest_severity == "high" and total < cfg.threshold_high:
            continue
        elif highest_severity == "medium" and total < cfg.threshold_medium:
            continue
        elif highest_severity == "low" and total < cfg.threshold_low:
            continue

        event, created = CorrelatedEvent.objects.get_or_create(
            attack_type=group["attack_type"],
            source=group["source"],
            start_time=group["start_time"],
            end_time=group["end_time"],
            total_alerts=group["total_alerts"],
            defaults={"risk_score": group["risk_score"]},
        )
        if created:
            event.related_alerts.set(group["alerts"])
            created_events += 1

    return redirect(reverse("soc_correlation:event_list") + f"?created={created_events}")


@login_required
def event_list(request):
    """
    List correlated security events that can be promoted to incidents.
    """
    qs = CorrelatedEvent.objects.prefetch_related("related_alerts", "related_alerts__raw_alert")

    attack_type = request.GET.get("attack_type") or ""
    source = request.GET.get("source") or ""

    if attack_type:
        qs = qs.filter(attack_type=attack_type)
    if source:
        qs = qs.filter(source__icontains=source)

    events = qs[:200]

    return render(
        request,
        "soc_correlation/event_list.html",
        {
            "events": events,
            "attack_type": attack_type,
            "source": source,
            "created": request.GET.get("created"),
        },
    )


