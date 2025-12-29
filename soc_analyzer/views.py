from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from soc_ingest.models import RawLogEntry

from .models import RawAlertAnalysis
from .rules import analyze_raw_alert


@login_required
def run_analysis(request):
    """
    Run rule-based analysis on unprocessed raw alerts.

    This simulates a SIEM batch detection job triggered by an analyst.
    """
    # Limit batch size to avoid huge processing in one click.
    pending = RawLogEntry.objects.filter(
        processing_status=RawLogEntry.STATUS_UNPROCESSED
    ).select_related("uploaded_by")[:500]

    analyzed_count = 0

    for raw in pending:
        result = analyze_raw_alert(raw)
        RawAlertAnalysis.objects.update_or_create(
            raw_alert=raw,
            defaults={
                "attack_type": result.attack_type,
                "severity": result.severity,
                "is_suspicious": result.is_suspicious,
                "rule_name": result.rule_name,
                "notes": result.notes,
            },
        )
        # Mark the raw alert as processed while keeping evidentiary fields immutable.
        raw.processing_status = RawLogEntry.STATUS_PROCESSED
        raw.save(update_fields=["processing_status"])
        analyzed_count += 1

    return redirect(reverse("soc_analyzer:analysis_results") + f"?analyzed={analyzed_count}")


@login_required
def analysis_results(request):
    """
    Display analyzed alerts with classification and severity.
    """
    qs = RawAlertAnalysis.objects.select_related("raw_alert", "raw_alert__uploaded_by")

    attack_type = request.GET.get("attack_type") or ""
    severity = request.GET.get("severity") or ""
    suspicious = request.GET.get("suspicious") or ""

    if attack_type:
        qs = qs.filter(attack_type=attack_type)
    if severity:
        qs = qs.filter(severity=severity)
    if suspicious in {"true", "false"}:
        qs = qs.filter(is_suspicious=(suspicious == "true"))

    analyses = qs[:200]

    return render(
        request,
        "soc_analyzer/analysis_results.html",
        {
            "analyses": analyses,
            "attack_type": attack_type,
            "severity": severity,
            "suspicious": suspicious,
            "attack_type_choices": RawAlertAnalysis.ATTACK_TYPE_CHOICES,
            "severity_choices": RawAlertAnalysis.SEVERITY_CHOICES,
            "analyzed": request.GET.get("analyzed"),
        },
    )


