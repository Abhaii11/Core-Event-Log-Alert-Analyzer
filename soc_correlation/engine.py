from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from django.utils import timezone

from soc_analyzer.models import RawAlertAnalysis


def _severity_weight(severity: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(severity, 1)


def correlate_alerts(
    analyses: Iterable[RawAlertAnalysis],
    window_minutes: int = 15,
) -> list[dict]:
    """
    Group analyzed alerts into correlated buckets by:
    - attack_type
    - source (log_source)
    - time window (within window_minutes)

    Returns a list of correlation groups with:
    - attack_type, source, start_time, end_time
    - alerts: list of RawAlertAnalysis
    - total_alerts
    - risk_score (severity-weighted volume)
    """
    groups: dict[tuple[str, str], list[RawAlertAnalysis]] = defaultdict(list)
    window = timedelta(minutes=window_minutes)

    now = timezone.now()
    min_time = now - window

    for a in analyses:
        # restrict to recent alerts within the window relative to now
        if a.detected_at < min_time:
            continue
        key = (a.attack_type, a.raw_alert.log_source)
        groups[key].append(a)

    correlated: list[dict] = []

    for (attack_type, source), alerts in groups.items():
        if not alerts:
            continue

        alerts_sorted = sorted(alerts, key=lambda x: x.detected_at)
        start_time = alerts_sorted[0].detected_at
        end_time = alerts_sorted[-1].detected_at
        total = len(alerts_sorted)

        # Base risk from highest severity in the group
        max_severity_weight = max(_severity_weight(a.severity) for a in alerts_sorted)
        # Volume factor: log-like growth using simple formula
        volume_factor = 1 + (total - 1) * 0.5
        risk_score = max_severity_weight * volume_factor

        correlated.append(
            {
                "attack_type": attack_type,
                "source": source,
                "start_time": start_time,
                "end_time": end_time,
                "alerts": alerts_sorted,
                "total_alerts": total,
                "risk_score": risk_score,
            }
        )

    return correlated


