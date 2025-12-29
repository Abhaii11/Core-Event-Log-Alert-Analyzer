from django.contrib import admin

from .models import Incident, IncidentHistory


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("incident_id", "attack_type", "current_status", "risk_score", "assigned_to", "created_at")
    list_filter = ("current_status", "attack_type", "created_at", "assigned_to")
    search_fields = ("incident_id", "attack_type", "correlated_event__source")
    date_hierarchy = "created_at"
    readonly_fields = ("incident_id", "correlated_event", "attack_type", "risk_score", "created_at", "created_by")


@admin.register(IncidentHistory)
class IncidentHistoryAdmin(admin.ModelAdmin):
    list_display = ("incident", "timestamp", "changed_by", "old_status", "new_status")
    list_filter = ("timestamp", "new_status")
    search_fields = ("incident__incident_id", "notes")
    date_hierarchy = "timestamp"
    readonly_fields = ("incident", "timestamp", "changed_by", "old_status", "new_status", "notes")

