from django.contrib import admin

from .models import RawAlertAnalysis


@admin.register(RawAlertAnalysis)
class RawAlertAnalysisAdmin(admin.ModelAdmin):
    list_display = ("detected_at", "attack_type", "severity", "is_suspicious", "raw_alert")
    list_filter = ("attack_type", "severity", "is_suspicious", "detected_at")
    search_fields = ("raw_alert__raw_message", "rule_name")
    autocomplete_fields = ("raw_alert",)


