from django.contrib import admin

from .models import CorrelatedEvent


@admin.register(CorrelatedEvent)
class CorrelatedEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "attack_type", "source", "total_alerts", "risk_score", "is_promoted_to_incident")
    list_filter = ("attack_type", "is_promoted_to_incident", "created_at")
    search_fields = ("attack_type", "source")
    autocomplete_fields = ("related_alerts",)


