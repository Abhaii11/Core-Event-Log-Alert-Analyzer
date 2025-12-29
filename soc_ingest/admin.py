from django.contrib import admin

from .models import RawLogEntry


@admin.register(RawLogEntry)
class RawLogEntryAdmin(admin.ModelAdmin):
    list_display = ("ingested_at", "log_source", "uploaded_by", "processing_status", "short_message")
    list_filter = ("log_source", "uploaded_by", "ingested_at", "processing_status")
    search_fields = ("raw_message", "log_source", "uploaded_by__username")
    date_hierarchy = "ingested_at"
    readonly_fields = ("ingested_at", "log_source", "uploaded_by", "raw_message")

    def short_message(self, obj):
        return (obj.raw_message[:97] + "...") if len(obj.raw_message) > 100 else obj.raw_message

    short_message.short_description = "Raw Message"


