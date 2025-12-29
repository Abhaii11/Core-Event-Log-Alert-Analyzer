from django.contrib import admin

from .models import AuditLogEntry


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ("sequence_number", "timestamp", "analyst", "action", "ip_address", "related_type", "related_id")
    list_filter = ("action", "analyst")
    search_fields = ("description", "related_id", "analyst__username")
    readonly_fields = ("sequence_number", "timestamp", "analyst", "action", "description", "ip_address", "related_type", "related_id", "prev_hash", "content_hash")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
