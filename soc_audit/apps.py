from django.apps import AppConfig


class SocAuditConfig(AppConfig):
    name = "soc_audit"

    def ready(self):
        from . import signals  # noqa
