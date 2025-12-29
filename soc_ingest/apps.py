from django.apps import AppConfig


class SocIngestConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "soc_ingest"
    verbose_name = "SOC Log Ingestion"


