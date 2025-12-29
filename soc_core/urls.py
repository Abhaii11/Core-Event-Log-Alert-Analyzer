from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include(("soc_auth.urls", "soc_auth"), namespace="soc_auth")),
    path("logs/", include(("soc_ingest.urls", "soc_ingest"), namespace="soc_ingest")),
    path("analysis/", include(("soc_analyzer.urls", "soc_analyzer"), namespace="soc_analyzer")),
    path("correlation/", include(("soc_correlation.urls", "soc_correlation"), namespace="soc_correlation")),
    path("incidents/", include(("soc_incidents.urls", "soc_incidents"), namespace="soc_incidents")),
    path("audit/", include(("soc_audit.urls", "soc_audit"), namespace="soc_audit")),
    path("admin-console/", include(("soc_admin.urls", "soc_admin"), namespace="soc_admin")),
    path("", RedirectView.as_view(pattern_name="soc_auth:dashboard", permanent=False)),
]


