from django.urls import path

from . import views

app_name = "soc_ingest"

urlpatterns = [
    path("upload/", views.upload_logs, name="upload_logs"),
    path("manual/", views.manual_entry, name="manual_entry"),
    path("raw/", views.raw_log_list, name="raw_log_list"),
]


