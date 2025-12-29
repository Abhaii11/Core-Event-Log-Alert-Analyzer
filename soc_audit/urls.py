from django.urls import path

from . import views

app_name = "soc_audit"

urlpatterns = [
    path("", views.audit_list, name="audit_list"),
]
