from django.urls import path

from . import views

app_name = "soc_incidents"

urlpatterns = [
    path("", views.incident_list, name="incident_list"),
    path("create/<int:event_id>/", views.create_incident, name="create_incident"),
    path("<str:incident_id>/", views.incident_detail, name="incident_detail"),
]

