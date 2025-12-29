from django.urls import path

from . import views

app_name = "soc_correlation"

urlpatterns = [
    path("run/", views.run_correlation, name="run_correlation"),
    path("events/", views.event_list, name="event_list"),
]


