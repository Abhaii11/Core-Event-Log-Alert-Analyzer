from django.urls import path

from . import views

app_name = "soc_analyzer"

urlpatterns = [
    path("run/", views.run_analysis, name="run_analysis"),
    path("results/", views.analysis_results, name="analysis_results"),
]


