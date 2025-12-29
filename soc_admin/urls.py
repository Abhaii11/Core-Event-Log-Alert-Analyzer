from django.urls import path

from . import views

app_name = "soc_admin"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("analysts/", views.analyst_list, name="analyst_list"),
    path("analysts/create/", views.analyst_create, name="analyst_create"),
    path("analysts/<int:user_id>/", views.analyst_update, name="analyst_update"),
    path("analysts/<int:user_id>/reset-password/", views.analyst_reset_password, name="analyst_reset_password"),
    path("config/", views.config_view, name="config"),
]
