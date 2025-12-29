from django.urls import path

from . import views

app_name = "soc_auth"

urlpatterns = [
    path("login/", views.SOCLoginView.as_view(), name="login"),
    path("logout/", views.SOCLogoutView.as_view(), name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("dashboard/data/", views.dashboard_data, name="dashboard_data"),
    path("alerts/", views.alerts, name="alerts"),
    path("incidents/", views.incidents, name="incidents"),
    path("admin-console/", views.admin_console, name="admin_console"),
    path("password-change/", views.password_change_required, name="password_change_required"),
]


