from django.shortcuts import redirect
from django.urls import reverse


class PasswordChangeRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            profile = getattr(request.user, "analyst_profile", None)
            path = request.path
            allow_paths = {
                reverse("soc_auth:login"),
                reverse("soc_auth:logout"),
                reverse("soc_auth:password_change_required"),
            }
            if profile and profile.must_change_password and path not in allow_paths:
                return redirect("soc_auth:password_change_required")
        return self.get_response(request)
