from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.urls import reverse


def admin_required(view_func):
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            login_url = reverse("soc_auth:login")
            next_url = request.get_full_path()
            return redirect(f"{login_url}?next={next_url}")
        if not (request.user.is_staff or request.user.is_superuser):
            return HttpResponseForbidden("Forbidden")
        return view_func(request, *args, **kwargs)
    return _wrapped
