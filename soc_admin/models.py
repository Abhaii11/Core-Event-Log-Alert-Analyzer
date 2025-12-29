from django.conf import settings
from django.db import models
from django.utils import timezone


class SOCConfig(models.Model):
    correlation_window_minutes = models.PositiveIntegerField(default=15)
    threshold_low = models.PositiveIntegerField(default=5)
    threshold_medium = models.PositiveIntegerField(default=3)
    threshold_high = models.PositiveIntegerField(default=2)
    threshold_critical = models.PositiveIntegerField(default=1)
    enable_brute_force = models.BooleanField(default=True)
    enable_scanning = models.BooleanField(default=True)
    enable_unauthorized_access = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "SOC Configuration"
        verbose_name_plural = "SOC Configuration"

    @classmethod
    def get(cls):
        obj = cls.objects.first()
        if not obj:
            obj = cls.objects.create()
        return obj


class AnalystProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="analyst_profile")
    must_change_password = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Profile for {self.user_id}"
