from django import forms
from django.contrib.auth.models import Group, User

from .models import SOCConfig


class AnalystCreateForm(forms.Form):
    username = forms.CharField(max_length=150)
    email = forms.EmailField(required=False)
    is_active = forms.BooleanField(required=False, initial=True)
    role = forms.ChoiceField(choices=[("Analyst", "Analyst"), ("Admin", "Admin")])
    password = forms.CharField(widget=forms.PasswordInput, required=False)

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists.")
        return username


class AnalystUpdateForm(forms.Form):
    email = forms.EmailField(required=False)
    is_active = forms.BooleanField(required=False)
    role = forms.ChoiceField(choices=[("Analyst", "Analyst"), ("Admin", "Admin")])


class AnalystPasswordResetForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput)


class SOCConfigForm(forms.ModelForm):
    class Meta:
        model = SOCConfig
        fields = [
            "correlation_window_minutes",
            "threshold_low",
            "threshold_medium",
            "threshold_high",
            "threshold_critical",
            "enable_brute_force",
            "enable_scanning",
            "enable_unauthorized_access",
        ]
