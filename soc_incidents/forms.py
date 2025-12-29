from django import forms

from .models import Incident


class IncidentStatusUpdateForm(forms.Form):
    """Form for updating incident status with investigation notes."""

    new_status = forms.ChoiceField(
        choices=Incident.STATUS_CHOICES,
        widget=forms.Select(attrs={"class": "field"}),
    )
    notes = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Enter investigation notes or reason for status change..."}),
        required=True,
        help_text="Document your investigation findings or reason for changing the status.",
    )

