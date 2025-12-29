from django import forms


class LogFileUploadForm(forms.Form):
    log_source = forms.CharField(
        max_length=128,
        help_text="e.g. auth.log, nginx-access, windows-security",
        label="Log source",
    )
    file = forms.FileField(
        label="Log file",
        help_text="Plain text log file. Each line will be stored as a separate raw entry.",
    )


class ManualLogEntryForm(forms.Form):
    log_source = forms.CharField(
        max_length=128,
        help_text="e.g. analyst-note, manual-incident-log",
        label="Log source",
    )
    raw_message = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6}),
        label="Raw log line",
        help_text="Paste or type the exact log line or event as received.",
    )


