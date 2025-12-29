from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse

from .forms import LogFileUploadForm, ManualLogEntryForm
from .models import RawLogEntry
from soc_audit.models import create_audit_log, AuditLogEntry


@login_required
def upload_logs(request):
    """
    Allow SOC analysts to upload log files.

    - Processes the uploaded file line by line.
    - Stores each line as a RawLogEntry with metadata.
    - Raw log data is stored exactly as received (no parsing or transformation).
    """
    if request.method == "POST":
        form = LogFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            log_source = form.cleaned_data["log_source"]
            uploaded_file = form.cleaned_data["file"]

            # Ensure we treat data as text lines but keep content untouched.
            # Decode as UTF-8 while preserving exact characters within each line.
            text_iter = (chunk.decode("utf-8", errors="replace") for chunk in uploaded_file.chunks())
            buffer = ""
            created_count = 0

            with transaction.atomic():
                for piece in text_iter:
                    buffer += piece
                    *lines, buffer = buffer.splitlines(keepends=False)
                    for line in lines:
                        if line.strip() == "":
                            continue
                        RawLogEntry.objects.create(
                            log_source=log_source,
                            uploaded_by=request.user,
                            raw_message=line,
                        )
                        created_count += 1

                # Handle any remaining text in buffer as a final line.
                if buffer.strip():
                    RawLogEntry.objects.create(
                        log_source=log_source,
                        uploaded_by=request.user,
                        raw_message=buffer,
                    )
                    created_count += 1

            create_audit_log(
                request.user,
                AuditLogEntry.ACTION_LOG_UPLOAD,
                f"Uploaded {created_count} lines from {log_source}",
                ip_address=request.META.get("REMOTE_ADDR"),
                related_type="log_source",
                related_id=log_source,
            )
            return redirect(
                reverse("soc_ingest:raw_log_list") + f"?ingested={created_count}&source={log_source}"
            )
    else:
        form = LogFileUploadForm()

    return render(
        request,
        "soc_ingest/upload_logs.html",
        {
            "form": form,
        },
    )


@login_required
def manual_entry(request):
    """
    Allow SOC analysts to manually submit a single raw log line.
    """
    if request.method == "POST":
        form = ManualLogEntryForm(request.POST)
        if form.is_valid():
            RawLogEntry.objects.create(
                log_source=form.cleaned_data["log_source"],
                uploaded_by=request.user,
                raw_message=form.cleaned_data["raw_message"],
            )
            create_audit_log(
                request.user,
                AuditLogEntry.ACTION_MANUAL_LOG_ENTRY,
                "Manual log entry created",
                ip_address=request.META.get("REMOTE_ADDR"),
                related_type="log_source",
                related_id=form.cleaned_data["log_source"],
            )
            return redirect("soc_ingest:raw_log_list")
    else:
        form = ManualLogEntryForm()

    return render(
        request,
        "soc_ingest/manual_entry.html",
        {
            "form": form,
        },
    )


@login_required
def raw_log_list(request):
    """
    List and filter raw alerts stored as evidence.

    Supports filtering by processing status and source type.
    """
    qs = RawLogEntry.objects.select_related("uploaded_by")

    status = request.GET.get("status") or ""
    source = request.GET.get("source") or ""

    if status in {RawLogEntry.STATUS_UNPROCESSED, RawLogEntry.STATUS_PROCESSED}:
        qs = qs.filter(processing_status=status)
    if source:
        qs = qs.filter(log_source__icontains=source)

    logs = qs[:200]

    return render(
        request,
        "soc_ingest/raw_log_list.html",
        {
            "logs": logs,
            "ingested": request.GET.get("ingested"),
            "source": source or request.GET.get("source"),
            "status": status,
            "status_choices": RawLogEntry.PROCESSING_STATUS_CHOICES,
        },
    )


