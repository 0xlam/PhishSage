from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.console import Console

console = Console()


# -----------------------------
# Attachment listing
# -----------------------------

def print_attachment_listing(results):
    console.print()

    attachments = results.get("attachments", results) if isinstance(results, dict) else {}

    if not attachments:
        console.print(Panel(
            Text("No attachments found.", style="yellow"),
            title="[bold]Attachment listing[/bold]",
            border_style="yellow",
        ))
        return

    table = Table(box=box.SIMPLE, expand=True, padding=(0, 1))

    table.add_column("#", style="dim", width=4)
    table.add_column("Filename", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("MIME type", style="magenta")

    for idx, (filename, meta) in enumerate(attachments.items(), 1):
        table.add_row(
            str(idx),
            filename,
            meta.get("size_human", "N/A"),
            meta.get("mime_type", "N/A"),
        )

    console.print(Panel(
        table,
        title="[bold]Attachment listing[/bold]",
        subtitle=f"{len(attachments)} attachment(s)",
        border_style="dim",
    ))


# -----------------------------
# Extraction
# -----------------------------

def print_attachment_extraction(results, save_dir):
    console.print()

    if not results:
        console.print(Panel(
            Text("No attachments found.", style="yellow"),
            title="[bold]Extracting attachments[/bold]",
            subtitle=save_dir,
            border_style="yellow",
        ))
        return

    saved_count = 0

    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Status", width=10)
    table.add_column("Filename", style="cyan")
    table.add_column("Saved path", style="green")

    for filename, path in results.items():
        if path:
            saved_count += 1
            status = Text("SAVED", style="bold green")
            saved_path = path
        else:
            status = Text("SKIPPED", style="bold yellow")
            saved_path = "Not saved"

        table.add_row(status, filename, saved_path)

    console.print(Panel(
        table,
        title="[bold]Attachment extraction[/bold]",
        subtitle=f"{saved_count}/{len(results)} saved → {save_dir}",
        border_style="dim",
    ))


# -----------------------------
# Hashes
# -----------------------------

def print_attachment_hashes(hashes):
    console.print()

    if not hashes:
        console.print(Panel(
            Text("No attachment hashes generated.", style="yellow"),
            title="[bold]Attachment hashes[/bold]",
            border_style="yellow",
        ))
        return

    table = Table(box=box.SIMPLE, expand=True, show_header=False, padding=(0, 1))
    table.add_column("label", style="dim", width=10)
    table.add_column("value", style="green")

    for idx, (filename, info) in enumerate(hashes.items()):
        if idx > 0:
            table.add_section()

        table.add_row(Text(filename, style="cyan bold"), "")
        table.add_row("MD5", info.get("md5", "N/A"))
        table.add_row("SHA1", info.get("sha1", "N/A"))
        table.add_row("SHA256", info.get("sha256", "N/A"))

    console.print(Panel(
        table,
        title="[bold]Attachment hash summary[/bold]",
        subtitle=f"{len(hashes)} hashed file(s)",
        border_style="dim",
    ))


# -----------------------------
# VirusTotal scan 
# -----------------------------

def print_vt_scan_attachments(results):
    console.print()

    attachments = results.get("attachments", results)
    summary = results.get("summary", {})

    if not attachments:
        console.print(Panel(
            Text("No attachments scanned.", style="yellow"),
            title="[bold]VirusTotal scan — attachments[/bold]",
            border_style="yellow",
        ))
        return

    total_files = 0
    malicious_total = 0
    suspicious_total = 0

    for filename, info in attachments.items():
        total_files += 1

        sha256 = info.get("sha256", "N/A")
        vt = info.get("virustotal", {})

        status = vt.get("status", "unknown")
        error = vt.get("reason")

        stats_block = vt.get("stats") or {}
        stats = stats_block.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)

        malicious_total += malicious
        suspicious_total += suspicious

        is_flagged = malicious > 0 or suspicious > 0

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("label", style="dim", width=14)
        body.add_column("value")

        body.add_row("Status", status)

        if error and status != "ok":
            body.add_row("Reason", Text(str(error), style="red"))

        if stats:
            body.add_row("Malicious", Text(str(malicious), style="red" if malicious else "default"))
            body.add_row("Suspicious", Text(str(suspicious), style="yellow" if suspicious else "default"))
            body.add_row("Undetected", str(undetected))
            body.add_row("Harmless", Text(str(harmless), style="green" if harmless else "default"))

            last_scan = stats_block.get("last_analysis_date")
            if last_scan:
                try:
                    body.add_row("Last scan", datetime.fromisoformat(str(last_scan)).strftime("%Y-%m-%d %H:%M"))
                except Exception:
                    pass

            first_seen = stats_block.get("first_submission_date")
            if first_seen:
                try:
                    body.add_row("First seen", datetime.fromisoformat(str(first_seen)).strftime("%Y-%m-%d %H:%M"))
                except Exception:
                    pass

        else:
            body.add_row("Stats", Text("unavailable", style="dim"))

        console.print(Panel(
            body,
            title=Text(filename, style="cyan"),
            subtitle=sha256,
            border_style="red" if is_flagged else "dim",
        ))

    if summary:
        console.print(
            f"\n[dim]Summary:[/dim] {summary.get('total', 0)} file(s) · "
            f"[yellow]{len(summary.get('errors', []))} error(s)[/yellow]"
        )


# -----------------------------
# YARA scan 
# -----------------------------

def print_yara_scan_attachments(results, verbose=False):
    console.print()

    attachments = results.get("attachments", results)
    summary = results.get("summary", {})

    if not attachments:
        console.print(Panel(
            Text("No attachments scanned.", style="yellow"),
            title="[bold]YARA scan — attachments[/bold]",
            border_style="yellow",
        ))
        return

    total_files = 0
    matched_files = 0
    error_files = 0

    for filename, scan_result in attachments.items():
        total_files += 1

        if "error" in scan_result:
            error_files += 1
            console.print(Panel(
                Text(f"Scan failed: {scan_result['error']}", style="red"),
                title=Text(filename, style="cyan"),
                border_style="red",
            ))
            continue

        flagged = scan_result.get("flag", False)
        matches = scan_result.get("matches", [])

        if not flagged:
            console.print(Panel(
                Text("No rules matched.", style="green"),
                title=Text(filename, style="cyan"),
                border_style="green",
            ))
            continue

        matched_files += 1

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("field", style="dim", width=14)
        body.add_column("value")

        for idx, match in enumerate(matches, 1):
            if idx > 1:
                body.add_section()

            rule = match.get("rule", "unknown_rule")
            namespace = match.get("namespace", "?")
            meta = match.get("rule_meta", {})

            severity = (meta.get("severity") or meta.get("Severity") or "unknown").lower()

            sev_style = {
                "high": "bold red",
                "medium": "bold yellow",
                "low": "bold green",
            }.get(severity, "dim")

            body.add_row("Rule", Text(rule, style="bold"))
            body.add_row("Namespace", namespace)
            body.add_row("Severity", Text(severity, style=sev_style))

            for k, v in meta.items():
                if k.lower() != "severity":
                    body.add_row(k, str(v))

            if verbose and match.get("strings"):
                for s in match["strings"]:
                    body.add_row(
                        f"{s.get('name', '?')}@{s.get('offset', '?')}",
                        Text(s.get("data", ""), style="dim"),
                    )

        console.print(Panel(
            body,
            title=Text(filename, style="cyan"),
            subtitle=f"{len(matches)} rule(s) matched",
            border_style="red",
        ))

    if summary:
        console.print(
            f"\n[dim]Summary:[/dim] {summary.get('total', 0)} file(s) · "
            f"[red]{matched_files} matched[/red] · "
            f"[yellow]{error_files} error(s)[/yellow]"
        )