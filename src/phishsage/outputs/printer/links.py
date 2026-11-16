from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich import box

console = Console()


def _flag_icon(flagged: bool) -> Text:
    if flagged:
        return Text("✗", style="bold red")
    return Text("✓", style="bold green")


def _heuristic_icon(result: dict) -> Text:
    status = result.get("status", "unknown")

    if status == "skipped":
        return Text("–", style="dim")

    if status == "error":
        return Text("!", style="bold yellow")

    return _flag_icon(result.get("flags", False))


def _format_date(value) -> str:
    if not value:
        return "N/A"
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(value)


def print_url_extraction(url_data):
    links = url_data.get("web", [])
    non_web = url_data.get("non_web", [])

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("icon", width=2)
    table.add_column("url", style="cyan")

    for url in links:
        table.add_row("•", url)

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]URL extraction[/bold]",
            subtitle=f"{len(links)} web · {len(non_web)} non-web",
            border_style="dim",
        )
    )

    if non_web:
        skipped = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        skipped.add_column("icon", width=2)
        skipped.add_column("url", style="dim")

        for url in non_web:
            skipped.add_row("•", url)

        console.print(
            Panel(
                skipped,
                title="[dim]Non-web URLs[/dim]",
                border_style="dim",
            )
        )


def print_vt_scan_links(vt_results):
    console.print()
    console.rule("[bold]VirusTotal scan — links[/bold]")

    total_malicious = 0
    total_suspicious = 0
    total_errors = 0
    total_no_detections = 0

    for url, result in vt_results.items():
        status = result.get("status", "unknown")
        stats = result.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total_malicious += malicious
        total_suspicious += suspicious

        if status != "ok":
            total_errors += 1
            verdict = Text("ERROR", style="bold yellow")
            border_style = "yellow"
        elif malicious > 0:
            verdict = Text("MALICIOUS DETECTION", style="bold red")
            border_style = "red"
        elif suspicious > 0:
            verdict = Text("SUSPICIOUS DETECTION", style="bold yellow")
            border_style = "yellow"
        else:
            total_no_detections += 1
            verdict = Text("NO DETECTION", style="bold green")
            border_style = "green"

        header = Text()
        header.append(url, style="cyan")
        header.append("  ")
        header.append(verdict)

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("label", style="dim", width=20)
        body.add_column("value")

        body.add_row("Status", status)

        if status == "ok":
            body.add_row(
                "Malicious",
                Text(str(malicious), style="red"),
            )
            body.add_row(
                "Suspicious",
                Text(str(suspicious), style="yellow"),
            )
            body.add_row("Undetected", str(stats.get("undetected", 0)))
            body.add_row(
                "Harmless",
                Text(str(stats.get("harmless", 0)), style="green"),
            )
            body.add_row(
                "Last scan",
                _format_date(result.get("last_analysis_date")),
            )
            body.add_row(
                "First seen",
                _format_date(result.get("first_submission_date")),
            )
        else:
            body.add_row(
                "Error",
                Text(result.get("error", status), style="red"),
            )

        console.print(
            Panel(
                body,
                title=header,
                border_style=border_style,
            )
        )

    console.print(
        f"[dim]Summary:[/dim] {len(vt_results)} scanned · "
        f"[red]{total_malicious} malicious detections[/red] · "
        f"[yellow]{total_suspicious} suspicious detections[/yellow] · "
        f"[green]{total_no_detections} with no detections[/green] · "
        f"[dim]{total_errors} errors[/dim]"
    )


def print_redirect_chain(results):
    console.print()
    console.rule("[bold]Redirect chain analysis[/bold]")

    redirected_count = 0
    excessive_count = 0
    error_count = 0
    skipped_count = 0

    for info in results:
        url = info.get("original_url", "Unknown URL")
        status = info.get("status", "unknown")

        if status == "error":
            error_count += 1
            console.print(
                Panel(
                    Text(
                        info.get("error", "Redirect lookup failed"),
                        style="red",
                    ),
                    title=Text(url, style="cyan"),
                    border_style="red",
                )
            )
            continue

        if status == "skipped":
            skipped_count += 1
            console.print(
                Panel(
                    Text(
                        info.get("error", "Redirect check skipped"),
                        style="dim",
                    ),
                    title=Text(url, style="cyan"),
                    border_style="dim",
                )
            )
            continue

        redirected = info.get("redirected", False)
        excessive = info.get("excessive_redirects", False)

        if redirected:
            redirected_count += 1

        if excessive:
            excessive_count += 1

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("label", style="dim", width=20)
        body.add_column("value")

        body.add_row(
            "Redirected",
            Text("Yes", style="yellow") if redirected else Text("No", style="green"),
        )

        body.add_row(
            "Redirect count",
            str(info.get("redirect_count", 0)),
        )

        if excessive:
            body.add_row(
                "Warning",
                Text(
                    "Maximum redirect limit exceeded",
                    style="bold red",
                ),
            )
            body.add_row(
                "Redirect chain",
                Text(
                    "Unavailable — redirect limit exceeded",
                    style="dim",
                ),
            )
        else:
            body.add_row(
                "Final URL",
                Text(info.get("final_url") or "N/A", style="cyan"),
            )

            body.add_row(
                "Status codes",
                str(info.get("status_codes", [])),
            )

            chain = info.get("redirect_chain", [])

            if chain:
                chain_text = Text()

                for i, step in enumerate(chain):
                    prefix = "└── " if i == len(chain) - 1 else "├── "
                    chain_text.append(f"{prefix}{step}\n", style="dim cyan")

                body.add_row("Chain", chain_text)

        console.print(
            Panel(
                body,
                title=Text(url, style="cyan"),
                border_style=(
                    "red" if excessive else "yellow" if redirected else "green"
                ),
            )
        )

    console.print(
        f"[dim]Summary:[/dim] {len(results)} analyzed · "
        f"[yellow]{redirected_count} redirected[/yellow] · "
        f"[red]{excessive_count} excessive redirects[/red] · "
        f"[red]{error_count} errors[/red] · "
        f"[dim]{skipped_count} skipped[/dim]"
    )


def print_link_heuristics(results: list) -> None:
    console.print()
    console.rule("[bold]Link heuristics analysis[/bold]")

    def _classify(result: dict) -> tuple:
        status = result.get("status", "unknown")
        flagged = bool(result.get("aggregated_flags"))
        return (
            flagged,
            status == "partial",
            status == "error",
            status == "skipped",
        )

    sorted_results = sorted(results, key=_classify, reverse=True)

    flagged_urls = 0
    partial_urls = 0
    error_urls = 0
    skipped_urls = 0
    no_signal_urls = 0

    heuristic_items = [
        ("IP-based URL", "ip_based"),
        ("Suspicious TLD", "suspicious_tld"),
        ("Embedded TLD", "embedded_tld"),
        ("Shortened URL", "shortened_url"),
        ("Abusable platform", "abusable_platform"),
        ("High entropy", "domain_entropy"),
    ]

    def add_issue_rows(table: Table, result: dict) -> None:
        details = result.get("details") or {}
        status = result.get("status", "unknown")

        if status == "error":
            table.add_row(
                "Error", Text(str(details.get("error", "Lookup failed")), style="red")
            )
        elif status == "skipped":
            missing = details.get("missing", "Unavailable")
            table.add_row("Unavailable", Text(str(missing), style="yellow"))

    for idx, res in enumerate(sorted_results, 1):
        url = res.get("url", "N/A")
        display_url = url
        flags = res.get("aggregated_flags") or []
        status = res.get("status", "unknown")
        is_flagged = bool(flags)
        is_partial = status == "partial"
        is_error = status == "error"
        is_skipped = status == "skipped"

        
        flagged_urls += int(is_flagged)
        partial_urls += int(is_partial)
        error_urls += int(is_error)
        skipped_urls += int(is_skipped)
        no_signal_urls += int(not is_flagged and status == "ok")

        title = Text()
        title.append(f"{idx}. ", style="dim")
        title.append(display_url, style="cyan")
        title.append("  ")

        if is_flagged:
            title.append("SUSPICIOUS", style="bold red")
            border_style = "red"
        elif is_partial:
            title.append("PARTIAL", style="bold yellow")
            border_style = "yellow"
        elif is_error:
            title.append("ERROR", style="bold red")
            border_style = "red"
        elif is_skipped:
            title.append("SKIPPED", style="dim")
            border_style = "dim"
        else:
            title.append("NO FLAGS", style="bold green")
            border_style = "green"

        sections = []

        
        parsed = res.get("parsed") or {}
        if parsed:
            parsed_table = Table(
                box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True
            )
            parsed_table.add_column("Field", style="dim", width=18, no_wrap=True)
            parsed_table.add_column("Value", overflow="fold")

            for label, key in (
                ("Scheme", "scheme"),
                ("Hostname", "hostname"),
                ("Registered domain", "registered_domain"),
                ("Domain", "domain"),
                ("Subdomain", "subdomain"),
                ("Suffix", "suffix"),
                ("Path", "path"),
            ):
                value = parsed.get(key)
                if value not in (None, ""):
                    parsed_table.add_row(label, str(value))

            query = parsed.get("query") or []
            if query:
                from urllib.parse import urlsplit

                raw_query = urlsplit(url).query
                if raw_query:
                    parsed_table.add_row("Query", Text(raw_query, style="cyan"))

            sections.append(
                Panel(parsed_table, title="[bold]Parsed URL[/bold]", border_style="dim")
            )

        
        checks = res.get("checks") or {}   
        heuristic_table = Table(
            box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True
        )
        heuristic_table.add_column("Result", width=3, no_wrap=True)
        heuristic_table.add_column("Heuristic", overflow="fold")

        for label, key in heuristic_items:
            item = checks.get(key)
            if not item:
                heuristic_table.add_row(
                    Text("–", style="dim"), Text(label, style="dim")
                )
                continue

            item_status = item.get("status", "unknown")
            heuristic_table.add_row(
                _heuristic_icon(item),
                Text(
                    label,
                    style=(
                        "red"
                        if item.get("flags")
                        else "dim" if item_status == "skipped" else "default"
                    ),
                ),
            )

        sections.append(
            Panel(
                heuristic_table,
                title="[bold]Local heuristics[/bold]",
                border_style="dim",
            )
        )

        enrichment = res.get("enrichment") or {}
        enrichment_sections = []

        for name, label, fields in (
            (
                "virustotal",
                "VirusTotal",
                (
                    ("Malicious", "malicious"),
                    ("Suspicious", "suspicious"),
                    ("Undetected", "undetected"),
                    ("Harmless", "harmless"),
                    ("Last scan", "last_analysis_date"),
                    ("First seen", "first_submission_date"),
                ),
            ),
            (
                "domain_age",
                "Domain age",
                (
                    ("Age (days)", "age_days"),
                    ("Expiry (days)", "expiry_days"),
                    ("Registrar", "registrar"),
                    ("Created", "created_at"),
                    ("Expires", "expires_at"),
                ),
            ),
            (
                "certificate",
                "Certificate",
                (
                    ("Issuer", "issuer"),
                    ("Subject", "subject"),
                    ("Valid from", "valid_from"),
                    ("Valid to", "valid_to"),
                    ("Days issued", "days_since_issued"),
                    ("Days to expiry", "days_until_expiry"),
                ),
            ),
            (
                "redirect_chain",
                "Redirect chain",
                (
                    ("Redirect count", "redirect_count"),
                    ("Final URL", "final_url"),
                    ("Final status", "final_status"),
                ),
            ),
        ):
            item = enrichment.get(name)
            if not item:
                continue

            item_status = item.get("status", "unknown")
            details = item.get("details") or {}
            table = Table(
                box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True
            )
            table.add_column("Field", style="dim", width=18, no_wrap=True)
            table.add_column("Value", overflow="fold")
            status_style = (
                "green"
                if item_status == "ok"
                else "yellow" if item_status == "skipped" else "red"
            )
            table.add_row("Status", Text(item_status.upper(), style=status_style))

            for field_label, key in fields:
                value = details.get(key)
                if value is None or value == "":
                    continue
                if key.endswith("_date") or key in (
                    "created_at",
                    "expires_at",
                    "valid_from",
                    "valid_to",
                ):
                    value = _format_date(value)
                if key == "expiry_days" and isinstance(value, (int, float)):
                    if value < 0:
                        field_label = "Expired (days)"
                        value = abs(value)
                table.add_row(
                    field_label,
                    Text(
                        str(value),
                        style=(
                            "cyan"
                            if key in ("final_url", "issuer", "subject")
                            else "default"
                        ),
                    ),
                )

            if name == "redirect_chain":
                reasons = item.get("reasons") or []
                if "excessive_redirects" in reasons:
                    table.add_row(
                        "Warning",
                        Text(
                            "Redirect limit exceeded; chain unavailable",
                            style="bold red",
                        ),
                    )
                else:
                    chain = details.get("redirect_chain") or []
                    if chain:
                        chain_text = Text()
                        for chain_idx, step in enumerate(chain):
                            prefix = "└── " if chain_idx == len(chain) - 1 else "├── "
                            chain_text.append(f"{prefix}{step}\n", style="cyan")
                        table.add_row("Chain", chain_text)

            add_issue_rows(table, item)
            enrichment_sections.append(
                Panel(table, title=f"[bold]{label}[/bold]", border_style="dim")
            )

        if enrichment_sections:
            sections.append(
                Panel(
                    Group(*enrichment_sections),
                    title="[bold]Enrichment[/bold]",
                    border_style="blue",
                )
            )

        if flags:
            flag_table = Table(
                box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True
            )
            flag_table.add_column("Signal", style="bold red", overflow="fold")
            for flag in flags:
                flag_table.add_row(str(flag))
            sections.append(
                Panel(
                    flag_table,
                    title="[bold red]Detected signals[/bold red]",
                    border_style="red",
                )
            )

        issues = []
        for section_name, section_results in (
            ("check", checks),
            ("enrichment", enrichment),
        ):
            for check_name, item in section_results.items():
                item_status = item.get("status")
                if item_status == "error":
                    message = (item.get("details") or {}).get("error", "Lookup failed")
                    issues.append(f"{section_name}.{check_name}: {message}")
                elif item_status == "skipped":
                    missing = (item.get("details") or {}).get("missing", "Unavailable")
                    issues.append(f"{section_name}.{check_name}: skipped ({missing})")

        if issues or is_partial or is_error or is_skipped:
            if not issues:
                issues.append("The URL could not be fully analyzed.")
            issue_text = Text(
                "\n".join(issues), style="yellow" if not is_error else "red"
            )
            sections.append(
                Panel(
                    issue_text,
                    title="[bold yellow]Analysis limitations[/bold yellow]",
                    border_style="yellow",
                )
            )

        if not sections:
            sections.append(Text("No analysis details available.", style="dim"))

       
        console.print(
            Panel(
                Group(*sections), title=title, border_style=border_style, padding=(1, 2)
            )
        )

    console.print()
    console.print(
        f"[dim]Summary:[/dim] {len(results)} URL(s) · "
        f"[red]{flagged_urls} suspicious[/red] · "
        f"[yellow]{partial_urls} partial[/yellow] · "
        f"[red]{error_urls} errors[/red] · "
        f"[dim]{skipped_urls} skipped[/dim] · "
        f"[green]{no_signal_urls} with no flags[/green]"
    )
    console.print()
