from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

console = Console()


def _flag_icon(flagged: bool) -> Text:
    if flagged:
        return Text("✗", style="bold red")
    return Text("✓", style="bold green")


def _badge(text: str, style: str) -> Text:
    return Text(f" {text} ", style=style)


def _format_date(value) -> str:
    if not value:
        return "N/A"
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(value)

def print_warning(message: str) -> None:
    console.print(Panel(
        Text(message, style="yellow"),
        border_style="yellow",
    ))


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

    total_flagged = 0
    total_errors = 0

    for url, result in vt_results.items():
        flags = result.get("flags")
        reasons = result.get("reasons")
        meta = result.get("meta", {})
        status = meta.get("status", "unknown")

        if flags:
            total_flagged += 1
            verdict = Text("FLAGGED", style="bold red")
        else:
            verdict = Text("CLEAN", style="bold green")

        header = Text()
        header.append(url, style="cyan")
        header.append("  ")
        header.append(verdict)

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("label", style="dim", width=20)
        body.add_column("value")

        body.add_row("Status", status)

        if reasons:
            body.add_row("Reasons", Text(", ".join(reasons), style="red"))

        stats = meta.get("stats")
        if stats and isinstance(stats, dict):
            body.add_row("Malicious",  Text(str(stats.get("malicious", 0)),  style="red"))
            body.add_row("Suspicious", Text(str(stats.get("suspicious", 0)), style="yellow"))
            body.add_row("Undetected", str(stats.get("undetected", 0)))
            body.add_row("Harmless",   Text(str(stats.get("harmless", 0)),   style="green"))
            body.add_row("Last scan",  _format_date(meta.get("last_analysis_date")))
            body.add_row("First seen", _format_date(meta.get("first_submission_date")))
        else:
            if status == "exception":
                total_errors += 1
                body.add_row("Error", Text(meta.get("error", "unknown"), style="red"))
            else:
                body.add_row("Stats", Text("unavailable", style="dim"))

        console.print(
            Panel(
                body,
                title=header,
                border_style="red" if flags else "green",
            )
        )

    console.print(
        f"[dim]Summary:[/dim] {len(vt_results)} scanned · "
        f"[red]{total_flagged} flagged[/red] · "
        f"[yellow]{total_errors} errors[/yellow]"
    )

def print_redirect_chain(results):
    console.print()
    console.rule("[bold]Redirect chain analysis[/bold]")

    total = len(results)
    redirected_count = 0
    error_count = 0

    for info in results:
        if "error" in info:
            error_count += 1
            console.print(Panel(
                Text(info["error"], style="red"),
                title=Text(info["original_url"], style="cyan"),
                border_style="red",
            ))
            continue

        redirected = info.get("redirected", False)
        if redirected:
            redirected_count += 1

        body = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        body.add_column("label", style="dim", width=18)
        body.add_column("value")

        body.add_row(
            "Redirected",
            Text("Yes", style="yellow") if redirected else Text("No", style="green")
        )
        body.add_row("Count",        str(info.get("redirect_count", 0)))
        body.add_row("Final URL", Text(info.get("final_url") or "N/A", style="cyan"))
        body.add_row("Status codes", str(info.get("status_codes", [])))

        chain = info.get("redirect_chain", [])
        if chain:
            chain_text = Text()
            for i, step in enumerate(chain):
                prefix = "└── " if i == len(chain) - 1 else "├── "
                chain_text.append(f"{prefix}{step}\n", style="dim cyan")
            body.add_row("Chain", chain_text)

        console.print(Panel(
            body,
            title=Text(info["original_url"], style="cyan"),
            border_style="yellow" if redirected else "dim",
        ))

    console.print(
        f"[dim]Summary:[/dim] {total} analyzed · "
        f"[yellow]{redirected_count} redirected[/yellow] · "
        f"[red]{error_count} errors[/red]"
    )


def print_link_heuristics(results: list) -> None:
    console.print()
    console.rule("[bold]Link heuristics analysis[/bold]")

    total_urls = len(results)
    flagged_urls = 0

    sorted_results = sorted(
        results,
        key=lambda r: bool(r.get("aggregated_flags")),
        reverse=True,
    )


    for idx, res in enumerate(sorted_results, 1):
        url = res.get("url", "N/A")
        agg_flags = res.get("aggregated_flags", [])
        is_flagged = bool(agg_flags)

        if is_flagged:
            flagged_urls += 1

        # --- header ---
        title = Text()
        title.append(f"{idx}. ", style="dim")
        title.append(url, style="cyan")
        title.append("  ")
        if is_flagged:
            title.append("FLAGGED", style="bold red")
        else:
            title.append("CLEAN", style="bold green")

        panels = []

        # --- heuristics grid ---
        h_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        h_table.add_column("icon", width=2)
        h_table.add_column("label", style="dim")

        heuristics = res.get("heuristics", {})
        items = [
            ("IP-based URL",         "ip_based"),
            ("Suspicious TLD",       "suspicious_tld"),
            ("Excessive subdomains", "excessive_subdomains"),
            ("Shortened URL",        "shortened_url"),
            ("Numeric domain",       "numeric_domain"),
            ("Excessive path",       "excessive_path"),
            ("Abusable platform",    "abusable_platform"),
            ("High entropy",         "domain_entropy"),
        ]
        for label, key in items:
            h = heuristics.get(key, {})
            flagged = h.get("flags", False)
            reasons = h.get("reasons", [])
            suffix = f" ({', '.join(reasons)})" if flagged and reasons else ""
            h_table.add_row(
                _flag_icon(flagged),
                Text(f"{label}{suffix}", style="red" if flagged else "default"),
            )

        panels.append(Panel(h_table, title="[dim]heuristics[/dim]", border_style="dim"))

        # --- enrichment ---
        enrichment = res.get("enrichment", {})

        vt = enrichment.get("virustotal")
        if vt:
            meta = vt.get("meta", {})
            stats = meta.get("stats") or {}
            vt_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            vt_table.add_column("label", style="dim", width=14)
            vt_table.add_column("value")
            vt_table.add_row("Status",     meta.get("status", "unknown"))
            vt_table.add_row("Malicious",  Text(str(stats.get("malicious", 0)),  style="red"))
            vt_table.add_row("Suspicious", Text(str(stats.get("suspicious", 0)), style="yellow"))
            vt_table.add_row("Undetected", str(stats.get("undetected", 0)))
            vt_table.add_row("Harmless",   Text(str(stats.get("harmless", 0)),   style="green"))
            if vt.get("flags"):
                vt_table.add_row("Flags", Text(", ".join(vt.get("reasons", [])), style="red"))
            panels.append(Panel(vt_table, title="[dim]virustotal[/dim]", border_style="dim"))

        domain_age = enrichment.get("domain_age")
        if domain_age:
            meta = domain_age.get("meta", {})
            age_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            age_table.add_column("label", style="dim", width=14)
            age_table.add_column("value")
            error = meta.get("error")
            if error:
                age_table.add_row("Error", Text(error, style="red"))
            else:
                age = meta.get("age_days")
                expiry = meta.get("expiry_days")
                age_table.add_row(
                    "Age",
                    Text(f"{age} days", style="yellow" if age and age < 180 else "default")
                    if age is not None else Text("N/A", style="dim")
                )
                age_table.add_row(
                    "Expires in",
                    Text(f"{expiry} days", style="yellow" if expiry and expiry < 30 else "default")
                    if expiry is not None else Text("N/A", style="dim")
                )
                age_table.add_row("Registrar", str(meta.get("registrar") or "N/A"))
            if domain_age.get("flags"):
                age_table.add_row("Flags", Text(", ".join(domain_age.get("reasons", [])), style="red"))
            panels.append(Panel(age_table, title="[dim]domain age[/dim]", border_style="dim"))

        cert = enrichment.get("certificate")
        if cert:
            meta = cert.get("meta", {})
            cert_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            cert_table.add_column("label", style="dim", width=16)
            cert_table.add_column("value")
            error = meta.get("error")
            if error:
                cert_table.add_row("Error", Text(error, style="red"))
            else:
                for label, key in [
                    ("Issuer",            "issuer"),
                    ("Subject",           "subject"),
                    ("Valid from",        "valid_from"),
                    ("Valid to",          "valid_to"),
                    ("Days issued",       "days_since_issued"),
                    ("Days to expiry",    "days_until_expiry"),
                ]:
                    val = meta.get(key)
                    if val is not None:
                        cert_table.add_row(label, str(val))
            if cert.get("flags"):
                cert_table.add_row("Flags", Text(", ".join(cert.get("reasons", [])), style="red"))
            panels.append(Panel(cert_table, title="[dim]certificate[/dim]", border_style="dim"))

        redirect = enrichment.get("redirect_chain")
        if redirect:
            meta = redirect.get("meta", {})
            r_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            r_table.add_column("label", style="dim", width=14)
            r_table.add_column("value")
            error = meta.get("error")
            if error:
                r_table.add_row("Error", Text(error, style="red"))
            else:
                redirected = meta.get("redirected", False)
                count = meta.get("redirect_count", 0)
                r_table.add_row(
                    "Redirected",
                    Text("Yes", style="yellow") if redirected else Text("No", style="green")
                )
                r_table.add_row("Count",     str(count))
                r_table.add_row("Final URL", Text(str(meta.get("final_url", "N/A")), style="cyan"))
                chain = meta.get("redirect_chain", [])
                if chain:
                    chain_text = Text()
                    for i, step in enumerate(chain):
                        prefix = "└── " if i == len(chain) - 1 else "├── "
                        chain_text.append(f"{prefix}{step}\n", style="dim cyan")
                    r_table.add_row("Chain", chain_text)
            if redirect.get("flags"):
                r_table.add_row("Flags", Text(", ".join(redirect.get("reasons", [])), style="red"))
            panels.append(Panel(r_table, title="[dim]redirects[/dim]", border_style="dim"))

        # aggregated flags banner
        if agg_flags:
            flag_text = Text("  ".join(agg_flags), style="bold red")
            flags_panel = Panel(flag_text, title="[red]aggregated flags[/red]", border_style="red")
        else:
            flags_panel = Panel(Text("No flags", style="green"), title="[green]result[/green]", border_style="green")

        console.print(Panel(
            Columns(panels, equal=False, expand=True),
            title=title,
            subtitle=flags_panel.renderable if not is_flagged else None,
            border_style="red" if is_flagged else "green",
        ))

        if is_flagged:
            console.print(flags_panel)

    console.print()
    console.print(
        f"[dim]Summary:[/dim] {total_urls} URL(s) analyzed · "
        f"[red]{flagged_urls} flagged[/red] · "
        f"[green]{total_urls - flagged_urls} clean[/green]"
    )
    console.print()