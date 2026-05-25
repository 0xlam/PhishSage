from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


def _status(val) -> Text:
    if val is True:
        return Text("pass", style="bold green")
    if val is False:
        return Text("fail", style="bold red")
    return Text("unknown", style="dim")


def print_header_heuristics(data):    
    console.print()
    console.rule("[bold]Header heuristics analysis[/bold]")

    meta = data.get("meta", {})
    mail_id = meta.get("mail_id", "N/A")
    console.print(f"[dim]Mail ID:[/dim] {mail_id}\n")

    alerts = data.get("alerts", [])
    results = data.get("results", {})

    # --- Authentication ---
    auth = results.get("auth")
    if auth:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("proto", style="dim", width=6)
        table.add_column("status", width=10)
        table.add_column("value", style="dim")
        for proto in ("spf", "dkim", "dmarc"):
            entry = auth.get(proto, {})
            passed = entry.get("passed")
            value = entry.get("value") or "—"
            table.add_row(proto.upper(), _status(passed), value)
        console.print(Panel(table, title="[dim]authentication[/dim]", border_style="dim"))

    # --- Address alignment ---
    alignment = results.get("address_alignment")
    if alignment:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("check", style="dim")
        table.add_column("status", width=10)
        from_vs_reply = alignment.get("from_vs_reply")
        from_vs_return = alignment.get("from_vs_return")
        if from_vs_reply is not None:
            table.add_row("From vs Reply-To", _status(from_vs_reply))
        if from_vs_return is not None:
            table.add_row("From vs Return-Path", _status(from_vs_return))
        console.print(Panel(table, title="[dim]address alignment[/dim]", border_style="dim"))

    # --- Message-ID domain ---
    msgid = results.get("message_id")
    if msgid:
        match = msgid.get("msgid_vs_from")
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("check", style="dim")
        table.add_column("status", width=10)
        if match is not None:
            table.add_row("Message-ID domain matches From domain", _status(match))
        console.print(Panel(table, title="[dim]message-id domain[/dim]", border_style="dim"))

    # --- Domain consistency ---
    domain_cons = results.get("domain_consistency")
    if domain_cons:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("check", style="dim")
        table.add_column("status", width=10)
        from_vs_return = domain_cons.get("from_vs_return")
        from_vs_reply = domain_cons.get("from_vs_reply")
        if from_vs_return is not None:
            table.add_row("From vs Return-Path domain", _status(from_vs_return))
        if from_vs_reply is not None:
            table.add_row("From vs Reply-To domain", _status(from_vs_reply))
        console.print(Panel(table, title="[dim]domain consistency[/dim]", border_style="dim"))

    # --- MX records ---
    mx = results.get("mx")
    if mx:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("label", style="dim", width=16)
        table.add_column("value")
        has_mx = mx.get("has_mx", False)
        records = mx.get("records")
        error = mx.get("error")
        if error:
            table.add_row("Error", Text(error, style="red"))
        else:
            table.add_row("Has MX", _status(has_mx))
            if records:
                table.add_row("Records", ", ".join(records))
        console.print(Panel(table, title="[dim]MX records[/dim]", border_style="dim"))

    # --- Spamhaus DBL ---
    spamhaus = results.get("spamhaus")
    if spamhaus:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("domain", style="dim", width=14)
        table.add_column("status", width=12)
        table.add_column("detail", style="dim")
        for label, entry in spamhaus.items():
            error = entry.get("error")
            listed = entry.get("listed", False)
            if error:
                table.add_row(
                    label.replace("_", " "),
                    Text("error", style="red"),
                    error,
                )
            else:
                table.add_row(
                    label.replace("_", " "),
                    Text("listed", style="bold red") if listed else Text("clean", style="bold green"),
                    "",
                )
        console.print(Panel(table, title="[dim]Spamhaus DBL[/dim]", border_style="dim"))

    # --- Domain age ---
    domain_age = results.get("domain_age")
    if domain_age:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("domain", style="dim", width=14)
        table.add_column("age", width=12)
        table.add_column("expiry", width=14)
        table.add_column("note", style="dim")
        for label, entry in domain_age.items():
            error = entry.get("error")
            age = entry.get("age_days")
            expiry = entry.get("expiry_days_left")
            if error:
                table.add_row(
                    label.replace("_", " "),
                    Text("error", style="red"),
                    "",
                    error,
                )
            else:
                age_text = Text(
                    f"{age} days" if age is not None else "—",
                    style="yellow" if age is not None and age < 180 else "default",
                )
                expiry_text = Text(
                    f"{expiry} days" if expiry is not None else "—",
                    style="yellow" if expiry is not None and expiry <= 30 else "default",
                )
                table.add_row(label.replace("_", " "), age_text, expiry_text, "")
        console.print(Panel(table, title="[dim]domain age[/dim]", border_style="dim"))

    # --- Alerts ---
    console.print()
    if alerts:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("type", style="yellow", width=32)
        table.add_column("message", style="dim")
        for alert in alerts:
            table.add_row(
                alert.get("type", "UNKNOWN"),
                alert.get("message", ""),
            )
        console.print(Panel(
            table,
            title=f"[yellow]alerts ({len(alerts)})[/yellow]",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            Text("No alerts", style="green"),
            title="[green]alerts[/green]",
            border_style="green",
        ))