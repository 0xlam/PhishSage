from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_warning(message: str) -> None:
    console.print(Panel(
        Text(message, style="yellow"),
        border_style="yellow",
        title="[yellow]Warning[/yellow]",
    ))


def print_error(message: str) -> None:
    console.print(Panel(
        Text(message, style="red"),
        border_style="red",
        title="[red]Error[/red]",
    ))
