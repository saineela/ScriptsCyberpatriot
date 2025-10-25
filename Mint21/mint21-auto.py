#!/usr/bin/env python3
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

def main():
    console.print(Panel("[bold cyan]CyberPatriot Dummy GUI[/bold cyan]", expand=False))
    console.print("This is a test interface to confirm everything works.")
    if Confirm.ask("Do you want to run a test command?"):
        console.print("[yellow]Running dummy command...[/yellow]")
        console.print("[green]Success! Everything is working.[/green]")
    else:
        console.print("[red]Cancelled by user.[/red]")

if __name__ == "__main__":
    main()
