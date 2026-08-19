from __future__ import annotations

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)


def run_console(scope_path: str = "scope.yaml", engagement_id: str = "demo") -> int:
    """Render an interactive rich terminal console for RedStrike."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3),
    )
    layout["main"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1),
    )

    # Header
    layout["header"].update(
        Panel(
            Text("REDSTRIKE -- AGENTIC ACTIVE DIRECTORY CAMPAIGN CONSOLE", style="bold red", justify="center"),
            style="red",
        )
    )

    # Left: Campaign Execution Table
    campaign_table = Table(title="Active Campaign Kill-Chain (DAG Execution)", expand=True)
    campaign_table.add_column("Node ID", style="cyan", no_wrap=True)
    campaign_table.add_column("Intent", style="white")
    campaign_table.add_column("Target", style="magenta")
    campaign_table.add_column("OPSEC", style="green")
    campaign_table.add_column("Status", style="bold green")

    campaign_table.add_row("P1-RECON", "enumerate_domain_users", "dc01.cadre.local", "STEALTH", "[OK] COMPLETE")
    campaign_table.add_row("P1-DELEGATION", "find_delegation", "dc01.cadre.local", "STEALTH", "[OK] COMPLETE")
    campaign_table.add_row("P2-ADCS", "certipy_find", "dc01.cadre.local", "STEALTH", "[OK] COMPLETE")
    campaign_table.add_row("P3-TGT", "request_tgt", "dc01.cadre.local", "BALANCED", "[..] PENDING")
    campaign_table.add_row("P4-DA-JUMP", "certipy_req (ESC1)", "dc01.cadre.local", "BALANCED", "[!!] HITL GATED")

    layout["left"].update(Panel(campaign_table, title="Execution Engine", style="dim"))

    # Right: Credential Ledger
    creds_table = Table(title="Credential Ledger (SSoT)", expand=True)
    creds_table.add_column("Account", style="yellow")
    creds_table.add_column("Privilege", style="red")
    creds_table.add_column("Type", style="cyan")

    creds_table.add_row("analyst_t1", "Low-Priv", "Password")
    creds_table.add_row("svc_backup", "Service", "TGT (RC4)")
    creds_table.add_row("Administrator", "Domain Admin", "PKINIT TGT")

    layout["right"].update(Panel(creds_table, title="Discovered Identities", style="dim"))

    # Footer: Controls
    layout["footer"].update(
        Panel(
            Text("Controls: [A] Approve Pending Gate  |  [R] Reject Gate  |  [C] Cleanup & Teardown  |  [Q] Exit", style="bold yellow", justify="center"),
            style="yellow",
        )
    )

    console.print(layout)
    console.print("[dim green]Console initialized successfully. Ready for agent intent streams.[/dim green]")
    return 0
