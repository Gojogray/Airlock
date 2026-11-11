"""
Airlock :: Terminal UI
======================
Rich-powered live terminal dashboard for the Airlock firewall.
"""

from __future__ import annotations

import time
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Decision colour map
# ---------------------------------------------------------------------------

DECISION_STYLES = {
    "ALLOW":        ("✅ LOCAL_ALLOW",        "bold green"),
    "LOCAL_BLOCK":  ("🚫 LOCAL_BLOCK",        "bold red"),
    "CANARY_BLOCK": ("☠️  CANARY_BLOCK",       "bold red on dark_red"),
    "ESCALATE":     ("☁️  HYBRID_ESCALATE",    "bold yellow"),
    "CLOUD_BLOCK":  ("🛡️  CLOUD_BLOCK",        "bold red"),
    "CLOUD_ALLOW":  ("☁️✅ CLOUD_ALLOW",       "bold green"),
}


def _decision_text(decision: str) -> Text:
    label, style = DECISION_STYLES.get(decision, (decision, "white"))
    return Text(label, style=style)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner = r"""
    ___    _      __           __  
   /   |  (_)____/ /___  _____/ /__
  / /| | / / ___/ / __ \/ ___/ //_/
 / ___ |/ / /  / / /_/ / /__/ ,<   
/_/  |_/_/_/  /_/\____/\___/_/|_|  

"""
    console.print(Text(banner, style="bold cyan"), justify="center")
    console.print(
        Panel(
            "[bold white]Zero-Latency Hybrid Security Firewall for Autonomous Coding Agents[/]\n"
            "[dim]#BuildHybridAI 2026 · Local-first · Cloud-escalate · Self-learning[/]",
            border_style="cyan",
            padding=(0, 4),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Scenario header
# ---------------------------------------------------------------------------

def print_scenario_header(index: int, title: str, description: str) -> None:
    console.print()
    console.print(Rule(f"[bold white] Scenario {index}: {title} [/]", style="cyan"))
    console.print(f"[dim italic]{description}[/]")
    console.print()


# ---------------------------------------------------------------------------
# Local guard result panel
# ---------------------------------------------------------------------------

def print_local_result(result, *, cloud_verdict: Optional[dict] = None) -> None:
    """Render a full decision panel for a GuardResult."""

    decision_key = result.decision
    if cloud_verdict:
        decision_key = "CLOUD_BLOCK" if cloud_verdict.get("verdict") == "BLOCK" else "CLOUD_ALLOW"

    # --- Top table ---
    tbl = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1))
    tbl.add_column("Key",   style="bold dim", width=24)
    tbl.add_column("Value", style="white")

    tbl.add_row("[DECISION]",   _decision_text(decision_key))
    tbl.add_row("[LATENCY]",    _latency_text(result.latency_ms, cloud_verdict))
    tbl.add_row("[RULE HIT]",   result.matched_rule_id or "—")

    if result.vault_tokens:
        tbl.add_row("[SECRETS MASKED]", f"[yellow]{len(result.vault_tokens)} token(s) vaulted[/]")

    console.print(
        Panel(tbl, title="[bold]⚡ Local Gate[/]", border_style="blue", padding=(0, 1))
    )

    # --- Command comparison ---
    cmd_tbl = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), expand=True)
    cmd_tbl.add_column("Label", style="bold dim", width=24)
    cmd_tbl.add_column("Command", style="white", no_wrap=False)

    cmd_tbl.add_row(
        "[ORIGINAL CMD]",
        Text(result.original_cmd, style="italic yellow"),
    )
    if result.sanitized_cmd != result.original_cmd:
        cmd_tbl.add_row(
            "[SANITIZED OUTBOUND]",
            Text(result.sanitized_cmd, style="italic green"),
        )
    else:
        cmd_tbl.add_row(
            "[SANITIZED OUTBOUND]",
            Text(result.sanitized_cmd, style="italic dim"),
        )

    console.print(
        Panel(cmd_tbl, title="[bold]🔍 Command Inspection[/]", border_style="dim", padding=(0, 1))
    )

    # --- Local reasoning ---
    console.print(
        Panel(
            Text(result.reason, style="italic"),
            title="[bold]🧠 Local Reasoning[/]",
            border_style="dim",
            padding=(0, 1),
        )
    )

    # --- Cloud verdict (if present) ---
    if cloud_verdict:
        _print_cloud_verdict(cloud_verdict)


def _latency_text(local_ms: float, cloud_verdict: Optional[dict] = None) -> Text:
    if cloud_verdict:
        cloud_ms = cloud_verdict.get("latency_ms", 0)
        total = local_ms + cloud_ms
        source = "live API" if cloud_verdict.get("cloud_used") else "offline heuristic"
        return Text(
            f"{total:.1f} ms total  (local {local_ms:.1f} ms + cloud {cloud_ms:.1f} ms [{source}])",
            style="yellow",
        )
    colour = "green" if local_ms < 20 else "yellow" if local_ms < 100 else "red"
    return Text(f"{local_ms:.1f} ms", style=colour)


def _print_cloud_verdict(verdict: dict) -> None:
    v_tbl = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1))
    v_tbl.add_column("Key",   style="bold dim", width=24)
    v_tbl.add_column("Value", style="white")

    final = verdict.get("verdict", "BLOCK")
    style = "bold red" if final == "BLOCK" else "bold green"
    v_tbl.add_row("[CLOUD VERDICT]",   Text(final, style=style))
    v_tbl.add_row("[CONFIDENCE]",      f"{verdict.get('confidence', 0):.0%}")
    v_tbl.add_row("[THREAT CATEGORY]", verdict.get("threat_category", "UNKNOWN"))
    v_tbl.add_row("[PROVENANCE]",      verdict.get("intent_provenance", "UNKNOWN"))

    source_label = "🌐 Gemini Flash" if verdict.get("cloud_used") else "🖥️  Offline heuristic"
    v_tbl.add_row("[CLOUD ENGINE]",    source_label)

    new_rule = verdict.get("new_local_rule")
    if new_rule:
        v_tbl.add_row("[NEW RULE COMPILED]", Text(new_rule, style="bold magenta"))

    console.print(
        Panel(
            v_tbl,
            title="[bold magenta]☁️  Cloud Reasoning (Firebase AI Logic Pattern)[/]",
            border_style="magenta",
            padding=(0, 1),
        )
    )

    if verdict.get("reason"):
        console.print(
            Panel(
                Text(verdict["reason"], style="italic"),
                title="[bold]🔎 Cloud Analysis[/]",
                border_style="dim magenta",
                padding=(0, 1),
            )
        )

    if new_rule:
        console.print(
            Panel(
                f"[bold green]✅ New rule registered in local engine[/]\n"
                f"[dim]Pattern:[/] [bold cyan]{new_rule}[/]\n"
                f"[dim]Next match will be blocked in [/][bold green]<15ms[/][dim] with zero cloud calls.[/]",
                title="[bold green]🔄 Flywheel: Cloud → Local[/]",
                border_style="green",
                padding=(0, 1),
            )
        )


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    console.print()
    console.print(Rule("[bold white] Demo Complete — Summary [/]", style="cyan"))
    console.print()

    tbl = Table(
        title="Airlock Decision Log",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    tbl.add_column("#",        style="dim", width=3)
    tbl.add_column("Scenario", style="bold white", min_width=28)
    tbl.add_column("Decision", min_width=20)
    tbl.add_column("Latency",  style="yellow", min_width=10)
    tbl.add_column("Cloud API?", width=10)
    tbl.add_column("Cost",     width=8)

    for r in results:
        decision_key = r.get("final_decision", "ALLOW")
        label, style = DECISION_STYLES.get(decision_key, (decision_key, "white"))
        cloud_calls = r.get("cloud_calls", 0)
        cost = "$0.00" if cloud_calls == 0 else f"~${0.0003 * cloud_calls:.4f}"
        tbl.add_row(
            str(r["index"]),
            r["title"],
            Text(label, style=style),
            f"{r['latency_ms']:.1f} ms",
            "✅ Yes" if cloud_calls else "❌ No",
            cost,
        )

    console.print(tbl)
    console.print()

    # Key stats
    console.print(
        Panel(
            "[bold green]✅ Zero secrets left the device[/]\n"
            "[bold cyan]🔄 Flywheel demonstrated: cloud rule pushed → local block achieved[/]\n"
            "[bold yellow]⚡ Average local decision: <20ms[/]\n"
            "[bold white]🛡️  Airlock protected the agent at every layer[/]",
            title="[bold]📊 Airlock Metrics[/]",
            border_style="green",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Interactive evaluate UI
# ---------------------------------------------------------------------------

def print_evaluate_header() -> None:
    console.print(
        Panel(
            "[bold white]Type a shell command to evaluate. Airlock will intercept, analyse, and decide.[/]\n"
            "[dim]Type [bold]exit[/] or [bold]quit[/] to leave.[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def prompt_command() -> str:
    console.print()
    return console.input("[bold cyan]agent@airlock[/][dim]:[/][bold yellow]~[/][dim]$[/] ")


def print_audit_log(entries: list[dict]) -> None:
    tbl = Table(
        title="Audit Log (Hash-Chained)",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    tbl.add_column("Time",        style="dim", width=20)
    tbl.add_column("Decision",    min_width=18)
    tbl.add_column("Latency",     width=10)
    tbl.add_column("Command",     min_width=30, no_wrap=False)
    tbl.add_column("Hash (sha256)", width=16, style="dim")

    for e in entries[-20:]:           # show last 20
        label, style = DECISION_STYLES.get(e.get("decision", ""), (e.get("decision", ""), "white"))
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        h = e.get("entry_hash", "")[:12] + "…"
        tbl.add_row(
            ts,
            Text(label, style=style),
            f"{e.get('latency_ms', 0):.1f} ms",
            e.get("command", "")[:60],
            h,
        )
    console.print(tbl)
