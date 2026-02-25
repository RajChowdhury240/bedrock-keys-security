"""Click-based output helpers replacing the Colors class"""

import click
from typing import Dict


def info(msg: str) -> None:
    click.echo(click.style(f"[INFO] {msg}", fg="cyan"))


def success(msg: str) -> None:
    click.echo(click.style(f"[SUCCESS] {msg}", fg="green"))


def warning(msg: str) -> None:
    click.echo(click.style(f"[WARNING] {msg}", fg="yellow"))


def error(msg: str) -> None:
    click.echo(click.style(f"[ERROR] {msg}", fg="red"), err=True)


def high_risk(msg: str) -> None:
    click.echo(click.style(f"[HIGH RISK] {msg}", fg="red"))


def bold(text: str) -> str:
    return click.style(text, bold=True)


def red(text: str) -> str:
    return click.style(text, fg="red")


def green(text: str) -> str:
    return click.style(text, fg="green")


def yellow(text: str) -> str:
    return click.style(text, fg="yellow")


def cyan(text: str) -> str:
    return click.style(text, fg="cyan")


def style_status(status: str) -> str:
    if status == "ESCALATED":
        return click.style(f"{status}!", fg="red")
    elif status == "ACTIVE":
        return click.style(status, fg="green")
    else:
        return click.style(status, fg="yellow")


def format_decode_table_output(result: Dict) -> str:
    if "error" in result:
        return f"\n{red('[ERROR] ' + result['error'])}\n"

    lines = []
    lines.append(f"\n{bold('─' * 60)}")
    lines.append(f"{bold(cyan('  Bedrock API Key Analysis'))}")
    lines.append(f"{bold('─' * 60)}")

    key_type = result.get("type", "Unknown")
    type_label = green("Long-term (ABSK)") if key_type == "long-term" else yellow("Short-term")
    lines.append(f"  Type: {type_label}")

    if key_type == "long-term":
        lines.append(f"  IAM Username: {cyan(result.get('username', 'N/A'))}")
        lines.append(f"  AWS Account ID: {cyan(result.get('account_id', 'N/A'))}")
        lines.append(f"  Secret Preview: {result.get('secret_preview', 'N/A')}")
        lines.append(f"  Format: {result.get('format', 'N/A')}")

    elif key_type == "short-term":
        lines.append(f"  Action: {result.get('action', 'N/A')}")
        lines.append(f"  Region: {cyan(result.get('region', 'N/A'))}")
        lines.append(f"  AWS Account ID: {cyan(result.get('account_id', 'N/A'))}")
        lines.append(f"  Expires In: {result.get('expires_in_seconds', 'N/A')} seconds")
        lines.append(f"  Date: {result.get('date', 'N/A')}")
        lines.append(f"  Format: {result.get('format', 'N/A')}")

    if "security_notes" in result and result["security_notes"]:
        lines.append(f"\n  {bold(yellow('Security Notes:'))}")
        for note in result["security_notes"]:
            lines.append(f"  {yellow('  • ' + note)}")

    lines.append(f"{bold('─' * 60)}\n")

    return "\n".join(lines)
