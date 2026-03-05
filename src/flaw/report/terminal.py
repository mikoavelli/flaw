"""Rich terminal output for scan and lint reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from flaw.models import DockerfileIssue, EnrichedVulnerability, ScanReport

stderr = Console(stderr=True)

_SEV_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def _severity_style(severity: str) -> str:
    """Return Rich style string for a severity level."""
    return _SEV_COLORS.get(severity.upper(), "white")


def print_scan_report(
    report: ScanReport,
    *,
    top: int | None = None,
) -> None:
    """Render a full scan report to stderr."""
    header = (
        f"[bold]Flaw[/bold] — {report.image}\n"
        f"Scanned in {report.duration_seconds:.1f}s"
        f" | {report.summary.total} CVEs"
        f" | Max Risk: {report.summary.max_risk_score}"
    )
    stderr.print(Panel(header, expand=False))

    if report.summary.critical > 0:
        stderr.print(
            f"\n [bold red]⚠  WARNING: {report.summary.critical}"
            f" CRITICAL vulnerabilities detected![/bold red]"
        )

    vulns = report.vulnerabilities
    if top is not None:
        vulns = vulns[:top]

    if vulns:
        _print_vuln_table(vulns)
    else:
        stderr.print("\n [green]No vulnerabilities found.[/green]\n")

    if report.dockerfile_issues is not None:
        _print_dockerfile_issues(report.dockerfile_issues)

    _print_summary(report)


def _print_vuln_table(vulns: list[EnrichedVulnerability]) -> None:
    """Render the vulnerability table."""
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("#", style="dim", width=4)
    table.add_column("CVE", min_width=16)
    table.add_column("Pkg", min_width=10)
    table.add_column("CVSS", justify="right", width=5)
    table.add_column("EPSS", justify="right", width=7)
    table.add_column("KEV", justify="center", width=4)
    table.add_column("Context", min_width=12)
    table.add_column("Risk", justify="right", width=6)

    for i, v in enumerate(vulns, 1):
        is_suppressed = v.vex_status in ("not_affected", "fixed")
        row_style = "dim" if is_suppressed else ""
        sev_style = "dim" if is_suppressed else _severity_style(v.severity)

        kev_marker = "[red]●[/red]" if v.in_kev and not is_suppressed else ""

        badges = []
        if is_suppressed:
            if v.vex_justification == "vulnerable_code_not_in_execute_path":
                badges.append("[bold green]Not Reachable[/bold green]")
            elif v.vex_status == "fixed":
                badges.append("[bold green]Fixed[/bold green]")
            else:
                badges.append("[bold green]VEX Suppressed[/bold green]")
        else:
            refs = [r.lower() for r in v.references]
            purl = v.purl.lower()

            if any("exploit-db.com" in r for r in refs):
                badges.append("[bold red]Exploit-DB[/bold red]")
            elif any("packetstorm" in r for r in refs):
                badges.append("[bold red]PStorm[/bold red]")
            elif any("github.com" in r and ("poc" in r or "exploit" in r) for r in refs):
                badges.append("[yellow]GitHub PoC[/yellow]")

            if "npm" in purl:
                badges.append("[blue]npm[/blue]")
            elif "pypi" in purl:
                badges.append("[blue]pypi[/blue]")
            elif "golang" in purl:
                badges.append("[cyan]go[/cyan]")
            elif "maven" in purl:
                badges.append("[magenta]java[/magenta]")
            elif "rust" in purl or "cargo" in purl:
                badges.append("[color(208)]rust[/color(208)]")

        ctx_str = " ".join(badges)

        table.add_row(
            str(i),
            f"[{sev_style}]{v.cve_id}[/{sev_style}]",
            v.pkg_name,
            f"{v.cvss:.1f}",
            f"{v.epss:.4f}" if not is_suppressed else "-",
            kev_marker,
            ctx_str,
            f"[bold]{v.risk_score:.1f}[/bold]",
            style=row_style,
        )

    stderr.print()
    stderr.print(table)
    stderr.print()


def _print_dockerfile_issues(issues: list[DockerfileIssue]) -> None:
    """Render Dockerfile issues."""
    stderr.print(f"\n[bold]Dockerfile Issues ({len(issues)}):[/bold]")
    for issue in issues:
        style = _severity_style(issue.severity)
        line_info = f" (line {issue.line})" if issue.line else ""
        stderr.print(
            f"   [{style}]{issue.severity:<6}[/{style}]  {issue.id}  {issue.description}{line_info}"
        )
    stderr.print()


def _print_summary(report: ScanReport) -> None:
    """Render the summary block."""
    s = report.summary
    stderr.print(" [bold]Summary:[/bold]")
    stderr.print(f"   Critical: {s.critical}  High: {s.high}  Medium: {s.medium}  Low: {s.low}")
    if s.suppressed > 0:
        stderr.print(f"   [bold green]Suppressed by VEX/Reachability: {s.suppressed}[/bold green]")
    if s.kev_count > 0 or s.exploit_count > 0:
        stderr.print(f"   In CISA KEV: {s.kev_count}  Has public exploit: {s.exploit_count}")
    stderr.print()


def print_lint_report(issues: list[DockerfileIssue], path: str) -> None:
    """Render a Dockerfile lint report to stderr."""
    header = f"[bold]Flaw Lint[/bold] — {path}\n{len(issues)} issues found"
    stderr.print(Panel(header, expand=False))

    if issues:
        _print_dockerfile_issues(issues)
    else:
        stderr.print("\n [green]No issues found.[/green]\n")
