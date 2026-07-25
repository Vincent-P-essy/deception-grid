"""The operator's view.

Five commands, and the shape of the output is an argument in itself. `report`
leads with the benign share rather than the event count, because a grid that
looks busy and a grid that is working are different things and the event count
cannot tell them apart.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .analyse import Report, analyse
from .event import EventLog, dump, load
from .intel import CONFIDENCE, CONFIDENCE_WHY, to_misp, to_stix
from .selftest import CLIENT_PROFILES, capture
from .server import Grid, run

DEFAULT_PORTS = {"ssh": 2222, "http": 8080, "s3": 8081}


def _console(width: int | None = None) -> Console:
    return Console(width=width, highlight=False)


def _plural(items) -> str:
    return "identity" if len(items) == 1 else "identities"


def _parse_benign(values: list[str] | None) -> dict[str, str]:
    """`--benign 10.20.30.=internal scanner`, repeatable."""
    out: dict[str, str] = {}
    for item in values or ():
        prefix, sep, reason = item.partition("=")
        if not sep or not prefix.strip():
            raise SystemExit(
                f"--benign expects PREFIX=REASON, got {item!r}. "
                "A source excused without a stated reason is one nobody can review."
            )
        out[prefix.strip()] = reason.strip()
    return out


def _parse_bindings(values: list[str] | None, host: str) -> dict[str, tuple[str, int]]:
    """`--listen ssh=2222`, repeatable; defaults to all three decoys."""
    if not values:
        return {name: (host, port) for name, port in DEFAULT_PORTS.items()}
    bindings: dict[str, tuple[str, int]] = {}
    for item in values:
        name, sep, port = item.partition("=")
        if not sep:
            name, port = item, str(DEFAULT_PORTS.get(item, 0))
        if name not in DEFAULT_PORTS:
            raise SystemExit(f"unknown decoy {name!r}; have {', '.join(DEFAULT_PORTS)}")
        bindings[name] = (host, int(port))
    return bindings


# -- run -----------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    console = _console()
    benign = _parse_benign(args.benign)
    bindings = _parse_bindings(args.listen, args.host)
    grid = Grid(log=EventLog(args.log), benign=benign, banner=args.banner)

    lines = [f"[bold]{name}[/bold] → {host}:{port}" for name, (host, port) in bindings.items()]
    lines.append("")
    lines.append(f"events → [cyan]{args.log}[/cyan]")
    if benign:
        for prefix, reason in benign.items():
            lines.append(f"benign  [green]{prefix}[/green] — {reason}")
    else:
        lines.append("[yellow]no benign sources declared — your own scanner will "
                     "look like an intrusion[/yellow]")
    console.print(Panel("\n".join(lines), title="decoys listening", border_style="cyan"))
    console.print("[dim]Ctrl-C to stop. Nothing a client sends is executed.[/dim]\n")

    try:
        asyncio.run(run(grid, bindings))
    except KeyboardInterrupt:
        console.print(f"\n[dim]stopped — {len(grid.log)} event(s) written[/dim]")
    return 0


# -- capture -------------------------------------------------------------------

def cmd_capture(args: argparse.Namespace) -> int:
    console = _console()
    events = capture()
    path = dump(events, args.output)
    console.print(f"[green]✓[/green] {len(events)} event(s) → [cyan]{path}[/cyan]")
    console.print(
        "[dim]Produced by starting the real listeners on ephemeral ports and "
        "connecting to them over real sockets.[/dim]"
    )
    return 0


# -- report --------------------------------------------------------------------

def _headline(report: Report) -> Panel:
    share = report.benign_share
    if share == 0:
        verdict, colour = "clean — every event is worth reading", "green"
    elif share < 0.25:
        verdict, colour = "acceptable — review the allowlisted sources", "yellow"
    else:
        verdict, colour = "the queue is being trained to be ignored", "red"

    body = Text()
    body.append(f"{share:.0%}", style=f"bold {colour}")
    body.append("  of events came from a known-benign source\n", style="dim")
    body.append(f"{verdict}\n\n", style=colour)
    linked = sum(1 for c in report.campaigns if c.is_linked)
    body.append(
        f"{len(report.hostile)} exportable {_plural(report.hostile)} · "
        f"{linked} campaign(s) · {len(report.contaminated)} withheld · "
        f"{len(report.sessions)} session(s) · {len(report.events)} event(s)",
        style="dim",
    )
    return Panel(body, title="benign share", border_style=colour)


def _actor_table(report: Report) -> Table:
    table = Table(title="identities", title_style="bold", header_style="bold cyan",
                  show_lines=False)
    table.add_column("identity", no_wrap=True, max_width=48)
    table.add_column("signal", no_wrap=True)
    table.add_column("conf", justify="right")
    table.add_column("addr", justify="right")
    table.add_column("svc", no_wrap=True)
    table.add_column("events", justify="right")
    table.add_column("export", no_wrap=True)

    for actor in report.actors:
        if actor.is_benign:
            style, disposition, confidence = "dim", "[dim]allowlisted[/dim]", ""
        elif actor.touches_benign:
            style, disposition, confidence = "yellow", "[yellow]withheld[/yellow]", ""
        else:
            style, disposition = "", "[green]yes[/green]"
            confidence = str(CONFIDENCE.get(actor.basis, 30))

        addresses = str(len(actor.addresses))
        if actor.multi_homed:
            addresses = f"[bold magenta]{addresses}[/bold magenta]"
        table.add_row(
            actor.label, actor.basis, confidence, addresses,
            ",".join(actor.services), str(actor.events), disposition,
            style=style,
        )
    return table


def _campaign_table(report: Report) -> Table | None:
    linked = [c for c in report.campaigns if c.is_linked]
    if not linked:
        return None
    table = Table(title="campaigns — identities that shared an address",
                  title_style="bold", header_style="bold cyan", show_lines=True)
    table.add_column("campaign")
    table.add_column("linked by", no_wrap=True)
    table.add_column("addr", justify="right")
    table.add_column("svc")
    table.add_column("events", justify="right")
    for campaign in linked:
        joins = "\n".join(f"{ip}  ({len(who)})" for ip, who in sorted(campaign.links.items()))
        table.add_row(campaign.label, joins, str(len(campaign.addresses)),
                      ",".join(campaign.services), str(campaign.events))
    return table


def _contamination_panel(report: Report) -> Panel | None:
    if not report.contaminated:
        return None
    body = Text()
    for actor in report.contaminated:
        hostile = [ip for ip in actor.addresses if ip not in actor.benign_addresses]
        body.append(f"{actor.label}\n", style="bold yellow")
        body.append(f"  matched by {actor.basis}, on both "
                    f"{', '.join(actor.benign_addresses)} (allowlisted) "
                    f"and {', '.join(hostile)}\n", style="dim")
    body.append(
        "\nWithheld from every export. Either the signal is not specific enough "
        "to be an identity, or something on the allowlist is doing what it was "
        "not allowlisted for. Both readings need a person.",
        style="yellow",
    )
    return Panel(body, title="contaminated identities", border_style="yellow")


def _probe_table(report: Report) -> Table:
    table = Table(title="what they were looking for", title_style="bold",
                  header_style="bold cyan")
    table.add_column("probe", no_wrap=True)
    table.add_column("hits", justify="right")
    table.add_column("meaning")
    from .web import PROBES
    meanings = {name: meaning for name, _, meaning in PROBES}
    for name, count in report.probes.most_common(10):
        table.add_row(name, str(count), meanings.get(name, ""))
    return table


def _fingerprint_table(report: Report) -> Table | None:
    rotating = {h: v for h, v in report.fingerprints.items() if len(v) > 1}
    if not rotating:
        return None
    table = Table(title="one client, more than one claimed identity",
                  title_style="bold", header_style="bold cyan")
    table.add_column("HASSH", no_wrap=True)
    table.add_column("version strings claimed")
    for fingerprint, versions in rotating.items():
        table.add_row(fingerprint, "\n".join(versions))
    return table


def render_report(report: Report, console: Console, *, quiet: bool = False) -> None:
    console.print(_headline(report))
    console.print()
    console.print(_actor_table(report))
    campaigns = _campaign_table(report)
    if campaigns is not None:
        console.print()
        console.print(campaigns)
        console.print(
            "[dim]A campaign is a weaker claim than the identities in it: an "
            "address can be a NAT gateway. Exported at address confidence, never "
            "at the identities'.[/dim]"
        )
    contamination = _contamination_panel(report)
    if contamination is not None:
        console.print()
        console.print(contamination)
    if report.probes:
        console.print()
        console.print(_probe_table(report))
    fingerprints = _fingerprint_table(report)
    if fingerprints is not None:
        console.print()
        console.print(fingerprints)
        console.print(
            "[dim]Same algorithm list, different banner: the version string is "
            "whatever the operator typed; the fingerprint is not.[/dim]"
        )
    if report.credentials and not quiet:
        console.print()
        table = Table(title="credentials the actor gave up", title_style="bold",
                      header_style="bold cyan")
        table.add_column("access key id", no_wrap=True)
        table.add_column("scheme")
        table.add_column("what the prefix means")
        for key, detail in report.credentials.items():
            table.add_row(key, str(detail.get("scheme", "")), str(detail.get("key_type", "")))
        console.print(table)


def cmd_report(args: argparse.Namespace) -> int:
    report = analyse(load(args.capture))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    render_report(report, _console(args.width))
    return 0


# -- export --------------------------------------------------------------------

def cmd_export(args: argparse.Namespace) -> int:
    console = _console()
    report = analyse(load(args.capture))
    document = to_misp(report) if args.format == "misp" else to_stix(report)
    text = json.dumps(document, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        console.print(f"[green]✓[/green] {args.format} → [cyan]{args.output}[/cyan]")
        console.print(
            f"  [green]{len(report.hostile)}[/green] {_plural(report.hostile)} "
            f"published\n"
            f"  [dim]{len(report.benign_actors)}[/dim] withheld — allowlisted source\n"
            f"  [yellow]{len(report.contaminated)}[/yellow] withheld — also matched "
            f"allowlisted traffic"
        )
        console.print("\n[dim]Confidence is capped by how the identity was "
                      "grouped, never by how many events it produced:[/dim]")
        for basis in sorted({a.basis for a in report.hostile}):
            console.print(f"[dim]  {basis:11s}[/dim] [bold]{CONFIDENCE[basis]:>3d}[/bold]"
                          f"  [dim]{CONFIDENCE_WHY[basis]}[/dim]")
    else:
        print(text)
    return 0


# -- selftest ------------------------------------------------------------------

def cmd_selftest(args: argparse.Namespace) -> int:
    console = _console(args.width)
    events = capture()
    report = analyse(events)

    checks: list[tuple[bool, str]] = []
    checks.append((len(events) > 0, f"listeners accepted traffic ({len(events)} events)"))
    checks.append((
        any(s.hassh for s in report.sessions),
        "SSH KEXINIT parsed and fingerprinted",
    ))

    rotating = [h for h, v in report.fingerprints.items() if len(v) > 1]
    checks.append((
        bool(rotating),
        "one HASSH seen under two banners — a rotating client was still grouped",
    ))

    wordlists = [a for a in report.hostile if a.basis == "path_set" and a.multi_homed]
    checks.append((
        bool(wordlists),
        "a wordlist walked from two addresses grouped as one identity",
    ))

    multi = [a for a in report.hostile if a.multi_homed]
    checks.append((bool(multi),
                   f"{len(multi)} {_plural(multi)} grouped across source addresses"))
    checks.append((
        bool(report.credentials),
        f"{len(report.credentials)} AWS access key id(s) recovered from S3 probes",
    ))

    linked = [c for c in report.campaigns if c.is_linked]
    checks.append((
        bool(linked),
        f"{len(linked)} campaign(s) joined identities across services",
    ))
    checks.append((
        report.benign_share > 0,
        f"benign traffic present and excluded ({report.benign_share:.0%} of events)",
    ))
    checks.append((
        bool(report.contaminated),
        f"{len(report.contaminated)} {_plural(report.contaminated)} matched the "
        f"allowlist and were withheld",
    ))

    # The export is where a mistake becomes someone else's problem, so it is
    # checked against the events rather than against the analyser's opinion.
    bundle = to_stix(report)
    published = json.dumps(bundle)
    benign_addresses = report.benign_addresses
    leaked_addresses = sorted(ip for ip in benign_addresses if f'"{ip}"' in published)
    checks.append((
        not leaked_addresses,
        "no allowlisted address reached the STIX bundle"
        + (f" — leaked {', '.join(leaked_addresses)}" if leaked_addresses else ""),
    ))

    benign_keys = {a.key for a in report.benign_actors} | {
        a.key for a in report.contaminated
    }
    leaked_keys = sorted(k for k in benign_keys if k and k in published)
    checks.append((
        not leaked_keys,
        "no allowlisted or contaminated signal published as an indicator",
    ))

    table = Table(header_style="bold cyan", title="selftest", title_style="bold")
    table.add_column("", no_wrap=True)
    table.add_column("check")
    for passed, description in checks:
        table.add_row("[green]✓[/green]" if passed else "[red]✗[/red]", description)
    console.print(table)

    failed = [d for passed, d in checks if not passed]
    if failed:
        console.print(f"\n[red]{len(failed)} check(s) failed[/red]")
        return 1
    console.print(f"\n[green]all {len(checks)} checks passed[/green] "
                  f"[dim]— against real sockets, not mocks[/dim]")
    return 0


# -- profiles ------------------------------------------------------------------

def cmd_profiles(args: argparse.Namespace) -> int:
    console = _console(args.width)
    table = Table(title="client profiles the selftest drives", title_style="bold",
                  header_style="bold cyan")
    table.add_column("profile", no_wrap=True)
    table.add_column("claims to be")
    table.add_column("kex/ciphers/macs", justify="right")
    for name, profile in CLIENT_PROFILES.items():
        counts = (f"{len(profile['kex'])}/{len(profile['ciphers'])}/"
                  f"{len(profile['macs'])}")
        table.add_row(name, profile["version"], counts)
    console.print(table)
    console.print("[dim]`scanner` and `scanner-disguised` share one algorithm list "
                  "under two banners.[/dim]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decoy",
        description="Low-interaction decoys, and the analysis that keeps them worth reading.",
    )
    parser.add_argument("--version", action="version", version=f"decoy {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="start the decoys")
    run_cmd.add_argument("--host", default="0.0.0.0")  # noqa: S104 - a decoy is meant to be reachable
    run_cmd.add_argument("--listen", action="append", metavar="NAME=PORT",
                         help="ssh=2222, http=8080, s3=8081 (repeatable)")
    run_cmd.add_argument("--log", default="captures/live.jsonl")
    run_cmd.add_argument("--benign", action="append", metavar="PREFIX=REASON",
                         help="a source that must not raise an alert, and why")
    run_cmd.add_argument("--banner", default=Grid.banner)
    run_cmd.set_defaults(func=cmd_run)

    capture_cmd = sub.add_parser("capture", help="drive the decoys and save the events")
    capture_cmd.add_argument("-o", "--output", default="captures/reference.jsonl")
    capture_cmd.set_defaults(func=cmd_capture)

    report_cmd = sub.add_parser("report", help="who touched the grid, and how much was noise")
    report_cmd.add_argument("capture", nargs="?", default="captures/reference.jsonl")
    report_cmd.add_argument("--json", action="store_true")
    report_cmd.add_argument("--width", type=int, default=None)
    report_cmd.set_defaults(func=cmd_report)

    export_cmd = sub.add_parser("export", help="STIX 2.1 or MISP, benign sources excluded")
    export_cmd.add_argument("capture", nargs="?", default="captures/reference.jsonl")
    export_cmd.add_argument("-f", "--format", choices=("stix", "misp"), default="stix")
    export_cmd.add_argument("-o", "--output")
    export_cmd.set_defaults(func=cmd_export)

    selftest_cmd = sub.add_parser("selftest", help="prove the pipeline over real sockets")
    selftest_cmd.add_argument("--width", type=int, default=None)
    selftest_cmd.set_defaults(func=cmd_selftest)

    profiles_cmd = sub.add_parser("profiles", help="the client profiles the selftest sends")
    profiles_cmd.add_argument("--width", type=int, default=None)
    profiles_cmd.set_defaults(func=cmd_profiles)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        _console().print(f"[red]{exc}[/red]\n[dim]Run `decoy capture` first.[/dim]")
        return 2
    except (ValueError, OSError) as exc:
        _console().print(f"[red]{exc}[/red]")
        return 2


if __name__ == "__main__":
    sys.exit(main())
