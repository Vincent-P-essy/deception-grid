"""deception-grid — low-interaction decoys that produce a signal worth reading.

The three listeners (`ssh`, `http`, `s3`) share one event log, one benign-source
policy and one rule: nothing a client sends is ever executed, opened or written.

The public surface is small on purpose:

    from decoy import Grid, EventLog, analyse, to_stix

    grid = Grid(log=EventLog("captures/live.jsonl"), benign={"10.20.30.": "scanner"})
    # ... run the listeners ...
    report = analyse(grid.log.events)
    bundle = to_stix(report)
"""

from __future__ import annotations

from .analyse import Actor, Report, Session, actors, analyse, sessions
from .event import Event, EventLog, dump, load, session_id
from .intel import to_misp, to_stix
from .server import Grid, bound_ports, run, serve
from .ssh import KexInit, SshError, parse_kexinit, parse_packet, parse_version
from .web import HttpError, Request, classify, parse_credentials, parse_request

__version__ = "1.0.0"

__all__ = [
    "Actor",
    "Event",
    "EventLog",
    "Grid",
    "HttpError",
    "KexInit",
    "Report",
    "Request",
    "Session",
    "SshError",
    "actors",
    "analyse",
    "bound_ports",
    "classify",
    "dump",
    "load",
    "parse_credentials",
    "parse_kexinit",
    "parse_packet",
    "parse_request",
    "parse_version",
    "run",
    "serve",
    "session_id",
    "sessions",
    "to_misp",
    "to_stix",
]
