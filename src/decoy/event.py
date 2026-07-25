"""The interaction event, and the one property that makes a decoy worth running.

A decoy has no users. Nothing legitimate has any reason to connect to it, so
every event is, by construction, either an intrusion attempt or a mistake in
your own estate. That is the entire value proposition: a signal with no base
rate of benign activity behind it.

Which means the thing that destroys a deception grid is not being detected by
an attacker. It is **your own vulnerability scanner**. Point a nightly
authenticated scan at the subnet the decoys live on and they will produce a few
hundred events a year, every one of them meaningless, and within a month nobody
reads the queue. The decoys still work perfectly and the programme is dead.

So an event carries `benign_reason` from the moment it is recorded, and every
report states what share of traffic came from a known-benign source. A grid
where that number is climbing is a grid that is being switched off, and the
number should be on the first screen rather than discovered later.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

UTC = timezone.utc
SCHEMA_VERSION = 1


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass
class Event:
    """One interaction with a decoy."""

    #: ssh | http | s3
    service: str
    source_ip: str
    source_port: int
    #: connect | banner | auth | request | disconnect
    kind: str
    at: str = field(default_factory=now)
    session: str = ""
    decoy: str = ""
    #: Free-form, per-service. Kept flat enough to grep.
    detail: dict[str, Any] = field(default_factory=dict)
    #: Set when the source is known-benign. Non-empty means "do not alert".
    benign_reason: str = ""
    schema: int = SCHEMA_VERSION

    @property
    def is_benign(self) -> bool:
        return bool(self.benign_reason)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in raw.items() if k in known})


def session_id(source_ip: str, source_port: int, service: str, at: str) -> str:
    """A stable identifier for one connection.

    Derived rather than random so a replayed capture produces byte-identical
    output, which is what lets CI diff the analyser's results.
    """
    seed = f"{service}|{source_ip}|{source_port}|{at}".encode()
    return hashlib.blake2b(seed, digest_size=8).hexdigest()


class EventLog:
    """Append-only JSONL sink.

    Line-buffered and flushed per event on purpose. A honeypot that loses the
    last thirty seconds of its buffer when the process is killed loses exactly
    the part of the session that mattered, and a decoy being killed is not an
    unusual way for one of these to end.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path else None
        self.events: list[Event] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: Event) -> Event:
        with self._lock:
            self.events.append(event)
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(event.to_json() + "\n")
                    handle.flush()
        return event

    def __len__(self) -> int:
        return len(self.events)


def load(path: str | os.PathLike[str]) -> list[Event]:
    """Read a JSONL capture, naming the line that failed rather than the file."""
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"capture not found: {source}")

    events = []
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{number} is not valid JSON: {exc.msg}") from None
        if raw.get("schema", SCHEMA_VERSION) > SCHEMA_VERSION:
            raise ValueError(
                f"{source}:{number} was written by a newer schema "
                f"(v{raw['schema']} > v{SCHEMA_VERSION})"
            )
        events.append(Event.from_dict(raw))
    return events


def dump(events: list[Event], path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(e.to_json() for e in events) + "\n", encoding="utf-8")
    return target
