"""The listeners.

Three constraints shape all of them, and each one is a refusal rather than a
feature:

**Nothing the client sends is ever executed, opened, or written.** Not a path,
not a filename, not a command. The decoys respond from constants. A honeypot
that "emulates" a filesystem is a filesystem.

**Every read is bounded and every connection is on a timer.** An attacker who
finds a decoy has found a process on your network that will do what they say;
the only safe answer is that it will not do very much, and not for very long. A
client that opens a socket and sends nothing is disconnected, not held.

**Every connection is recorded before it is understood.** The `connect` event
is written the moment the socket is accepted, so a client that crashes the
parser still leaves evidence of having been there. The order matters: parse
first and a malformed probe becomes an invisible one.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import ssh as sshmod
from . import web
from .event import Event, EventLog, now, session_id

READ_TIMEOUT = 10.0
SESSION_TIMEOUT = 30.0
MAX_BYTES = 64 * 1024


@dataclass
class Grid:
    """A set of decoys sharing one event log and one benign-source policy."""

    log: EventLog
    #: CIDR-ish prefixes and exact addresses that are known-benign.
    benign: dict[str, str] = field(default_factory=dict)
    banner: str = sshmod.DEFAULT_BANNER
    bucket: str = "corp-finance-archive"
    servers: list[asyncio.AbstractServer] = field(default_factory=list)

    def benign_reason(self, ip: str) -> str:
        """Why this source should not raise an alert, or empty.

        Prefix matching on the dotted string rather than real CIDR arithmetic.
        It is enough for the allowlists these deployments actually carry
        (`10.20.30.` for a scanner subnet, an exact address for a load
        balancer) and it cannot silently widen the way a mis-typed prefix
        length can.
        """
        for prefix, reason in self.benign.items():
            if ip == prefix or ip.startswith(prefix):
                return reason
        return ""

    def record(self, service: str, ip: str, port: int, kind: str, session: str,
               **detail: Any) -> Event:
        return self.log.record(Event(
            service=service, source_ip=ip, source_port=port, kind=kind,
            session=session, detail=detail, benign_reason=self.benign_reason(ip),
        ))


def _peer(writer: asyncio.StreamWriter) -> tuple[str, int]:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return str(peer[0]), int(peer[1])
    return "unknown", 0


async def _read_some(reader: asyncio.StreamReader, limit: int = MAX_BYTES) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout=READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionResetError):
        return b""


def handle_ssh(grid: Grid) -> Callable:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = _peer(writer)
        session = session_id(ip, port, "ssh", now())
        grid.record("ssh", ip, port, "connect", session)
        try:
            writer.write(sshmod.server_banner(grid.banner))
            await writer.drain()

            data = await _read_some(reader, 4096)
            if not data:
                grid.record("ssh", ip, port, "disconnect", session,
                            reason="no identification string sent")
                return

            try:
                version = sshmod.parse_version(data)
            except sshmod.SshError as exc:
                # Not SSH at all. Worth its own event: something is probing the
                # port with the wrong protocol, which is itself a finding.
                grid.record("ssh", ip, port, "banner", session,
                            error=str(exc), first_bytes=data[:64].hex())
                return

            grid.record("ssh", ip, port, "banner", session, client_version=version)

            # The KEXINIT may already be in the same read, or may follow.
            remainder = data.split(b"\n", 1)[1] if b"\n" in data else b""
            if len(remainder) < 6:
                remainder = await _read_some(reader, 8192)

            kexinit = None
            if remainder:
                try:
                    message, payload = sshmod.parse_packet(remainder)
                    if message == sshmod.SSH_MSG_KEXINIT:
                        kexinit = sshmod.parse_kexinit(payload)
                except sshmod.SshError as exc:
                    grid.record("ssh", ip, port, "kexinit", session, error=str(exc))

            if kexinit is not None:
                grid.record(
                    "ssh", ip, port, "kexinit", session,
                    client=sshmod.classify_client(version, kexinit),
                    **kexinit.to_dict(),
                )
        finally:
            grid.record("ssh", ip, port, "disconnect", session)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return handler


def _http_like(grid: Grid, service: str) -> Callable:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, port = _peer(writer)
        session = session_id(ip, port, service, now())
        grid.record(service, ip, port, "connect", session)
        try:
            data = await _read_some(reader)
            if not data:
                grid.record(service, ip, port, "disconnect", session,
                            reason="connected without sending a request")
                return

            try:
                request = web.parse_request(data)
            except web.HttpError as exc:
                grid.record(service, ip, port, "request", session,
                            error=str(exc), first_bytes=data[:64].hex())
                return

            detail: dict[str, Any] = {
                **request.to_dict(),
                "user_agent": request.header("user-agent"),
            }
            if service == "s3":
                credentials = web.parse_credentials(request)
                if credentials:
                    detail["credentials"] = credentials
                status, body = web.s3_response(request, grid.bucket)
                response = web.render_s3(status, body)
            else:
                probes = web.classify(request)
                if probes:
                    detail["probes"] = probes
                status, body = web.http_response(request)
                response = web.render_http(status, body)

            detail["status"] = status
            grid.record(service, ip, port, "request", session, **detail)

            writer.write(response)
            await writer.drain()
        finally:
            grid.record(service, ip, port, "disconnect", session)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return handler


def handle_http(grid: Grid) -> Callable:
    return _http_like(grid, "http")


def handle_s3(grid: Grid) -> Callable:
    return _http_like(grid, "s3")


HANDLERS = {"ssh": handle_ssh, "http": handle_http, "s3": handle_s3}


async def serve(grid: Grid, bindings: dict[str, tuple[str, int]]) -> list[asyncio.AbstractServer]:
    """Start the named decoys. Returns the servers so a caller can close them."""
    servers = []
    for service, (host, port) in bindings.items():
        if service not in HANDLERS:
            raise ValueError(f"unknown decoy {service!r}; have {', '.join(sorted(HANDLERS))}")
        server = await asyncio.start_server(HANDLERS[service](grid), host, port)
        servers.append(server)
    grid.servers = servers
    return servers


async def run(grid: Grid, bindings: dict[str, tuple[str, int]]) -> None:
    servers = await serve(grid, bindings)
    async with contextlib.AsyncExitStack() as stack:
        for server in servers:
            await stack.enter_async_context(server)
        await asyncio.gather(*(s.serve_forever() for s in servers))


def bound_ports(servers: list[asyncio.AbstractServer]) -> list[int]:
    """The ports actually bound, which is how port 0 becomes usable in tests."""
    ports = []
    for server in servers:
        for sock in server.sockets or ():
            ports.append(sock.getsockname()[1])
    return ports
