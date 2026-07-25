"""An SSH decoy that stops exactly where a decoy should stop.

It completes the version exchange, reads the client's `SSH_MSG_KEXINIT`, and
then closes. That is deliberately short of a key exchange, and short of an
authentication prompt, for two reasons.

The first is that the interesting intelligence is already in hand. A client's
KEXINIT lists, in order, every algorithm it is willing to use — key exchange,
host key, cipher, MAC, compression. That ordering is a property of the *client
implementation*, not of the target, and hashing it gives a **HASSH**
fingerprint that survives a change of source IP. Two scans from different
addresses with the same HASSH are the same tool, and often the same operator.
A username and a password are one credential pair; a HASSH is an identity.

The second is that everything past this point is liability. Completing a key
exchange means running cryptography on attacker-supplied input; offering a
shell means emulating one. A decoy exists on a network *you* own, and every
feature added to make it more convincing is a feature an attacker can attack.
The version banner and the algorithm list cost nothing and give up nothing.

Protocol reference: RFC 4253 §4.2 (version exchange) and §6-7 (binary packet
protocol and KEXINIT).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

#: What the decoy claims to be. A version that is old enough to look worth
#: attacking, and specific enough that a scan records something.
DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

SSH_MSG_KEXINIT = 20

#: The ten name-lists in a KEXINIT, in wire order (RFC 4253 §7.1).
_NAME_LISTS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


class SshError(ValueError):
    """Raised when a client's bytes are not SSH. Says what was expected."""


@dataclass(frozen=True)
class KexInit:
    """The client's declared algorithm preferences."""

    lists: dict[str, list[str]]
    cookie: str

    @property
    def hassh(self) -> str:
        """The HASSH fingerprint: MD5 over four comma-joined name-lists.

        MD5 because the HASSH specification says MD5, and a fingerprint that
        does not match everyone else's is not a fingerprint. It is an identifier
        here, never a security control.
        """
        parts = ";".join(
            ",".join(self.lists.get(name, []))
            for name in (
                "kex_algorithms",
                "encryption_algorithms_client_to_server",
                "mac_algorithms_client_to_server",
                "compression_algorithms_client_to_server",
            )
        )
        return hashlib.md5(parts.encode(), usedforsecurity=False).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "hassh": self.hassh,
            "kex_algorithms": self.lists.get("kex_algorithms", []),
            "host_key_algorithms": self.lists.get("server_host_key_algorithms", []),
            "ciphers": self.lists.get("encryption_algorithms_client_to_server", []),
            "macs": self.lists.get("mac_algorithms_client_to_server", []),
            "compression": self.lists.get("compression_algorithms_client_to_server", []),
        }


def parse_version(data: bytes) -> str:
    """Extract the client's identification string.

    RFC 4253 §4.2 permits arbitrary lines before it, so the first line is not
    necessarily the banner. Taking `data.split(b'\\r\\n')[0]` is the usual bug
    and it silently mislabels every client behind a proxy that prepends a line.
    """
    for line in data.replace(b"\r\n", b"\n").split(b"\n"):
        text = line.strip().decode("utf-8", errors="replace")
        if text.startswith("SSH-"):
            if not text.startswith(("SSH-2.0-", "SSH-1.99-")):
                raise SshError(f"unsupported SSH protocol version in {text!r}")
            return text
    raise SshError("no SSH identification string (expected a line starting 'SSH-')")


def _name_list(payload: bytes, offset: int) -> tuple[list[str], int]:
    if offset + 4 > len(payload):
        raise SshError("truncated name-list length")
    (length,) = struct.unpack(">I", payload[offset:offset + 4])
    offset += 4
    if offset + length > len(payload):
        raise SshError(f"name-list claims {length} bytes, {len(payload) - offset} remain")
    raw = payload[offset:offset + length].decode("ascii", errors="replace")
    return ([item for item in raw.split(",") if item], offset + length)


def parse_packet(data: bytes) -> tuple[int, bytes]:
    """Unwrap one binary packet, returning (message number, payload).

    Packet layout: uint32 packet_length, byte padding_length, payload, padding.
    `packet_length` counts everything after itself, so the payload is
    `packet_length - padding_length - 1` bytes.
    """
    if len(data) < 6:
        raise SshError(f"packet too short: {len(data)} bytes, need at least 6")
    (packet_length,) = struct.unpack(">I", data[:4])
    if packet_length > 35000:
        # RFC 4253 §6.1 sets 35000 as the minimum a client must accept, and a
        # larger figure here is a malformed or hostile length rather than a
        # real packet. Refusing it is what stops a length field from becoming
        # an allocation primitive.
        raise SshError(f"packet_length {packet_length} exceeds the 35000-byte limit")
    padding_length = data[4]
    payload_length = packet_length - padding_length - 1
    if payload_length < 1 or 4 + packet_length > len(data):
        raise SshError(
            f"packet claims {packet_length} bytes with {padding_length} padding; "
            f"{len(data)} received"
        )
    payload = data[5:5 + payload_length]
    return payload[0], payload[1:]


def parse_kexinit(payload: bytes) -> KexInit:
    """Parse a KEXINIT payload (message number already stripped)."""
    if len(payload) < 16:
        raise SshError("KEXINIT payload is shorter than its 16-byte cookie")
    cookie = payload[:16].hex()
    offset = 16
    lists: dict[str, list[str]] = {}
    for name in _NAME_LISTS:
        values, offset = _name_list(payload, offset)
        lists[name] = values
    return KexInit(lists=lists, cookie=cookie)


def server_banner(banner: str = DEFAULT_BANNER) -> bytes:
    return (banner + "\r\n").encode()


def classify_client(version: str, kexinit: KexInit | None) -> str:
    """A short label for what connected. Best effort, and says so.

    Version strings are trivially forged, which is exactly why the HASSH is
    recorded alongside: a client can claim to be OpenSSH while offering an
    algorithm list no OpenSSH build has ever offered, and the disagreement is
    itself the finding.
    """
    lowered = version.lower()
    for needle, label in (
        ("openssh", "OpenSSH client"),
        ("paramiko", "Paramiko (Python) — scripted"),
        ("libssh", "libssh"),
        ("go", "Go x/crypto/ssh — commonly a scanner"),
        ("putty", "PuTTY"),
        ("nmap", "Nmap NSE"),
        ("zgrab", "ZGrab — internet-wide scanning"),
        ("masscan", "masscan"),
    ):
        if needle in lowered:
            return label
    if kexinit and not kexinit.lists.get("languages_client_to_server"):
        return "unrecognised client"
    return "unrecognised client"
