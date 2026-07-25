"""The decoys, over real sockets.

Every test here binds a real listener on an ephemeral port and connects to it
with a real socket. Mocking the network in a honeypot's test suite tests the
author's beliefs about the network, which is the one thing a honeypot cannot
afford to be wrong about.
"""

from __future__ import annotations

import asyncio

import pytest

from decoy import ssh as sshmod
from decoy.event import Event, EventLog, dump, load, session_id
from decoy.selftest import CLIENT_PROFILES, build_kexinit
from decoy.server import Grid, bound_ports, serve


async def _round_trip(payload: bytes, service: str = "http", **grid_kwargs) -> tuple:
    """Start one decoy, send `payload`, return (response, events)."""
    grid = Grid(log=EventLog(), **grid_kwargs)
    servers = await serve(grid, {service: ("127.0.0.1", 0)})
    port = bound_ports(servers)[0]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(65536), timeout=3.0)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()
    return response, grid.log.events


# -- the listeners -------------------------------------------------------------

async def test_http_decoy_answers_and_records_the_probe():
    response, events = await _round_trip(b"GET /.git/config HTTP/1.1\r\nHost: x\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 404")
    request = next(e for e in events if e.kind == "request")
    assert request.detail["probes"][0]["probe"] == "git-exposure"


async def test_ssh_decoy_sends_a_banner_and_records_the_fingerprint():
    payload = b"SSH-2.0-Go\r\n" + build_kexinit(CLIENT_PROFILES["scanner"])
    response, events = await _round_trip(payload, "ssh")
    assert response.startswith(b"SSH-2.0-OpenSSH")
    kexinit = next(e for e in events if e.kind == "kexinit")
    assert len(kexinit.detail["hassh"]) == 32
    assert kexinit.detail["client"].startswith("Go x/crypto/ssh")


async def test_s3_decoy_recovers_the_access_key():
    payload = (b"GET / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 "
               b"Credential=AKIATESTTESTTESTTEST/20260725/eu-west-1/s3/aws4_request, "
               b"SignedHeaders=host, Signature=dead\r\n\r\n")
    response, events = await _round_trip(payload, "s3")
    assert b"AmazonS3" in response
    request = next(e for e in events if e.kind == "request")
    assert request.detail["credentials"]["access_key_id"] == "AKIATESTTESTTESTTEST"


async def test_connect_is_recorded_before_the_payload_is_understood():
    """A probe that crashes the parser must still leave evidence.

    Parsing first and recording second makes a malformed probe an invisible
    one, which hands an attacker a way to touch the grid without appearing in
    it: send garbage.
    """
    _, events = await _round_trip(b"\x00\xff\xfe not a request at all\r\n\r\n")
    assert events[0].kind == "connect"
    assert any(e.kind == "request" and "error" in e.detail for e in events)


async def test_traffic_on_the_ssh_port_that_is_not_ssh_is_itself_a_finding():
    _, events = await _round_trip(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "ssh")
    banner = next(e for e in events if e.kind == "banner")
    assert "no SSH identification string" in banner.detail["error"]
    assert banner.detail["first_bytes"]


async def test_a_client_that_sends_nothing_is_disconnected_not_held():
    grid = Grid(log=EventLog())
    servers = await serve(grid, {"http": ("127.0.0.1", 0)})
    port = bound_ports(servers)[0]
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.1)
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()
    assert {e.kind for e in grid.log.events} == {"connect", "disconnect"}


async def test_the_decoy_never_reflects_what_the_client_asked_for():
    """The response is built from constants. It has to be.

    A decoy that echoes the request is a stored-XSS and SSRF surface sitting on
    a network segment nobody watches, reachable by anyone who found it.
    """
    response, _ = await _round_trip(
        b"GET /<img/src=x onerror=alert(1)> HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert b"onerror" not in response
    assert b"<img" not in response


async def test_three_decoys_share_one_log():
    grid = Grid(log=EventLog())
    servers = await serve(grid, {"ssh": ("127.0.0.1", 0), "http": ("127.0.0.1", 0),
                                 "s3": ("127.0.0.1", 0)})
    try:
        assert len(bound_ports(servers)) == 3
        assert len({*bound_ports(servers)}) == 3
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()


async def test_serve_names_the_decoys_it_has_when_asked_for_one_it_does_not():
    with pytest.raises(ValueError, match="unknown decoy 'telnet'"):
        await serve(Grid(log=EventLog()), {"telnet": ("127.0.0.1", 0)})


# -- the benign allowlist ------------------------------------------------------

async def test_a_benign_source_is_labelled_at_the_moment_of_recording():
    """Not at analysis time. The log is what survives; the analyser is not."""
    _, events = await _round_trip(
        b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n",
        benign={"127.0.0.": "the loopback, for this test"},
    )
    assert all(e.is_benign for e in events)
    assert events[0].benign_reason == "the loopback, for this test"


def test_benign_matching_is_a_prefix_not_a_netmask():
    """Deliberate, and the docstring says so.

    Prefix matching on the dotted string cannot silently widen the way an
    off-by-one prefix length can: `/16` typed where `/24` was meant excuses 255
    times more traffic and looks identical in review.
    """
    grid = Grid(log=EventLog(), benign={"10.20.30.": "scanner subnet"})
    assert grid.benign_reason("10.20.30.9") == "scanner subnet"
    assert grid.benign_reason("10.20.31.9") == ""
    assert grid.benign_reason("10.20.3.9") == ""


def test_an_unlisted_source_has_no_reason():
    assert Grid(log=EventLog()).benign_reason("203.0.113.1") == ""


# -- the log -------------------------------------------------------------------

def test_events_round_trip_through_jsonl(tmp_path):
    original = [
        Event(service="ssh", source_ip="203.0.113.1", source_port=4444,
              kind="connect", session="abc"),
        Event(service="http", source_ip="203.0.113.2", source_port=5555,
              kind="request", detail={"target": "/.env"}, benign_reason="scanner"),
    ]
    restored = load(dump(original, tmp_path / "c.jsonl"))
    assert [e.to_dict() for e in restored] == [e.to_dict() for e in original]


def test_load_names_the_line_that_failed(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"service":"ssh","source_ip":"1","source_port":1,"kind":"connect"}\n'
                    "{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"broken\.jsonl:2"):
        load(path)


def test_load_refuses_a_capture_from_a_newer_schema(tmp_path):
    """Silently dropping fields it does not understand would be worse.

    A capture written by a later version may carry a field this version treats
    as absent, and 'absent' is the value that means *not hostile* in several
    places here.
    """
    path = tmp_path / "future.jsonl"
    path.write_text('{"service":"ssh","source_ip":"1","source_port":1,'
                    '"kind":"connect","schema":99}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="newer schema"):
        load(path)


def test_load_names_a_capture_that_is_not_there(tmp_path):
    with pytest.raises(FileNotFoundError, match="capture not found"):
        load(tmp_path / "absent.jsonl")


def test_the_log_writes_through_on_every_event(tmp_path):
    """A decoy being killed is not an unusual way for one of these to end.

    Buffering loses exactly the part of the session that mattered.
    """
    path = tmp_path / "live.jsonl"
    log = EventLog(path)
    log.record(Event(service="ssh", source_ip="1", source_port=1, kind="connect"))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_session_ids_are_derived_not_random():
    """So a replayed capture produces byte-identical analysis, and CI can diff it."""
    first = session_id("203.0.113.1", 4444, "ssh", "2026-07-25T10:00:00.000+00:00")
    second = session_id("203.0.113.1", 4444, "ssh", "2026-07-25T10:00:00.000+00:00")
    assert first == second
    assert first != session_id("203.0.113.1", 4445, "ssh", "2026-07-25T10:00:00.000+00:00")


def test_the_server_banner_ends_with_crlf():
    """RFC 4253 §4.2. A client waiting for the newline otherwise hangs until
    the read timeout, and the KEXINIT never arrives."""
    assert sshmod.server_banner("SSH-2.0-Test").endswith(b"\r\n")
