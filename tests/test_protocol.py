"""Parsing tests: the bytes a client sends, including the bytes it should not.

A decoy parses hostile input by definition, so every parser here is tested with
something malformed as well as something valid. A honeypot that only survives
well-formed traffic has not been tested at all.
"""

from __future__ import annotations

import struct

import pytest

from decoy import ssh, web
from decoy.selftest import CLIENT_PROFILES, build_kexinit

# -- SSH version exchange ------------------------------------------------------

def test_parse_version_reads_the_identification_string():
    assert ssh.parse_version(b"SSH-2.0-OpenSSH_9.6p1\r\n") == "SSH-2.0-OpenSSH_9.6p1"


def test_parse_version_skips_lines_before_the_banner():
    """RFC 4253 §4.2 permits them, and proxies actually send them.

    Taking the first line is the usual shortcut and it mislabels every client
    behind anything that prepends a line.
    """
    data = b"You are being monitored.\r\nSSH-2.0-PuTTY_Release_0.80\r\n"
    assert ssh.parse_version(data) == "SSH-2.0-PuTTY_Release_0.80"


def test_parse_version_accepts_the_1_99_compatibility_string():
    assert ssh.parse_version(b"SSH-1.99-Cisco-1.25\r\n").startswith("SSH-1.99")


def test_parse_version_rejects_ssh_1():
    with pytest.raises(ssh.SshError, match="unsupported SSH protocol version"):
        ssh.parse_version(b"SSH-1.5-OpenSSH_2.9\r\n")


def test_parse_version_rejects_traffic_that_is_not_ssh():
    with pytest.raises(ssh.SshError, match="no SSH identification string"):
        ssh.parse_version(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


# -- SSH binary packet ---------------------------------------------------------

def test_parse_packet_round_trips_a_real_kexinit():
    packet = build_kexinit(CLIENT_PROFILES["openssh"])
    message, payload = ssh.parse_packet(packet)
    assert message == ssh.SSH_MSG_KEXINIT
    assert ssh.parse_kexinit(payload).lists["kex_algorithms"] == \
        CLIENT_PROFILES["openssh"]["kex"]


def test_parse_packet_refuses_an_oversized_length():
    """The length field is the first thing an attacker controls.

    Honouring it would make it an allocation primitive; RFC 4253 §6.1 sets
    35000 as the minimum a peer must accept, so anything larger is hostile or
    broken and neither deserves the memory.
    """
    hostile = struct.pack(">I", 4_000_000_000) + b"\x04" + b"\x00" * 8
    with pytest.raises(ssh.SshError, match="exceeds the 35000-byte limit"):
        ssh.parse_packet(hostile)


def test_parse_packet_rejects_a_length_longer_than_the_data():
    truncated = struct.pack(">I", 500) + b"\x04" + b"\x00" * 8
    with pytest.raises(ssh.SshError, match="claims 500 bytes"):
        ssh.parse_packet(truncated)


def test_parse_kexinit_rejects_a_name_list_longer_than_the_payload():
    payload = b"\x00" * 16 + struct.pack(">I", 9999) + b"aes128-ctr"
    with pytest.raises(ssh.SshError, match="name-list claims 9999 bytes"):
        ssh.parse_kexinit(payload)


def test_parse_kexinit_rejects_a_payload_shorter_than_its_cookie():
    with pytest.raises(ssh.SshError, match="shorter than its 16-byte cookie"):
        ssh.parse_kexinit(b"\x00" * 8)


# -- HASSH ---------------------------------------------------------------------

def _hassh(name: str) -> str:
    _, payload = ssh.parse_packet(build_kexinit(CLIENT_PROFILES[name]))
    return ssh.parse_kexinit(payload).hassh


def test_hassh_is_stable_for_the_same_algorithm_list():
    assert _hassh("openssh") == _hassh("openssh")


def test_hassh_ignores_the_claimed_version_string():
    """The whole point. `scanner` and `scanner-disguised` differ only in banner."""
    assert CLIENT_PROFILES["scanner"]["version"] != \
        CLIENT_PROFILES["scanner-disguised"]["version"]
    assert _hassh("scanner") == _hassh("scanner-disguised")


def test_hassh_differs_between_client_implementations():
    assert len({_hassh("openssh"), _hassh("scanner"), _hassh("paramiko")}) == 3


def test_hassh_excludes_the_host_key_algorithms():
    """HASSH is four name-lists, not five.

    The host key list is a property of what the *server* offered as much as of
    the client, so including it would make the fingerprint depend on the decoy
    and stop matching what anyone else records.
    """
    lists = {name: ["x"] for name in ssh._NAME_LISTS}
    baseline = ssh.KexInit(lists=lists, cookie="00").hassh
    changed = dict(lists, server_host_key_algorithms=["ssh-ed25519", "rsa-sha2-512"])
    assert ssh.KexInit(lists=changed, cookie="00").hassh == baseline


# -- HTTP ----------------------------------------------------------------------

def test_parse_request_keeps_a_colon_inside_a_header_value():
    """`split(":")` instead of `partition(":")` truncates every URL header."""
    request = web.parse_request(
        b"GET / HTTP/1.1\r\nReferer: http://evil.example/a?b=1\r\n\r\n"
    )
    assert request.header("referer") == "http://evil.example/a?b=1"


def test_parse_request_splits_path_from_query():
    request = web.parse_request(b"GET /a/b?id=1&x=2 HTTP/1.1\r\n\r\n")
    assert (request.path, request.query) == ("/a/b", "id=1&x=2")


def test_parse_request_tolerates_bare_newlines():
    request = web.parse_request(b"GET /x HTTP/1.1\nHost: y\n\n")
    assert request.header("host") == "y"


def test_parse_request_rejects_an_empty_request_line():
    with pytest.raises(web.HttpError, match="empty request line"):
        web.parse_request(b"\r\n\r\n")


def test_parse_request_rejects_a_request_larger_than_the_cap():
    with pytest.raises(web.HttpError, match="exceeds"):
        web.parse_request(b"GET / HTTP/1.1\r\n\r\n" + b"A" * web.MAX_REQUEST_BYTES)


def test_header_lookup_is_case_insensitive():
    request = web.parse_request(b"GET / HTTP/1.1\r\nUSER-AGENT: curl/8\r\n\r\n")
    assert request.header("User-Agent") == "curl/8"


# -- probe classification ------------------------------------------------------

@pytest.mark.parametrize(("target", "expected"), [
    ("/.git/config", "git-exposure"),
    ("/.env", "env-file"),
    ("/actuator/env", "spring-actuator"),
    ("/wp-login.php", "wordpress"),
    ("/phpinfo.php", "php-config"),
    ("/admin/", "admin-panel"),
    ("/backup.sql", "backup-file"),
    ("/x?f=../../../../etc/passwd", "path-traversal"),
    ("/latest/meta-data/iam/security-credentials/", "aws-metadata"),
    ("/api?id=1'+OR+'1'='1", "sql-injection"),
])
def test_classify_names_what_the_probe_was_after(target, expected):
    request = web.parse_request(f"GET {target} HTTP/1.1\r\n\r\n".encode())
    assert expected in {p["probe"] for p in web.classify(request)}


def test_classify_searches_headers_not_only_the_path():
    """Log4Shell was overwhelmingly a header attack.

    A classifier that reads only the URL misses the class of probe it most
    needs to catch, and the request looks entirely ordinary.
    """
    request = web.parse_request(
        b"GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://x/a}\r\n\r\n"
    )
    found = {p["probe"]: p for p in web.classify(request)}
    assert "jndi-injection" in found
    assert found["jndi-injection"]["where"] == "header or body"


def test_classify_reports_where_a_path_probe_was_found():
    request = web.parse_request(b"GET /.git/config HTTP/1.1\r\n\r\n")
    found = {p["probe"]: p for p in web.classify(request)}
    assert found["git-exposure"]["where"] == "path"


@pytest.mark.parametrize("target", [
    "/api?id=1'+OR+'1'='1",
    "/api?id=1%27+OR+%271%27%3D%271",
    "/api?id=1%2527%2520OR%2520%25271%2527%253D%25271",   # double-encoded
])
def test_sql_injection_is_caught_in_the_form_it_is_actually_sent_in(target):
    """The decisive case for the whole classifier.

    `' OR '1'='1` reaches a server as `%27+OR+%271%27%3D%271`. A signature
    written with `\\s` matches literally none of that, so the request is logged
    as an ordinary query string and the probe is invisible.
    """
    request = web.parse_request(f"GET {target} HTTP/1.1\r\n\r\n".encode())
    assert "sql-injection" in {p["probe"] for p in web.classify(request)}


def test_encoded_traversal_is_caught_after_decoding():
    request = web.parse_request(b"GET /x?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n\r\n")
    assert "path-traversal" in {p["probe"] for p in web.classify(request)}


def test_wp_login_php_matches_the_wordpress_signature():
    """`(/|$)` after the word misses the most-probed path on the internet."""
    request = web.parse_request(b"GET /wp-login.php HTTP/1.1\r\n\r\n")
    assert "wordpress" in {p["probe"] for p in web.classify(request)}


def test_classify_returns_nothing_for_an_ordinary_request():
    request = web.parse_request(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
    assert web.classify(request) == []


def test_every_probe_carries_a_meaning():
    """'Suspicious path' tells an analyst nothing they cannot already see."""
    assert all(meaning.strip() for _, _, meaning in web.PROBES)


# -- S3 credentials ------------------------------------------------------------

def test_parse_credentials_reads_a_sigv4_authorization_header():
    request = web.parse_request(
        b"GET / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 "
        b"Credential=AKIAIOSFODNN7EXAMPLE/20260725/eu-west-1/s3/aws4_request, "
        b"SignedHeaders=host, Signature=dead\r\n\r\n"
    )
    credentials = web.parse_credentials(request)
    assert credentials["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert credentials["region"] == "eu-west-1"


def test_parse_credentials_reads_a_presigned_url():
    """Presigned requests carry no Authorization header at all.

    Reading only the header loses the credential from every presigned probe,
    which is the form a browser-delivered link takes.
    """
    request = web.parse_request(
        b"GET /?X-Amz-Credential=ASIAY44TESTTEMPCRED%2F20260725%2Feu-west-1%2Fs3 "
        b"HTTP/1.1\r\n\r\n"
    )
    credentials = web.parse_credentials(request)
    assert credentials["access_key_id"] == "ASIAY44TESTTEMPCRED"
    assert credentials["scheme"] == "presigned URL"


def test_asia_prefix_is_reported_as_a_temporary_credential():
    """A prefix is not decoration: ASIA means something already issued it."""
    request = web.parse_request(
        b"GET /?X-Amz-Credential=ASIAXXXXXXXXXXXXXXXX%2F20260725%2Feu-west-1%2Fs3"
        b" HTTP/1.1\r\n\r\n"
    )
    assert "already compromised" in web.parse_credentials(request)["key_type"]


def test_parse_credentials_returns_none_for_an_unauthenticated_request():
    assert web.parse_credentials(web.parse_request(b"GET / HTTP/1.1\r\n\r\n")) is None


# -- responses -----------------------------------------------------------------

def test_the_http_decoy_never_reflects_the_requested_path():
    """Reflecting the path is how a decoy becomes an XSS vector on your estate."""
    request = web.parse_request(b"GET /<script>alert(1)</script> HTTP/1.1\r\n\r\n")
    _, body = web.http_response(request)
    assert b"script" not in body


def test_the_s3_decoy_lists_nothing():
    request = web.parse_request(b"GET / HTTP/1.1\r\n\r\n")
    status, body = web.s3_response(request)
    assert status == 200
    assert b"<Contents>" not in body


def test_the_s3_decoy_denies_writes():
    request = web.parse_request(b"PUT /x HTTP/1.1\r\n\r\n")
    assert web.s3_response(request)[0] == 403


def test_api_paths_answer_401_to_invite_a_second_attempt():
    """A 404 ends the interaction; a 401 buys another event, sometimes with a
    credential in it."""
    assert web.http_response(web.parse_request(b"GET /api/v1/x HTTP/1.1\r\n\r\n"))[0] == 401
