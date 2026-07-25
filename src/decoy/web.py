"""HTTP and S3-alike decoys.

Both answer plausibly enough that a scanner records a hit and moves on, and
neither ever executes, reads or writes anything the request names. A decoy that
serves a real filesystem is a file server with a misleading name.

What they are for is different from what they look like. The HTTP decoy exists
to capture **what was probed**, because the probe path is a better fingerprint
of the tooling than the User-Agent is: a request for `/.git/config` followed by
`/.env` followed by `/actuator/env` is a specific scanner with a specific
wordlist, and the User-Agent it sends is whatever the operator typed.

The S3 decoy exists to capture the **access key ID** out of a SigV4
`Authorization` header. An attacker probing a bucket with credentials has
already told you which credentials they hold, and `AKIA...` prefixes are
long-lived identifiers that outlive any single source address. It is the
highest-value field either decoy collects and it arrives before authentication
is even attempted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

MAX_REQUEST_BYTES = 64 * 1024


#: Real methods are alphabetic; the hyphen admits SSDP's `M-SEARCH`, which is
#: worth keeping because discovery traffic reaching a decoy is itself a finding.
_METHOD = re.compile(r"[A-Za-z][A-Za-z-]{0,19}")


class HttpError(ValueError):
    """Raised when a request cannot be parsed. Names what was expected."""


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query(self) -> str:
        return self.target.split("?", 1)[1] if "?" in self.target else ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "target": self.target,
            "version": self.version,
            "headers": self.headers,
            "body": self.body[:2048].decode("utf-8", errors="replace"),
        }


def parse_request(data: bytes) -> Request:
    """Parse an HTTP/1.x request. Tolerant of the malformed, because probes are.

    Header values are joined on the colon with `split(":", 1)` rather than
    `split(":")`, because `Referer: http://x/` contains a colon and losing
    everything after it drops the most interesting header a probe sends.
    """
    if len(data) > MAX_REQUEST_BYTES:
        raise HttpError(f"request exceeds {MAX_REQUEST_BYTES} bytes")

    head, _, body = data.partition(b"\r\n\r\n")
    if not head:
        head, _, body = data.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines or not lines[0].strip():
        raise HttpError("empty request line")

    parts = lines[0].decode("utf-8", errors="replace").split()
    if len(parts) < 2:
        raise HttpError(f"malformed request line: {lines[0][:80]!r}")
    method, target = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/0.9"

    # Being tolerant of malformed HTTP is not the same as accepting bytes that
    # are not HTTP. A binary probe whose first bytes happen to contain a space
    # would otherwise be recorded as a request with a control-character method
    # and its actual bytes thrown away — losing the only evidence that
    # something spoke a different protocol at this port, which is a finding in
    # its own right.
    if not _METHOD.fullmatch(method):
        raise HttpError(
            f"request line does not start with an HTTP method: {method[:20]!r}"
        )

    headers: dict[str, str] = {}
    for line in lines[1:]:
        text = line.decode("utf-8", errors="replace")
        if not text.strip():
            continue
        name, sep, value = text.partition(":")
        if not sep:
            continue
        headers[name.strip().lower()] = value.strip()

    return Request(method=method, target=target, version=version, headers=headers, body=body)


#: Probe signatures. Each names what the request was after, because "suspicious
#: path" in an alert tells an analyst nothing they cannot see for themselves.
PROBES: list[tuple[str, re.Pattern[str], str]] = [
    ("git-exposure", re.compile(r"/\.git(/|$)"),
     "exposed .git directory — source code and often credentials in history"),
    ("env-file", re.compile(r"/\.env(\.|$)|/\.env$"),
     "framework .env file — database and API credentials"),
    ("aws-metadata", re.compile(r"169\.254\.169\.254|/latest/meta-data"),
     "cloud instance metadata — SSRF probe for temporary credentials"),
    ("spring-actuator", re.compile(r"/actuator(/|$)|/env$|/heapdump$"),
     "Spring Boot actuator — configuration and heap dumps"),
    ("php-config", re.compile(r"/(phpinfo|info)\.php|/wp-config\.php"),
     "PHP configuration disclosure"),
    # `(/|$)` alone misses `/wp-login.php`, which is the single most-requested
    # path on the internet that is not `/`. The dot matters.
    ("wordpress", re.compile(r"/wp-(admin|login|content|includes|json)(/|\.|$)|/xmlrpc\.php"),
     "WordPress surface — mass exploitation target"),
    ("path-traversal", re.compile(r"\.\./|%2e%2e[/%]|\.\.%2f", re.IGNORECASE),
     "directory traversal"),
    ("shell-upload", re.compile(r"/(shell|cmd|c99|r57|webshell)\.(php|jsp|asp)"),
     "attempt to reach a previously uploaded web shell"),
    ("admin-panel", re.compile(r"/(admin|administrator|manager/html|phpmyadmin)(/|$)"),
     "administrative interface"),
    ("api-keys", re.compile(r"/(credentials|secrets|config\.json|appsettings\.json)$"),
     "credential file by name"),
    ("backup-file", re.compile(r"\.(bak|old|swp|sql|tar\.gz|zip)$"),
     "backup or archive left in the web root"),
    ("jndi-injection", re.compile(r"\$\{jndi:", re.IGNORECASE),
     "JNDI lookup — Log4Shell-style injection"),
    ("template-injection", re.compile(r"\{\{.*\}\}|\$\{.*\}"),
     "server-side template injection"),
    ("sql-injection",
     re.compile(r"(union\s+select|'\s+or\s+'1'\s*=\s*'1|sleep\(\d)", re.IGNORECASE),
     "SQL injection"),
]


def decoded(text: str) -> str:
    """Percent-decoding, with `+` treated as a space.

    Injection payloads are almost never sent in the form the signature is
    written in. `' OR '1'='1` travels as `%27+OR+%271%27%3D%271`, and a pattern
    containing `\\s` matches nothing at all against it — the request sails past
    every rule and the log records an ordinary-looking query string. Decoding
    twice catches the other half of it, where a filter upstream has already
    decoded once and the payload was encoded twice to survive that.
    """
    once = unquote_plus(text)
    twice = unquote_plus(once)
    return once if once == twice else f"{once}\n{twice}"


def classify(request: Request) -> list[dict[str, str]]:
    """What this request was looking for. Searches headers as well as the path.

    Injection payloads arrive in `User-Agent`, `Referer` and `X-Forwarded-For`
    at least as often as in the URL — Log4Shell was overwhelmingly a header
    attack — so a classifier that only reads the path misses the class of probe
    it most needs to catch.

    Both the raw and the decoded form are searched. Only the decoded form would
    miss a probe that is meaningful *because* it is encoded, and only the raw
    form would miss almost every real injection.
    """
    haystacks = [request.target, request.body[:4096].decode("utf-8", errors="replace")]
    haystacks += [f"{name}: {value}" for name, value in request.headers.items()]
    raw = "\n".join(haystacks)
    combined = f"{raw}\n{decoded(raw)}"
    target = f"{request.target}\n{decoded(request.target)}"

    found = []
    for name, pattern, meaning in PROBES:
        match = pattern.search(combined)
        if match:
            where = "path" if pattern.search(target) else "header or body"
            found.append({"probe": name, "meaning": meaning, "matched": match.group(0)[:80],
                          "where": where})
    return found


#: Responses chosen to look like a real service that is nearly worth pursuing.
#: A 404 for everything ends the interaction; a 401 invites another attempt and
#: buys a second event with, occasionally, a credential in it.
def http_response(request: Request) -> tuple[int, bytes]:
    path = request.path.rstrip("/") or "/"
    if path in ("/", "/index.html"):
        body = (
            b"<!doctype html><title>Internal Tools</title>"
            b"<h1>Internal Tools</h1><p>Authentication required.</p>"
        )
        return 200, body
    if path.startswith("/api"):
        return 401, b'{"error":"unauthorized","detail":"missing bearer token"}'
    if path in ("/health", "/healthz", "/livez"):
        return 200, b'{"status":"ok"}'
    return 404, b'{"error":"not_found"}'


def render_http(status: int, body: bytes, server: str = "nginx/1.18.0 (Ubuntu)") -> bytes:
    reasons = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}
    content_type = "application/json" if body.startswith(b"{") else "text/html; charset=utf-8"
    head = (
        f"HTTP/1.1 {status} {reasons.get(status, 'OK')}\r\n"
        f"Server: {server}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    )
    return head.encode() + body


# -- S3 ------------------------------------------------------------------------

#: `AWS4-HMAC-SHA256 Credential=AKIA.../20260725/eu-west-1/s3/aws4_request, ...`
_SIGV4 = re.compile(
    r"AWS4-HMAC-SHA256\s+Credential=(?P<key>[A-Z0-9]+)/(?P<date>\d{8})/"
    r"(?P<region>[a-z0-9-]+)/(?P<service>[a-z0-9]+)/aws4_request",
    re.IGNORECASE,
)
#: The older SigV2 form, still emitted by some tooling.
_SIGV2 = re.compile(r"AWS\s+(?P<key>[A-Z0-9]{16,}):(?P<signature>\S+)")

#: AWS key-ID prefixes carry meaning: ASIA is a temporary STS credential, which
#: means the holder has already compromised something that could issue one.
_KEY_PREFIX = {
    "AKIA": "long-lived IAM user access key",
    "ASIA": "temporary STS credential — issued to something already compromised",
    "AIDA": "IAM user unique id",
    "AROA": "IAM role unique id",
    "ANPA": "managed policy id",
}


def parse_credentials(request: Request) -> dict[str, Any] | None:
    """Pull the access key out of an S3 request. The highest-value field here.

    Also checks the query string, because presigned URLs put the credential in
    `X-Amz-Credential` and never send an Authorization header at all.
    """
    authorization = request.header("authorization")
    match = _SIGV4.search(authorization)
    if match:
        key = match.group("key").upper()
        return {
            "scheme": "AWS4-HMAC-SHA256",
            "access_key_id": key,
            "key_type": _KEY_PREFIX.get(key[:4], "unrecognised prefix"),
            "signed_date": match.group("date"),
            "region": match.group("region"),
            "service": match.group("service"),
        }

    match = _SIGV2.search(authorization)
    if match:
        key = match.group("key").upper()
        return {
            "scheme": "AWS (SigV2)",
            "access_key_id": key,
            "key_type": _KEY_PREFIX.get(key[:4], "unrecognised prefix"),
        }

    presigned = re.search(
        r"X-Amz-Credential=(?P<key>[A-Z0-9]+)(?:%2F|/)", request.query, re.IGNORECASE
    )
    if presigned:
        key = presigned.group("key").upper()
        return {
            "scheme": "presigned URL",
            "access_key_id": key,
            "key_type": _KEY_PREFIX.get(key[:4], "unrecognised prefix"),
        }
    return None


def s3_response(request: Request, bucket: str = "corp-finance-archive") -> tuple[int, bytes]:
    """A plausible S3 reply. Never lists anything, because there is nothing."""
    if request.method in ("PUT", "POST", "DELETE"):
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message>"
            b"<RequestId>0000000000000000</RequestId></Error>"
        )
        return 403, body

    if request.path.rstrip("/") in ("", "/"):
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            + f"<Name>{bucket}</Name>".encode()
            + b"<Prefix></Prefix><MaxKeys>1000</MaxKeys>"
            b"<IsTruncated>false</IsTruncated></ListBucketResult>"
        )
        return 200, body

    body = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<Error><Code>NoSuchKey</Code><Message>The specified key does not exist."
        b"</Message></Error>"
    )
    return 404, body


def render_s3(status: int, body: bytes) -> bytes:
    reasons = {200: "OK", 403: "Forbidden", 404: "Not Found"}
    head = (
        f"HTTP/1.1 {status} {reasons.get(status, 'OK')}\r\n"
        f"Server: AmazonS3\r\n"
        f"x-amz-request-id: 0000000000000000\r\n"
        f"Content-Type: application/xml\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    )
    return head.encode() + body
