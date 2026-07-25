"""Export to STIX 2.1, so the observations leave this tool and join a graph.

A decoy that writes to its own log file has produced a log file. The point of
the exercise is that a HASSH seen here yesterday matches one your EDR saw
last week, and that correlation happens in a threat-intelligence platform, not
here.

Two decisions in this module are worth stating because they are the ones a
naive exporter gets wrong.

**Benign sources are excluded, and the exclusion is counted.** Publishing your
own vulnerability scanner's address as an indicator of compromise is how a
sharing community stops trusting your feed. The count is returned so the
operator can see it was not silent.

**Nothing is asserted with more confidence than it was observed with.** Each
indicator carries `confidence` derived from how much the underlying signal
survives — a HASSH or an access key is durable and scores high; a source
address seen once scores low, because it is very likely a NAT gateway, a VPN
exit or a residential lease that belonged to someone else last week. An
indicator feed that rates everything 100 is a feed of future false positives.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .analyse import Actor, Report

UTC = timezone.utc

#: STIX requires deterministic UUIDv5 for SCOs; using one throughout means a
#: replayed capture produces a byte-identical bundle, which is what lets CI
#: diff it. Namespace from STIX 2.1 §1.6.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _deterministic_id(prefix: str, seed: str) -> str:
    return f"{prefix}--{uuid.uuid5(STIX_NAMESPACE, f'{prefix}:{seed}')}"


def _stamp(at: str) -> str:
    """STIX wants RFC 3339 with a Z and millisecond precision."""
    try:
        moment = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        moment = datetime.now(UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{moment.microsecond // 1000:03d}Z"


#: How durable each grouping signal is, and therefore how much of a claim an
#: indicator built on it can honestly make.
CONFIDENCE = {
    "hassh": 85,
    "access_key": 90,
    "path_set": 60,
    "address": 30,
}
CONFIDENCE_WHY = {
    "hassh": "client implementation fingerprint; survives a change of source address",
    "access_key": "long-lived credential identifier held by the actor",
    "path_set": "scanner wordlist; stable per tool but shared between operators",
    "address": "single source address, seen once; likely to be reassigned",
}


#: A wordlist pattern names every path, and a long one is unreadable in every
#: platform that will display it. Truncating is stated in the description
#: rather than done silently.
MAX_PATTERN_PATHS = 20


def _pattern(actor: Actor) -> str | None:
    """The STIX pattern for one identity, or None if it has nothing to assert.

    Every basis gets one. An identity the analyser was confident enough to
    report and then silently declines to export is worse than one it never
    grouped: the operator sees it on screen, assumes it was shared, and it
    was not.
    """
    if actor.basis == "hassh":
        return f"[network-traffic:extensions.'socket-ext'.options.HASSH = '{actor.key}']"
    if actor.basis == "access_key":
        return f"[user-account:account_login = '{actor.key}']"
    if actor.basis == "path_set":
        # The wordlist identifies the *tool*, which is what makes it worth
        # sharing: a recipient can match it against their own web logs without
        # ever having seen these addresses.
        paths = actor.key.split("|")[:MAX_PATTERN_PATHS]
        return " OR ".join(
            "[network-traffic:extensions.'http-request-ext'.request_value = "
            f"'{path}']" for path in paths
        )
    if actor.basis == "address" and actor.addresses:
        return " OR ".join(f"[ipv4-addr:value = '{ip}']" for ip in actor.addresses)
    return None


def to_stix(report: Report, *, created_by: str = "deception-grid") -> dict[str, Any]:
    """Build a STIX 2.1 bundle from the hostile actors only."""
    objects: list[dict[str, Any]] = []

    identity_id = _deterministic_id("identity", created_by)
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": created_by,
        "identity_class": "system",
        "description": "Low-interaction decoy grid. Every observation is an "
                       "interaction with a host that has no legitimate users.",
    })

    excluded = 0
    contaminated = 0
    for actor in report.actors:
        if actor.is_benign:
            # Publishing your own scanner as an IoC is how a sharing community
            # stops trusting your feed.
            excluded += 1
            continue
        if actor.touches_benign:
            # Matched allowlisted traffic as well as hostile traffic, so the
            # signal is not specific enough to be an indicator. Stock OpenSSH
            # has one HASSH; publishing it would fire on every Ubuntu host on
            # the internet, starting with the ones in this estate.
            contaminated += 1
            continue

        seen = _stamp(actor.first_seen)
        for address in actor.addresses:
            objects.append({
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": _deterministic_id("ipv4-addr", address),
                "value": address,
            })

        pattern = _pattern(actor)
        if pattern is None:
            continue

        confidence = CONFIDENCE.get(actor.basis, 30)
        indicator_id = _deterministic_id("indicator", f"{actor.basis}:{actor.key}")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": identity_id,
            "created": seen,
            "modified": seen,
            "name": actor.label,
            "description": (
                f"Observed by a decoy with no legitimate users. "
                f"{actor.events} event(s) across {len(actor.sessions)} session(s) "
                f"from {len(actor.addresses)} address(es). "
                f"Confidence {confidence}: {CONFIDENCE_WHY.get(actor.basis, '')}."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": seen,
            "confidence": confidence,
            "labels": sorted(set(actor.probes)) or [actor.basis],
        })

        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _deterministic_id("observed-data", f"{actor.basis}:{actor.key}"),
            "created_by_ref": identity_id,
            "created": seen,
            "modified": seen,
            "first_observed": seen,
            "last_observed": _stamp(max(s.started for s in actor.sessions)),
            "number_observed": actor.events,
            "object_refs": [_deterministic_id("ipv4-addr", ip) for ip in actor.addresses],
        })

    bundle = {
        "type": "bundle",
        "id": _deterministic_id(
            "bundle",
            hashlib.sha256(
                json.dumps([o["id"] for o in objects], sort_keys=True).encode()
            ).hexdigest(),
        ),
        "objects": objects,
    }
    bundle["x_deception_grid"] = {
        "benign_actors_excluded": excluded,
        "contaminated_actors_excluded": contaminated,
        "benign_share_of_events": round(report.benign_share, 4),
        "note": "Known-benign sources are excluded from this bundle by design, "
                "along with any identity that also matched allowlisted traffic.",
    }
    return bundle


def to_misp(report: Report, *, info: str = "Decoy grid observations") -> dict[str, Any]:
    """A MISP event. Same exclusions, same confidence, different shape."""
    attributes: list[dict[str, Any]] = []
    for actor in report.actors:
        if actor.is_benign or actor.touches_benign:
            continue
        comment = f"{actor.label} — {actor.events} event(s), {CONFIDENCE_WHY.get(actor.basis, '')}"
        for address in actor.addresses:
            attributes.append({
                "type": "ip-src", "category": "Network activity", "value": address,
                "to_ids": actor.basis in ("hassh", "access_key"),
                "comment": comment,
            })
        if actor.basis == "hassh":
            attributes.append({
                "type": "hassh-md5", "category": "Network activity", "value": actor.key,
                "to_ids": True, "comment": comment,
            })
        if actor.basis == "access_key":
            attributes.append({
                "type": "text", "category": "Payload delivery", "value": actor.key,
                "to_ids": False, "comment": f"AWS access key ID — {comment}",
            })
        if actor.basis == "path_set":
            for path in actor.key.split("|")[:MAX_PATTERN_PATHS]:
                attributes.append({
                    "type": "uri", "category": "Network activity", "value": path,
                    "to_ids": False,
                    "comment": f"scanner wordlist entry — {comment}",
                })

    return {
        "Event": {
            "info": info,
            "analysis": "2",
            "threat_level_id": "2",
            "distribution": "0",
            "Attribute": attributes,
            "Tag": [{"name": 'source:"deception-grid"'}, {"name": 'tlp:amber'}],
        }
    }
