"""Grouping, campaigns, contamination, and what is allowed to leave the tool.

These are the tests that matter most. A parser that is wrong produces a bad
event; the grouping being wrong produces a published indicator that fires on
somebody else's estate, and they cannot see why.
"""

from __future__ import annotations

import json

import pytest

from decoy.analyse import COMMON_PATHS, analyse, wordlist
from decoy.event import Event
from decoy.intel import CONFIDENCE, to_misp, to_stix
from decoy.selftest import capture

CLOCK = "2026-07-25T09:00:00.000+00:00"


@pytest.fixture(scope="module")
def bundled():
    """The real capture, driven over real sockets once for the whole module."""
    return analyse(capture())


def event(service: str, ip: str, kind: str = "request", session: str = "",
          benign: str = "", **detail) -> Event:
    return Event(service=service, source_ip=ip, source_port=44444, kind=kind,
                 at=CLOCK, session=session or f"{service}-{ip}-{kind}",
                 detail=detail, benign_reason=benign)


def request(ip: str, target: str, session: str, **kwargs) -> Event:
    return event("http", ip, "request", session, target=target, **kwargs)


def kexinit(ip: str, hassh: str, version: str, session: str, **kwargs) -> Event:
    return event("ssh", ip, "kexinit", session, hassh=hassh,
                 client_version=version, **kwargs)


# -- grouping ------------------------------------------------------------------

def test_one_hassh_across_two_addresses_is_one_identity():
    report = analyse([
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        kexinit("198.51.100.1", "aa" * 16, "SSH-2.0-OpenSSH_8.2p1", "s2"),
    ])
    assert len(report.actors) == 1
    actor = report.actors[0]
    assert actor.basis == "hassh"
    assert actor.multi_homed
    assert actor.addresses == ["198.51.100.1", "203.0.113.1"]


def test_the_disagreement_between_fingerprint_and_banner_is_surfaced():
    """One implementation claiming two identities is a stronger signal than
    either version string on its own."""
    report = analyse([
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        kexinit("198.51.100.1", "aa" * 16, "SSH-2.0-OpenSSH_8.2p1", "s2"),
    ])
    assert report.fingerprints["aa" * 16] == ["SSH-2.0-Go", "SSH-2.0-OpenSSH_8.2p1"]


def test_an_access_key_groups_sessions_from_different_addresses():
    report = analyse([
        event("s3", "203.0.113.1", "request", "s1", target="/",
              credentials={"access_key_id": "AKIATEST"}),
        event("s3", "198.51.100.1", "request", "s2", target="/x",
              credentials={"access_key_id": "AKIATEST"}),
    ])
    assert [(a.basis, a.multi_homed) for a in report.actors] == [("access_key", True)]


def test_a_wordlist_is_computed_per_address_not_per_session():
    """The defect this replaced.

    HTTP/1.1 with `Connection: close` gives one request per connection, so a
    per-session wordlist signature can never reach three paths. It is not a
    weak signal, it is dead code — and its silent effect is that every web
    scanner falls back to being identified by an address it can change.
    """
    events = [
        request("203.0.113.1", path, f"s{index}")
        for index, path in enumerate(["/.git/config", "/.env", "/actuator/env"])
    ]
    report = analyse(events)
    assert len(report.sessions) == 3
    assert [a.basis for a in report.actors] == ["path_set"]


def test_the_same_wordlist_from_a_new_address_is_the_same_identity():
    paths = ["/.git/config", "/.env", "/actuator/env", "/wp-login.php"]
    events = [request("203.0.113.1", p, f"a{i}") for i, p in enumerate(paths)]
    events += [request("198.51.100.1", p, f"b{i}") for i, p in enumerate(paths)]
    report = analyse(events)
    assert len(report.actors) == 1
    assert report.actors[0].multi_homed


def test_a_different_wordlist_is_a_different_identity():
    first = ["/.git/config", "/.env", "/actuator/env"]
    second = ["/phpinfo.php", "/backup.sql", "/xmlrpc.php"]
    events = [request("203.0.113.1", p, f"a{i}") for i, p in enumerate(first)]
    events += [request("198.51.100.1", p, f"b{i}") for i, p in enumerate(second)]
    assert len(analyse(events).actors) == 2


def test_common_paths_do_not_make_a_wordlist():
    """Two hosts both requesting `/` is not evidence of anything.

    Merging on it is the false positive this signal is most prone to, and it
    merges the loudest sources first.
    """
    assert wordlist(set(COMMON_PATHS)) == ""
    assert wordlist({"/", "/health", "/.git/config"}) == ""
    assert wordlist({"/", "/.git/config", "/.env", "/actuator/env"}) != ""


def test_too_few_paths_falls_back_to_the_address():
    """Which is the honest answer, not a failure."""
    events = [request("192.0.2.1", "/download", "s1"),
              request("192.0.2.1", "/api/v1/users", "s2")]
    actors = analyse(events).actors
    assert [(a.basis, a.key) for a in actors] == [("address", "192.0.2.1")]


def test_grouping_prefers_the_signal_that_survives_a_change_of_address():
    """A session with both a fingerprint and a wordlist is filed under the
    fingerprint, because that is the one that outlives the address."""
    events = [kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1")]
    events += [request("203.0.113.1", p, f"h{i}") for i, p in
               enumerate(["/.git/config", "/.env", "/actuator/env"])]
    bases = {a.basis for a in analyse(events).actors}
    assert bases == {"hassh", "path_set"}


# -- campaigns -----------------------------------------------------------------

def test_identities_sharing_an_address_form_a_campaign():
    """The argument for running three decoys rather than one.

    The SSH fingerprint and the S3 key are unrelated observations until an
    address ties them together, and a single-service honeypot cannot make the
    link at all.
    """
    events = [
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        event("s3", "203.0.113.1", "request", "s2", target="/",
              credentials={"access_key_id": "AKIATEST"}),
    ]
    campaigns = analyse(events).campaigns
    assert len(campaigns) == 1
    assert campaigns[0].is_linked
    assert campaigns[0].services == ["s3", "ssh"]
    assert set(campaigns[0].links["203.0.113.1"]) == {"aa" * 16, "AKIATEST"}


def test_identities_that_share_nothing_stay_apart():
    events = [
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        kexinit("198.51.100.1", "bb" * 16, "SSH-2.0-paramiko_3", "s2"),
    ]
    campaigns = analyse(events).campaigns
    assert len(campaigns) == 2
    assert not any(c.is_linked for c in campaigns)


def test_a_campaign_never_merges_its_identities_into_one_indicator():
    """A campaign is a weaker claim than the identities in it.

    An address can be a NAT gateway, so collapsing the two layers would let one
    shared egress address publish an access key and a fingerprint as the same
    thing at the higher of their two confidences.
    """
    events = [
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        event("s3", "203.0.113.1", "request", "s2", target="/",
              credentials={"access_key_id": "AKIATEST"}),
    ]
    report = analyse(events)
    assert len(report.campaigns) == 1
    patterns = [o["pattern"] for o in to_stix(report)["objects"]
                if o["type"] == "indicator"]
    assert len(patterns) == 2
    assert sum("HASSH" in p for p in patterns) == 1
    assert sum("account_login" in p for p in patterns) == 1


# -- the allowlist -------------------------------------------------------------

def test_the_benign_share_is_computed_over_events():
    events = [request("10.20.30.9", "/", "s1", ), request("203.0.113.1", "/.env", "s2")]
    events[0].benign_reason = "internal scanner"
    assert analyse(events).benign_share == 0.5


def test_an_identity_seen_on_both_sides_of_the_allowlist_is_contaminated():
    """Stock OpenSSH has exactly one HASSH.

    So the fingerprint of a patched Ubuntu fleet is also the fingerprint of
    every attacker who connected from an Ubuntu box. Publishing it would fire
    on the whole internet, starting inside the estate that published it.
    """
    events = [
        kexinit("10.20.30.9", "cc" * 16, "SSH-2.0-OpenSSH_9.6p1", "s1", ),
        kexinit("203.0.113.99", "cc" * 16, "SSH-2.0-OpenSSH_9.6p1", "s2"),
    ]
    events[0].benign_reason = "internal scanner"
    report = analyse(events)
    assert len(report.contaminated) == 1
    assert report.hostile == []
    assert report.contaminated[0].benign_addresses == ["10.20.30.9"]


def test_a_contaminated_identity_is_withheld_from_both_exports():
    events = [
        kexinit("10.20.30.9", "cc" * 16, "SSH-2.0-OpenSSH_9.6p1", "s1"),
        kexinit("203.0.113.99", "cc" * 16, "SSH-2.0-OpenSSH_9.6p1", "s2"),
    ]
    events[0].benign_reason = "internal scanner"
    report = analyse(events)

    bundle = to_stix(report)
    assert bundle["x_deception_grid"]["contaminated_actors_excluded"] == 1
    assert "cc" * 16 not in json.dumps(bundle)
    assert "203.0.113.99" not in json.dumps(bundle)
    assert to_misp(report)["Event"]["Attribute"] == []


def test_a_wholly_benign_identity_is_excluded_and_the_exclusion_is_counted():
    """Silence would be worse. An operator who cannot see that something was
    withheld cannot tell a filtered feed from an empty one."""
    events = [request("10.20.30.9", p, f"s{i}") for i, p in
              enumerate(["/.git/config", "/.env", "/actuator/env"])]
    for item in events:
        item.benign_reason = "internal scanner"
    bundle = to_stix(analyse(events))
    assert bundle["x_deception_grid"]["benign_actors_excluded"] == 1
    assert "10.20.30.9" not in json.dumps(bundle)


def test_every_identity_is_in_exactly_one_of_the_three_states(bundled):
    states = (len(bundled.hostile) + len(bundled.benign_actors) +
              len(bundled.contaminated))
    assert states == len(bundled.actors)


# -- what leaves the tool ------------------------------------------------------

def test_an_indicator_is_never_more_confident_than_its_signal():
    """A feed that rates everything 100 is a feed of future false positives."""
    assert CONFIDENCE["access_key"] > CONFIDENCE["hassh"] > CONFIDENCE["path_set"] \
        > CONFIDENCE["address"]


def test_a_single_source_address_is_the_least_trusted_indicator():
    """It is very likely a NAT gateway, a VPN exit, or a residential lease that
    belonged to somebody else last week."""
    assert CONFIDENCE["address"] <= 30


def test_the_bundle_is_byte_identical_for_the_same_capture():
    """Deterministic UUIDv5 throughout, so CI can diff an export."""
    events = [kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1")]
    first, second = to_stix(analyse(events)), to_stix(analyse(events))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_stix_timestamps_carry_the_millisecond_precision_the_spec_wants():
    events = [kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1")]
    indicator = next(o for o in to_stix(analyse(events))["objects"]
                     if o["type"] == "indicator")
    assert indicator["valid_from"].endswith("Z")
    assert indicator["valid_from"] == "2026-07-25T09:00:00.000Z"


def test_misp_marks_only_durable_identities_for_detection():
    """`to_ids` on an address that was seen once turns a colleague's SIEM into
    a false-positive generator."""
    events = [
        kexinit("203.0.113.1", "aa" * 16, "SSH-2.0-Go", "s1"),
        request("192.0.2.1", "/download", "s2"),
    ]
    attributes = to_misp(analyse(events))["Event"]["Attribute"]
    by_value = {a["value"]: a for a in attributes}
    assert by_value["203.0.113.1"]["to_ids"] is True
    assert by_value["192.0.2.1"]["to_ids"] is False


@pytest.mark.parametrize("field", ["type", "spec_version", "id", "pattern",
                                   "pattern_type", "valid_from", "confidence"])
def test_every_indicator_carries_the_required_stix_fields(field, bundled):
    indicator = next(o for o in to_stix(bundled)["objects"]
                     if o["type"] == "indicator")
    assert field in indicator


def test_every_exportable_identity_produces_an_indicator(bundled):
    """An identity reported on screen and then silently not exported is worse
    than one that was never grouped: the operator assumes it was shared."""
    indicators = [o for o in to_stix(bundled)["objects"] if o["type"] == "indicator"]
    assert len(indicators) == len(bundled.hostile)


def test_a_wordlist_is_exported_as_the_paths_it_walked(bundled):
    """The wordlist identifies the tool, which is what makes it shareable: a
    recipient can match it against their own web logs having never seen these
    addresses."""
    actor = next(a for a in bundled.hostile if a.basis == "path_set")
    indicator = next(o for o in to_stix(bundled)["objects"]
                     if o["type"] == "indicator" and "http-request-ext" in o["pattern"])
    assert indicator["confidence"] == CONFIDENCE["path_set"]
    for path in actor.key.split("|"):
        assert f"'{path}'" in indicator["pattern"]


def test_the_bundle_states_what_it_withheld(bundled):
    bundle = to_stix(bundled)
    marker = bundle["x_deception_grid"]
    assert marker["benign_actors_excluded"] >= 1
    assert "excluded from this bundle by design" in marker["note"]
