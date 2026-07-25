"""Turning events into the numbers that decide whether anyone keeps looking.

**How many distinct identities** touched the grid, which is not the event count
and not the number of source addresses. One scanner making four hundred
requests from twelve addresses is one identity, and reporting it as four
hundred alerts is how a decoy programme becomes a queue. Identities are grouped
on what survives a change of address — the SSH HASSH fingerprint, the S3 access
key ID, the set of paths a scanner walks — falling back to the address only
when a session gave nothing else away.

**How many campaigns**, which is a deliberately weaker second layer. Identities
that shared a source address are probably one operator, but an address can be a
NAT gateway and that claim must never be exported at the confidence the
identities themselves carry. Keeping the two layers apart is the difference
between a feed people trust and one shared egress address ruining it.

**The benign share**: what fraction of traffic came from a source the operator
already knows about. A deception grid has no legitimate users, so this should
be zero. Every point above zero is a nightly vulnerability scan or a
load-balancer health check teaching the on-call rota that these alerts do not
matter. It is the metric that predicts the programme's death, and it belongs on
the first screen rather than in a quarterly review.

**How many identities are contaminated** — matching allowlisted traffic *and*
hostile traffic. That number should be zero too, and when it is not it is
because a signal turned out to be less distinctive than it looked. It is the
last thing checked before anything is published.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .event import Event


@dataclass
class Session:
    """One connection's events, in order."""

    session: str
    service: str
    source_ip: str
    source_port: int
    events: list[Event] = field(default_factory=list)

    @property
    def started(self) -> str:
        return self.events[0].at if self.events else ""

    @property
    def is_benign(self) -> bool:
        return bool(self.events) and self.events[0].is_benign

    @property
    def benign_reason(self) -> str:
        return self.events[0].benign_reason if self.events else ""

    @property
    def hassh(self) -> str:
        for event in self.events:
            if event.detail.get("hassh"):
                return str(event.detail["hassh"])
        return ""

    @property
    def access_key(self) -> str:
        for event in self.events:
            credentials = event.detail.get("credentials")
            if isinstance(credentials, dict) and credentials.get("access_key_id"):
                return str(credentials["access_key_id"])
        return ""

    @property
    def paths(self) -> list[str]:
        return [
            str(e.detail["target"]).split("?", 1)[0]
            for e in self.events
            if e.kind == "request" and e.detail.get("target")
        ]

    @property
    def probes(self) -> list[str]:
        found = []
        for event in self.events:
            for probe in event.detail.get("probes") or ():
                found.append(str(probe.get("probe", "")))
        return found

    @property
    def client_version(self) -> str:
        for event in self.events:
            if event.detail.get("client_version"):
                return str(event.detail["client_version"])
        return ""


def sessions(events: list[Event]) -> list[Session]:
    grouped: dict[str, Session] = {}
    for event in events:
        key = event.session or f"{event.service}:{event.source_ip}:{event.source_port}"
        session = grouped.get(key)
        if session is None:
            session = Session(
                session=key, service=event.service,
                source_ip=event.source_ip, source_port=event.source_port,
            )
            grouped[key] = session
        session.events.append(event)
    return sorted(grouped.values(), key=lambda s: (s.started, s.session))


@dataclass
class Actor:
    """One apparent operator, across however many addresses they used."""

    key: str
    #: hassh | access_key | path_set | address
    basis: str
    sessions: list[Session] = field(default_factory=list)

    @property
    def addresses(self) -> list[str]:
        return sorted({s.source_ip for s in self.sessions})

    @property
    def services(self) -> list[str]:
        return sorted({s.service for s in self.sessions})

    @property
    def events(self) -> int:
        return sum(len(s.events) for s in self.sessions)

    @property
    def is_benign(self) -> bool:
        """Every session came from an allowlisted source."""
        return all(s.is_benign for s in self.sessions)

    @property
    def touches_benign(self) -> bool:
        """Any session came from an allowlisted source. Blocks export.

        The interesting case is not an identity that is wholly benign — that
        one is easy. It is an identity that is *partly* benign, which happens
        the moment a signal is not as distinctive as it looked. Stock OpenSSH
        has one HASSH, so the fingerprint of your own patched Ubuntu fleet is
        also the fingerprint of every attacker who ssh'd from an Ubuntu box.

        Publishing that as an indicator would fire on the whole internet, and
        it would fire first inside your own estate. So the allowlist is treated
        here as a *sample of things that are definitely fine*: if an identity
        matches any of it, the identity is not specific enough to export,
        whatever else it also matched.
        """
        return any(s.is_benign for s in self.sessions)

    @property
    def benign_addresses(self) -> list[str]:
        return sorted({s.source_ip for s in self.sessions if s.is_benign})

    @property
    def benign_reason(self) -> str:
        return next((s.benign_reason for s in self.sessions if s.benign_reason), "")

    @property
    def first_seen(self) -> str:
        return min((s.started for s in self.sessions), default="")

    @property
    def probes(self) -> Counter:
        counter: Counter = Counter()
        for session in self.sessions:
            counter.update(session.probes)
        return counter

    @property
    def label(self) -> str:
        """What to call this actor in a report."""
        if self.basis == "hassh":
            version = next((s.client_version for s in self.sessions if s.client_version), "")
            return f"SSH client {self.key[:12]} ({version})" if version else \
                f"SSH client {self.key[:12]}"
        if self.basis == "access_key":
            return f"AWS key {self.key}"
        if self.basis == "path_set":
            paths = self.key.count("|") + 1
            article = "an" if str(paths)[0] in "8" else "a"
            return f"scanner walking {article} {paths}-path wordlist"
        return self.key

    @property
    def multi_homed(self) -> bool:
        """Used more than one source address. The reason to group at all."""
        return len(self.addresses) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "basis": self.basis,
            "label": self.label,
            "addresses": self.addresses,
            "services": self.services,
            "sessions": len(self.sessions),
            "events": self.events,
            "benign": self.is_benign,
            "benign_reason": self.benign_reason,
            "first_seen": self.first_seen,
            "probes": dict(self.probes.most_common()),
        }


#: Paths that everything requests. Grouping two actors because they both asked
#: for `/` is the false merge this signal is most prone to, and one shared
#: `/favicon.ico` is not evidence of anything.
COMMON_PATHS = frozenset({
    "/", "/index.html", "/favicon.ico", "/robots.txt",
    "/health", "/healthz", "/livez", "/ping",
})

#: How many distinctive paths make a wordlist rather than a coincidence.
WORDLIST_MINIMUM = 3


def wordlist(paths: set[str]) -> str:
    """A scanner's wordlist, if what it walked amounts to one.

    Computed over an **address**, not a session. HTTP/1.1 with `Connection:
    close` means one request per connection, so a session holds exactly one
    path and a per-session wordlist signature can never fire — it is silently
    dead code that makes every web scanner fall back to being identified by its
    address. The wordlist only becomes visible once the requests are put back
    together.
    """
    distinctive = sorted(paths - COMMON_PATHS)
    return "|".join(distinctive) if len(distinctive) >= WORDLIST_MINIMUM else ""


def actors(all_sessions: list[Session]) -> list[Actor]:
    """Group sessions into apparent identities.

    Ordered by how much a signal survives a change of address: a HASSH and an
    access key both do and are visible inside a single connection; a wordlist
    usually does but is only visible once an address's requests are put back
    together; the address itself is the fallback for a session that gave
    nothing else away.
    """
    paths_by_address: dict[str, set[str]] = defaultdict(set)
    for session in all_sessions:
        paths_by_address[session.source_ip].update(session.paths)

    grouped: dict[tuple[str, str], Actor] = {}
    for session in all_sessions:
        if session.hassh:
            basis, key = "hassh", session.hassh
        elif session.access_key:
            basis, key = "access_key", session.access_key
        elif (signature := wordlist(paths_by_address[session.source_ip])):
            basis, key = "path_set", signature
        else:
            basis, key = "address", session.source_ip

        actor = grouped.get((basis, key))
        if actor is None:
            actor = Actor(key=key, basis=basis)
            grouped[(basis, key)] = actor
        actor.sessions.append(session)

    return sorted(grouped.values(), key=lambda a: (-a.events, a.first_seen, a.key))


@dataclass
class Campaign:
    """Identities linked by a shared source address.

    An identity says *the same tool* or *the same credential*. A campaign says
    *probably the same operator*, and it is a weaker claim built on a weaker
    signal: two identities are joined here because they were seen from one
    address, and an address can be a NAT gateway, a VPN exit or a compromised
    third party that two unrelated actors both happen to be behind.

    So a campaign is reported and never exported at more than the confidence
    the link deserves. Collapsing the distinction — treating a campaign as if
    it were an identity — is how a shared egress address turns a feed into one
    enormous false positive.

    It exists because a grid running three decoys is not three honeypots. The
    web sweep from one address and the S3 probe from another are unrelated
    observations until the SSH fingerprint ties the two addresses together, and
    no single-service honeypot can make that link at all.
    """

    members: list[Actor] = field(default_factory=list)
    #: address -> the identities that used it. Only the addresses that did the
    #: linking, because "shared with nobody" is not a link.
    links: dict[str, list[str]] = field(default_factory=dict)

    @property
    def addresses(self) -> list[str]:
        return sorted({ip for actor in self.members for ip in actor.addresses})

    @property
    def services(self) -> list[str]:
        return sorted({service for actor in self.members for service in actor.services})

    @property
    def events(self) -> int:
        return sum(actor.events for actor in self.members)

    @property
    def first_seen(self) -> str:
        return min((a.first_seen for a in self.members), default="")

    @property
    def is_linked(self) -> bool:
        """More than one identity, joined by an address they shared."""
        return len(self.members) > 1

    @property
    def label(self) -> str:
        if not self.is_linked:
            return self.members[0].label if self.members else ""
        bases = Counter(a.basis for a in self.members)
        return (f"{len(self.members)} identities across {len(self.addresses)} address(es) "
                f"({', '.join(f'{n}×{b}' for b, n in bases.most_common())})")

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "linked": self.is_linked,
            "members": [a.key for a in self.members],
            "addresses": self.addresses,
            "services": self.services,
            "events": self.events,
            "links": self.links,
        }


def campaigns(hostile: list[Actor]) -> list[Campaign]:
    """Join identities that shared a source address.

    Benign identities are excluded before this runs. An allowlisted source
    merged into a hostile campaign would drag the whole campaign's status into
    ambiguity, and the allowlist is precisely the place an attacker would most
    like to be — so that case is surfaced separately by `Report.benign_overlap`
    rather than absorbed silently here.
    """
    parent = list(range(len(hostile)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        parent[find(left)] = find(right)

    holders: dict[str, list[int]] = defaultdict(list)
    for index, actor in enumerate(hostile):
        for address in actor.addresses:
            holders[address].append(index)

    links: dict[str, list[str]] = {}
    for address, indices in sorted(holders.items()):
        if len(indices) < 2:
            continue
        links[address] = [hostile[i].key for i in indices]
        for other in indices[1:]:
            union(indices[0], other)

    components: dict[int, Campaign] = {}
    for index, actor in enumerate(hostile):
        components.setdefault(find(index), Campaign()).members.append(actor)

    result = []
    for campaign in components.values():
        keys = {a.key for a in campaign.members}
        campaign.links = {ip: who for ip, who in links.items() if keys & set(who)}
        result.append(campaign)
    return sorted(result, key=lambda c: (-c.events, c.first_seen))


@dataclass
class Report:
    events: list[Event]
    sessions: list[Session]
    actors: list[Actor]

    #: Every identity is in exactly one of these three states, and each has a
    #: different disposition: export, ignore, or read with a person.
    @property
    def hostile(self) -> list[Actor]:
        """Clean hostile identities — the only ones that may be exported."""
        return [a for a in self.actors if not a.touches_benign]

    @property
    def benign_actors(self) -> list[Actor]:
        return [a for a in self.actors if a.is_benign]

    @property
    def contaminated(self) -> list[Actor]:
        """Identities matching both hostile and allowlisted traffic.

        Withheld from every export and reported instead, because there are two
        readings and no code can pick between them: the signal is too generic
        to be an identity, or something on the allowlist is doing what it was
        not allowlisted for.
        """
        return [a for a in self.actors if a.touches_benign and not a.is_benign]

    @property
    def campaigns(self) -> list[Campaign]:
        return campaigns(self.hostile)

    @property
    def benign_addresses(self) -> set[str]:
        return {e.source_ip for e in self.events if e.is_benign}

    @property
    def benign_share(self) -> float:
        """The number that predicts whether anyone keeps reading the queue."""
        if not self.events:
            return 0.0
        return sum(1 for e in self.events if e.is_benign) / len(self.events)

    @property
    def by_service(self) -> dict[str, int]:
        return dict(Counter(e.service for e in self.events).most_common())

    @property
    def probes(self) -> Counter:
        counter: Counter = Counter()
        for actor in self.hostile:
            counter.update(actor.probes)
        return counter

    @property
    def credentials(self) -> dict[str, dict[str, Any]]:
        """Access keys seen, with what their prefix implies."""
        out: dict[str, dict[str, Any]] = {}
        for event in self.events:
            credentials = event.detail.get("credentials")
            if isinstance(credentials, dict) and credentials.get("access_key_id"):
                out.setdefault(str(credentials["access_key_id"]), credentials)
        return out

    @property
    def fingerprints(self) -> dict[str, list[str]]:
        """HASSH -> the client versions claimed under it.

        More than one entry is the interesting case: the same client
        implementation presenting different version strings is a scanner
        rotating its banner, and the disagreement between the two is a stronger
        signal than either alone.
        """
        out: dict[str, set[str]] = defaultdict(set)
        for session in self.sessions:
            if session.hassh and session.client_version:
                out[session.hassh].add(session.client_version)
        return {h: sorted(v) for h, v in sorted(out.items())}

    def to_dict(self) -> dict[str, Any]:
        campaign_list = self.campaigns
        return {
            "events": len(self.events),
            "sessions": len(self.sessions),
            "actors": len(self.actors),
            "hostile_actors": len(self.hostile),
            "benign_actors": len(self.benign_actors),
            "contaminated_actors": len(self.contaminated),
            "campaigns": len(campaign_list),
            "linked_campaigns": sum(1 for c in campaign_list if c.is_linked),
            "benign_share": round(self.benign_share, 4),
            "contaminated_detail": [
                {"label": a.label, "basis": a.basis, "key": a.key,
                 "benign_addresses": a.benign_addresses,
                 "hostile_addresses": [ip for ip in a.addresses
                                       if ip not in a.benign_addresses]}
                for a in self.contaminated
            ],
            "by_service": self.by_service,
            "probes": dict(self.probes.most_common()),
            "credentials": self.credentials,
            "fingerprints": self.fingerprints,
            "actor_detail": [a.to_dict() for a in self.actors],
            "campaign_detail": [c.to_dict() for c in campaign_list],
        }


def analyse(events: list[Event]) -> Report:
    all_sessions = sessions(events)
    return Report(events=events, sessions=all_sessions, actors=actors(all_sessions))
