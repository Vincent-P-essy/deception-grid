#!/usr/bin/env python3
"""Regenerate every number this repository publishes.

Run it and diff `results/expected.json`. Nothing in the README is typed by
hand: the capture is produced by starting the real listeners on ephemeral
ports, connecting to them over real sockets, and reading the events back out of
the log. If a figure in the README and a figure here disagree, the README is
wrong.

    python scripts/reproduce.py           # rewrite results/expected.json
    python scripts/reproduce.py --check   # fail if anything drifted
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from decoy.analyse import analyse  # noqa: E402
from decoy.event import dump  # noqa: E402
from decoy.intel import to_misp, to_stix  # noqa: E402
from decoy.selftest import capture  # noqa: E402

CAPTURE = ROOT / "captures" / "reference.jsonl"
STIX = ROOT / "results" / "bundle.stix.json"
MISP = ROOT / "results" / "event.misp.json"
EXPECTED = ROOT / "results" / "expected.json"


def _round(value: float) -> float:
    return round(value, 4)


def build() -> dict:
    events = capture()
    dump(events, CAPTURE)
    report = analyse(events)

    bundle = to_stix(report)
    STIX.parent.mkdir(parents=True, exist_ok=True)
    STIX.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    MISP.write_text(json.dumps(to_misp(report), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    linked = [c for c in report.campaigns if c.is_linked]
    multi_homed = [a for a in report.hostile if a.multi_homed]

    return {
        "capture": {
            "events": len(events),
            "sessions": len(report.sessions),
            "by_service": report.by_service,
        },
        "identities": {
            "total": len(report.actors),
            "exportable": len(report.hostile),
            "allowlisted": len(report.benign_actors),
            "contaminated": len(report.contaminated),
            "multi_homed": len(multi_homed),
            "by_basis": {
                basis: sum(1 for a in report.actors if a.basis == basis)
                for basis in sorted({a.basis for a in report.actors})
            },
        },
        "campaigns": {
            "total": len(report.campaigns),
            "linked": len(linked),
            "largest_address_count": max((len(c.addresses) for c in linked), default=0),
            "largest_service_count": max((len(c.services) for c in linked), default=0),
        },
        "noise": {
            "benign_share": _round(report.benign_share),
            "benign_events": sum(1 for e in events if e.is_benign),
        },
        "intelligence": {
            "fingerprints": len(report.fingerprints),
            "rotating_banners": sum(1 for v in report.fingerprints.values() if len(v) > 1),
            "access_keys": sorted(report.credentials),
            "probe_types": len(report.probes),
        },
        "export": {
            "stix_objects": len(bundle["objects"]),
            "indicators": len(indicators),
            "confidences": sorted({o["confidence"] for o in indicators}),
            "benign_actors_excluded": bundle["x_deception_grid"]["benign_actors_excluded"],
            "contaminated_actors_excluded":
                bundle["x_deception_grid"]["contaminated_actors_excluded"],
            "misp_attributes": len(to_misp(report)["Event"]["Attribute"]),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the results differ from results/expected.json")
    args = parser.parse_args()

    results = build()
    rendered = json.dumps(results, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not EXPECTED.exists():
            print(f"{EXPECTED} does not exist; run without --check first")
            return 1
        recorded = EXPECTED.read_text(encoding="utf-8")
        if recorded != rendered:
            print("results drifted from results/expected.json\n")
            print("--- recorded\n" + recorded)
            print("+++ produced\n" + rendered)
            return 1
        print(f"results match {EXPECTED.relative_to(ROOT)}")
        return 0

    EXPECTED.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED.write_text(rendered, encoding="utf-8")
    print(rendered)
    print(f"wrote {EXPECTED.relative_to(ROOT)}, {CAPTURE.relative_to(ROOT)}, "
          f"{STIX.relative_to(ROOT)}, {MISP.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
