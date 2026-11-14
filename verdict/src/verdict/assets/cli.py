# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""`verdict assets build`: consolidate the detection files of each client into its asset inventory.

Reads <detect>/<client>/*.json, writes <out>/<client>/assets.json, findings.json, exposure_gaps.json,
coverage.json (scan coverage, v0.19.0), asset_graph.json (how the assets are reached, v0.24.0) and
flows_proposed.yaml (the flows the scanners observed, as a `flows:` section to review).
`--previous` names the assets directory of the run before: its sightings off the premises still count.
The inventory is rebuilt at each run from the observations of that run; history (first seen across
runs, attribute changes) comes with the PostgreSQL storage.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from ngvm.io import ExchangeError, detection_files, read_detection, write_assets, write_findings
from ngvm.profile import ProfileError, load_profile

from .build import build_inventory
from .coverage import GAPS, build_coverage, write_coverage
from .gaps import write_gaps
from .graph import proposed_flows, read_graph, write_graph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verdict assets", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build the asset inventory of one or more clients")
    b.add_argument("profiles", nargs="+", help="client profile YAML files")
    b.add_argument("--detect", default="work/detect", help="detect stage output directory")
    b.add_argument("--out", default="work/assets")
    b.add_argument("--previous", help="assets directory of the run before (v0.24.0), e.g. the same as --out")
    f = sub.add_parser("flows", help="the flows the scanners observed, as a `flows:` section to review (v0.24.0)")
    f.add_argument("assets", help="assets directory of one client, e.g. work/assets/<client>")
    args = parser.parse_args(argv)
    if args.command == "flows":
        return _flows(Path(args.assets))

    for path in args.profiles:
        try:
            profile = load_profile(path)
            detections = [read_detection(f) for f in detection_files(args.detect, profile.id)]
        except (ProfileError, ExchangeError, OSError) as exc:
            print(exc, file=sys.stderr)
            return 2
        if not detections:
            print(f"{profile.id}: no detection file in {args.detect}/{profile.id}/", file=sys.stderr)
            return 2
        try:
            previous = (
                read_graph(Path(args.previous) / profile.id / "asset_graph.json", profile.id) if args.previous else None
            )
        except (OSError, ValueError) as exc:  # the run goes on without the sightings of the run before
            print(f"  WARN  previous asset graph not read: {exc}", file=sys.stderr)
            previous = None
        inv = build_inventory(profile, detections, previous)
        target = Path(args.out) / profile.id
        write_assets(target / "assets.json", profile.id, inv.assets)
        write_findings(target / "findings.json", profile.id, inv.findings, inv.not_affected)
        write_gaps(target / "exposure_gaps.json", profile.id, inv.exposure_gaps)
        coverage = build_coverage(profile.id, inv.assets, profile.coverage)
        write_coverage(target / "coverage.json", profile.id, coverage)
        if inv.graph is not None:
            write_graph(target / "asset_graph.json", inv.graph)
            (target / "flows_proposed.yaml").write_text(proposed_flows(inv.graph), encoding="utf-8")
        for g in inv.exposure_gaps:
            print(f"  WARN  exposure gap ({g['kind']}): {g['name']}: {g['detail']}")
        assumed = Counter(n for a in inv.assets for n, attr in a.attributes.items() if attr.assumed)
        assumed_txt = ", ".join(f"{k}: {v}" for k, v in sorted(assumed.items())) or "none"
        print(
            f"{profile.id}: {len(inv.assets)} assets from {len(detections)} sources, {len(inv.findings)} findings, "
            f"assumed attributes: {assumed_txt} -> {target}"
        )
        print(f"{profile.id}: {_summary(inv)}")
        gaps = {s: n for s, n in coverage["counts"].items() if n and s in GAPS}
        share = coverage["covered_share"]
        print(
            f"{profile.id}: coverage {'with' if coverage['cmdb'] else 'without'} CMDB, "
            f"{coverage['counts']['covered']}/{coverage['expected_assets']} covered"
            f"{f' ({share:.0%})' if share is not None else ''}, "
            f"gaps: {', '.join(f'{s}: {n}' for s, n in gaps.items()) or 'none'}"
        )
    return 0


def _summary(inv) -> str:  # noqa: ANN001 - Inventory
    """How the exposures were set: computed from the graph, observed, declared, assumed."""
    sources = Counter(a.attributes["exposure"].source for a in inv.assets)
    flows = inv.graph.observed_flows if inv.graph else []
    undeclared = sum(1 for f in flows if not f["declared"])
    parts = ", ".join(f"{k}: {v}" for k, v in sorted(sources.items()))
    return f"exposure from {parts}; {len(flows)} flows observed between zones, {undeclared} not declared"


def _flows(directory: Path) -> int:
    graph_file = directory / "asset_graph.json"
    if not graph_file.exists():
        print(f"{graph_file}: no asset graph (assets built before v0.24.0?)", file=sys.stderr)
        return 2
    client = directory.name
    try:
        graph = read_graph(graph_file, client)
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2
    print(proposed_flows(graph), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
