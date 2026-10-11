"""`vulnops-assets build`: consolidate the detection files of each client into its asset inventory.

Reads <detect>/<client>/*.json, writes <out>/<client>/assets.json and <out>/<client>/findings.json.
The inventory is rebuilt at each run from the observations of that run; history (first seen across
runs, attribute changes) comes with the PostgreSQL storage.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from vulnops.core.io import ExchangeError, detection_files, read_detection, write_assets, write_findings
from vulnops.core.profile import ProfileError, load_profile

from .build import build_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnops-assets", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build the asset inventory of one or more clients")
    b.add_argument("profiles", nargs="+", help="client profile YAML files")
    b.add_argument("--detect", default="work/detect", help="detect stage output directory")
    b.add_argument("--out", default="work/assets")
    args = parser.parse_args(argv)

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
        inv = build_inventory(profile, detections)
        target = Path(args.out) / profile.id
        write_assets(target / "assets.json", profile.id, inv.assets)
        write_findings(target / "findings.json", profile.id, inv.findings, inv.not_affected)
        assumed = Counter(n for a in inv.assets for n, attr in a.attributes.items() if attr.assumed)
        assumed_txt = ", ".join(f"{k}: {v}" for k, v in sorted(assumed.items())) or "none"
        print(
            f"{profile.id}: {len(inv.assets)} assets from {len(detections)} sources, {len(inv.findings)} findings, "
            f"assumed attributes: {assumed_txt} -> {target}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
