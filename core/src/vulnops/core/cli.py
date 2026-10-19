# SPDX-License-Identifier: LicenseRef-vulnops-proprietary
"""`vulnops-profiles validate client.yaml ...`: check client profiles against their schema."""

from __future__ import annotations

import argparse
import sys

from .profile import ProfileError, load_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnops-profiles", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate client profiles against the schema")
    v.add_argument("profiles", nargs="+")
    args = parser.parse_args(argv)

    failed = 0
    for path in args.profiles:
        try:
            profile = load_profile(path)
            print(f"OK    {path} ({profile.id}, {len(profile.assets)} assets)")
            for warning in profile.warnings:
                print(f"WARN  {path}: {warning}")
        except (ProfileError, OSError) as exc:
            failed += 1
            print(f"FAIL  {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
