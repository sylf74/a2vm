"""`vulnops-detect inventory`: findings from client profiles x a records file, one file per client."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnops.core.config import describe_llm, load_settings
from vulnops.core.io import read_records, write_findings
from vulnops.core.llm import LlmClient
from vulnops.core.profile import ProfileError, load_profile

from .inventory import InventoryScanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnops-detect", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    i = sub.add_parser("inventory", help="match a records file against declared client inventories")
    i.add_argument("profiles", nargs="+", help="client profile YAML files")
    i.add_argument("--settings", default="config/settings.yaml")
    i.add_argument("--records", default="work/records.json")
    i.add_argument("--out", default="work/findings", help="directory; one <client>.json per client")
    i.add_argument("--no-llm", action="store_true", help="no LLM adjudication of fuzzy product matches")
    args = parser.parse_args(argv)

    settings = load_settings(args.settings)
    if args.no_llm:
        settings.llm.enabled = False
    print(describe_llm(settings))
    try:
        profiles = [load_profile(p) for p in args.profiles]
    except ProfileError as exc:
        print(exc, file=sys.stderr)
        return 2
    requested, records, _ = read_records(args.records)
    ordered = [records[c] for c in requested if c in records]

    llm = LlmClient(settings.llm) if settings.llm.enabled else None
    try:
        scanner = InventoryScanner(settings, llm)
        for profile in profiles:
            result = scanner.scan(profile, ordered)
            path = write_findings(
                Path(args.out) / f"{profile.id}.json", profile.id, result.findings, result.not_affected
            )
            print(
                f"{profile.id}: {len(result.findings)} findings, "
                f"{len(result.not_affected)} not affected (version) -> {path}"
            )
    finally:
        if llm:
            llm.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
