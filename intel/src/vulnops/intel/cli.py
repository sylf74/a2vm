"""`vulnops-intel collect`: fetch and normalise vulnerability records into a records file."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from vulnops.core.config import load_settings
from vulnops.core.io import detection_files, read_detection, write_records

from .collect import collect, select_cve_ids
from .sources import Sources


def parse_since(value: str) -> dt.datetime:
    if value.endswith("h") and value[:-1].isdigit():
        return dt.datetime.now(dt.UTC) - dt.timedelta(hours=int(value[:-1]))
    if value.endswith("d") and value[:-1].isdigit():
        return dt.datetime.now(dt.UTC) - dt.timedelta(days=int(value[:-1]))
    parsed = dt.datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def read_cve_file(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.split("#")[0].strip() for line in text.splitlines() if line.split("#")[0].strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnops-intel", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect", help="build a records file for a set of CVEs")
    c.add_argument("--settings", default="config/settings.yaml")
    c.add_argument("--cve", action="append", help="CVE id (repeatable)")
    c.add_argument("--cve-file", help="file with one CVE id per line (e.g. the daily watch export)")
    c.add_argument("--since", help="CVEs published since: ISO date/time, or 24h / 2d (+ KEV additions)")
    c.add_argument("--include-updated", action="store_true", help="with --since, also updated CVE records")
    c.add_argument(
        "--detect",
        help="detect stage output directory: also collect every CVE found by scanners (work/detect)",
    )
    c.add_argument("--fixtures", help="read sources from a local fixtures directory (no network)")
    c.add_argument("--out", default="work/records.json")
    args = parser.parse_args(argv)

    settings = load_settings(args.settings)
    sources = Sources(settings.sources, fixtures_dir=args.fixtures)
    try:
        explicit = list(args.cve or []) + (read_cve_file(args.cve_file) if args.cve_file else [])
        if args.detect:
            found = sorted({f.cve_id for p in detection_files(args.detect) for f in read_detection(p).findings})
            print(f"{len(found)} CVE found by scanners in {args.detect}")
            explicit += found
        since = parse_since(args.since) if args.since else None
        cve_ids = select_cve_ids(sources, explicit, since, args.include_updated)
        if not cve_ids:
            print("no CVE selected (use --cve, --cve-file or --since)", file=sys.stderr)
            return 2
        result = collect(sources, cve_ids)
    finally:
        sources.close()
    path = write_records(args.out, result.records, result.requested, result.errors)
    print(
        f"{len(result.requested)} CVE requested, {len(result.records)} records, {len(result.errors)} errors -> {path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
