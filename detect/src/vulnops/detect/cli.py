"""vulnops-detect: produce detection files (asset observations + findings), one per client and source.

  plan       check a targets file and list the scans it would run (no connection)
  collect    run read-only scanners over SSH on the targets of a client, then import their output
  import     import scanner output files produced elsewhere (Trivy JSON, dnf updateinfo text)
  inventory  match a records file against the assets declared in client profiles

Output: <out>/<client>/<source>.json (default work/detect).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnops.core.config import describe_llm, load_settings
from vulnops.core.io import Detection, read_records, write_detection
from vulnops.core.llm import LlmClient
from vulnops.core.profile import ProfileError, load_profile

from .collect import collect, load_targets, plan
from .inventory import InventoryScanner
from .scanners import load_dnf_file, load_trivy_file, merge


def _write(out: str, d: Detection) -> None:
    path = write_detection(Path(out) / d.client_id / f"{d.source}.json", d)
    skipped = ", ".join(f"{k}: {v}" for k, v in sorted(d.skipped.items())) or "none"
    print(
        f"{d.client_id} [{d.source}]: {len(d.observations)} assets observed, {len(d.findings)} findings, "
        f"{len(d.not_affected)} not affected, skipped: {skipped} -> {path}"
    )


def cmd_inventory(args: argparse.Namespace) -> int:
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
            _write(args.out, scanner.scan(profile, ordered))
    finally:
        if llm:
            llm.close()
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    failed = 0
    for path in args.targets:
        tf = load_targets(path)
        print(f"{tf.client}: {len(tf.targets)} targets")
        detections, errors = collect(tf, args.raw)
        for e in errors:
            print(f"  ERROR {e}", file=sys.stderr)
        for d in detections:
            _write(args.out, d)
        if not detections:
            failed += 1
    return 1 if failed else 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        tf = load_targets(args.targets)
        client = load_profile(args.profile).id if args.profile else None
    except (ValueError, ProfileError, TypeError) as exc:
        print(f"{args.targets}: {exc}", file=sys.stderr)
        return 2
    if client and client != tf.client:
        print(f"{args.targets}: client {tf.client!r} does not match profile {client!r}", file=sys.stderr)
        return 2
    jobs = plan(tf)
    print(f"{tf.client}: {len(tf.targets)} targets, {len(jobs)} scans, ssh user {tf.user or '(default)'}")
    for t, method, _remote, target in jobs:
        print(f"  {t.host:<32} {method:<15} {target.kind}:{target.ref}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    loader = load_trivy_file if args.source == "trivy" else load_dnf_file
    _write(args.out, merge([loader(f, args.client) for f in args.files]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnops-detect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    i = sub.add_parser("inventory", help="match a records file against declared client inventories")
    i.add_argument("profiles", nargs="+", help="client profile YAML files")
    i.add_argument("--settings", default="config/settings.yaml")
    i.add_argument("--records", default="work/records.json")
    i.add_argument("--out", default="work/detect")
    i.add_argument("--no-llm", action="store_true", help="no LLM adjudication of fuzzy product matches")
    i.set_defaults(func=cmd_inventory)

    pl = sub.add_parser("plan", help="check a targets file and list the scans (no connection)")
    pl.add_argument("targets", help="targets YAML file")
    pl.add_argument("--profile", help="client profile: check that both name the same client")
    pl.set_defaults(func=cmd_plan)

    c = sub.add_parser("collect", help="run read-only scans over SSH (targets file per client)")
    c.add_argument("targets", nargs="+", help="targets YAML files, e.g. examples/lab/targets.yaml")
    c.add_argument("--raw", default="work/scans", help="where raw scanner outputs are kept")
    c.add_argument("--out", default="work/detect")
    c.set_defaults(func=cmd_collect)

    m = sub.add_parser("import", help="import scanner output files (one file per host or image)")
    m.add_argument("--client", required=True)
    m.add_argument("--source", required=True, choices=["trivy", "dnf-updateinfo"])
    m.add_argument("files", nargs="+", help="<host>.json (Trivy) or <host>.txt (dnf): the file name is the host")
    m.add_argument("--out", default="work/detect")
    m.set_defaults(func=cmd_import)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
