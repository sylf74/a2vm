"""Command line: `cve-triage validate` and `cve-triage run`."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from .config import load_settings
from .llm import LlmClient
from .pipeline import Triage, collect_cve_ids
from .profile import ProfileError, load_profile
from .report import write_all
from .sources import Sources


def _since(value: str) -> dt.datetime:
    if value.endswith("h") and value[:-1].isdigit():
        return dt.datetime.now(dt.UTC) - dt.timedelta(hours=int(value[:-1]))
    if value.endswith("d") and value[:-1].isdigit():
        return dt.datetime.now(dt.UTC) - dt.timedelta(days=int(value[:-1]))
    parsed = dt.datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def cmd_validate(args: argparse.Namespace) -> int:
    failed = 0
    for path in args.profiles:
        try:
            profile = load_profile(path)
            print(f"OK    {path} ({profile.id}, {len(profile.assets)} assets)")
        except (ProfileError, OSError) as exc:
            failed += 1
            print(f"FAIL  {exc}", file=sys.stderr)
    return 1 if failed else 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = load_settings(args.settings)
    if args.no_llm:
        settings.llm.enabled = False
    try:
        profiles = [load_profile(p) for p in args.profiles]
    except ProfileError as exc:
        print(exc, file=sys.stderr)
        return 2

    sources = Sources(settings.sources, fixtures_dir=args.fixtures)
    llm = LlmClient(settings.llm) if settings.llm.enabled else None
    try:
        explicit = list(args.cve or [])
        if args.cve_file:
            text = Path(args.cve_file).read_text(encoding="utf-8")
            explicit += [line.split("#")[0].strip() for line in text.splitlines() if line.split("#")[0].strip()]
        since = _since(args.since) if args.since else None
        cve_ids = collect_cve_ids(sources, explicit, since, args.include_updated)
        if not cve_ids:
            print("no CVE to triage (use --cve, --cve-file or --since)", file=sys.stderr)
            return 2
        print(f"{len(cve_ids)} CVE to triage for {len(profiles)} client(s)")
        epss = sources.epss(cve_ids)
        triage = Triage(settings, sources, llm)
        for profile in profiles:
            run = triage.run(profile, cve_ids, epss)
            target = write_all(run, Path(args.out))
            counts = {d: sum(r.delivery_decision == d for r in run.rows) for d in ("ACT", "ATTEND", "TRACK")}
            print(
                f"{profile.id}: ACT={counts['ACT']} ATTEND={counts['ATTEND']} TRACK={counts['TRACK']} "
                f"review={sum(r.needs_review for r in run.rows)} errors={len(run.errors)} -> {target}"
            )
    finally:
        sources.close()
        if llm:
            llm.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cve-triage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="validate client profiles against the schema")
    v.add_argument("profiles", nargs="+")
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("run", help="triage CVEs for one or more clients")
    r.add_argument("profiles", nargs="+", help="client profile YAML files")
    r.add_argument("--settings", default="config/settings.yaml")
    r.add_argument("--cve", action="append", help="CVE id (repeatable)")
    r.add_argument("--cve-file", help="file with one CVE id per line (e.g. the daily watch export)")
    r.add_argument("--since", help="CVEs published since: ISO date/time, or 24h / 2d")
    r.add_argument("--include-updated", action="store_true", help="with --since, also updated CVE records")
    r.add_argument("--out", default="output")
    r.add_argument("--fixtures", help="read sources from a local fixtures directory (no network)")
    r.add_argument("--no-llm", action="store_true", help="deterministic run, template rationales")
    r.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
