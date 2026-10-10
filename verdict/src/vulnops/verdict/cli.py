"""`verdict run`: decide on the findings of each client, from the intel and detect stage outputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnops.core.config import describe_llm, load_settings
from vulnops.core.io import ExchangeError, read_findings, read_records
from vulnops.core.llm import LlmClient
from vulnops.core.profile import ProfileError, load_profile

from .report import write_all
from .triage import Triage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verdict", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="triage the findings of one or more clients")
    r.add_argument("profiles", nargs="+", help="client profile YAML files")
    r.add_argument("--settings", default="config/settings.yaml")
    r.add_argument("--records", default="work/records.json", help="intel stage output")
    r.add_argument("--findings", default="work/findings", help="detect stage output directory (<client>.json)")
    r.add_argument("--out", default="output")
    r.add_argument("--no-llm", action="store_true", help="deterministic run, template rationales")
    args = parser.parse_args(argv)

    settings = load_settings(args.settings)
    if args.no_llm:
        settings.llm.enabled = False
    print(describe_llm(settings))
    try:
        profiles = [load_profile(p) for p in args.profiles]
        requested, records, errors = read_records(args.records)
    except (ProfileError, ExchangeError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2

    llm = LlmClient(settings.llm) if settings.llm.enabled else None
    try:
        triage = Triage(settings, llm)
        for profile in profiles:
            path = Path(args.findings) / f"{profile.id}.json"
            try:
                client_id, findings, not_affected = read_findings(path)
            except (ExchangeError, OSError) as exc:
                print(f"{profile.id}: {exc}", file=sys.stderr)
                return 2
            if client_id != profile.id:
                print(f"{path}: findings of {client_id!r}, expected {profile.id!r}", file=sys.stderr)
                return 2
            run = triage.run(profile, records, findings, not_affected, len(requested), errors)
            target = write_all(run, Path(args.out))
            counts = {d: sum(r.delivery_decision == d for r in run.rows) for d in ("ACT", "ATTEND", "TRACK")}
            llm_failures = sum(r.rationale_source.startswith("template (LLM") for r in run.rows)
            print(
                f"{profile.id}: ACT={counts['ACT']} ATTEND={counts['ATTEND']} TRACK={counts['TRACK']} "
                f"review={sum(r.needs_review for r in run.rows)} errors={len(run.errors)} "
                f"llm_fallbacks={llm_failures} -> {target}"
            )
            for row in run.rows:
                if row.rationale_source.startswith("template (LLM"):
                    print(f"  {row.cve_id} {row.asset_id}: {row.rationale_source}", file=sys.stderr)
    finally:
        if llm:
            llm.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
