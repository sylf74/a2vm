# SPDX-License-Identifier: AGPL-3.0-only
"""`verdict run`: decide on the findings of each client, from the intel and assets stage outputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnops.core.config import describe_llm, load_settings
from vulnops.core.io import ExchangeError, read_assets, read_findings, read_records
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
    r.add_argument("--assets", default="work/assets", help="assets stage output (<client>/assets.json, findings.json)")
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
            base = Path(args.assets) / profile.id
            try:
                a_client, assets = read_assets(base / "assets.json")
                f_client, findings, not_affected = read_findings(base / "findings.json")
            except (ExchangeError, OSError) as exc:
                print(f"{profile.id}: {exc}", file=sys.stderr)
                return 2
            if {a_client, f_client} != {profile.id}:
                print(f"{base}: files of {a_client!r}/{f_client!r}, expected {profile.id!r}", file=sys.stderr)
                return 2
            run = triage.run(profile, records, assets, findings, not_affected, len(requested), errors)
            target = write_all(run, Path(args.out))
            counts = {d: sum(r.delivery_decision == d for r in run.rows) for d in ("ACT", "ATTEND", "TRACK")}
            llm_failures = [r for r in run.rows if r.rationale_source.startswith("template (LLM")]
            print(
                f"{profile.id}: ACT={counts['ACT']} ATTEND={counts['ATTEND']} TRACK={counts['TRACK']} "
                f"review={sum(r.needs_review for r in run.rows)} errors={len(run.errors)} "
                f"llm_calls={triage.llm_calls} llm_fallbacks={len(llm_failures)} -> {target}"
            )
            if triage.llm_stopped:
                print(f"  LLM not used for the rest of the run: {triage.llm_stopped}", file=sys.stderr)
            for row in llm_failures[:20]:
                print(f"  {row.cve_id} {row.asset_id}: {row.rationale_source}", file=sys.stderr)
            if len(llm_failures) > 20:
                print(f"  ... and {len(llm_failures) - 20} more (see triage.csv)", file=sys.stderr)
    finally:
        if llm:
            llm.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
