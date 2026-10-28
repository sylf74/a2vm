# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`verdict`: pillar 3 commands.

verdict assets build …   consolidate the detection files of each client into its asset inventory
verdict run …            decide on the findings of each client, from the records and the asset inventory
verdict publish …        load reporting datasets into the reporting database (restitution)
verdict db …             administer the reporting database: `verdict db -h`
verdict grafana …        Grafana dashboards reading the reporting database: `verdict grafana -h`
verdict serve …          the decision service of one tenant: read API on its latest runs
verdict push …           push a run's triage to the decision service
verdict tools …          tool server of the conversational search, on the decision service
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from a2vm.config import describe_llm, load_settings
from a2vm.io import ExchangeError, read_assets, read_findings, read_records
from a2vm.llm import LlmClient
from a2vm.profile import ProfileError, load_profile

from .assets.gaps import read_gaps
from .report import write_all
from .triage import Triage

RESTITUTION = {"publish", "db", "grafana"}
SERVICE = {"serve", "push", "tools"}


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    if args_in[:1] == ["assets"]:
        from .assets.cli import main as assets_main

        return assets_main(args_in[1:])
    if args_in[:1] and args_in[0] in RESTITUTION:
        from .restitution.cli import main as restitution_main

        return restitution_main(args_in)
    if args_in[:1] and args_in[0] in SERVICE:
        from .service.cli import main as service_main

        return service_main(args_in)
    parser = argparse.ArgumentParser(
        prog="verdict", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("assets", help="asset inventory: `verdict assets build -h`", add_help=False)
    for name, text in (
        ("publish", "load reporting datasets into the reporting database"),
        ("db", "administer the reporting database"),
        ("grafana", "Grafana dashboards"),
        ("serve", "the decision service of one tenant"),
        ("push", "push a run's triage to the decision service"),
        ("tools", "tool server of the conversational search"),
    ):
        sub.add_parser(name, help=f"{text}: `verdict {name} -h`", add_help=False)  # fmt: skip
    r = sub.add_parser("run", help="triage the findings of one or more clients")
    r.add_argument("profiles", nargs="+", help="client profile YAML files")
    r.add_argument("--settings", default="config/settings.yaml")
    r.add_argument("--records", default="work/records.json", help="records file (via collect)")
    r.add_argument(
        "--assets",
        default="work/assets",
        help="asset inventory (verdict assets build): <client>/assets.json, findings.json",
    )
    r.add_argument("--out", default="output")
    r.add_argument("--no-llm", action="store_true", help="deterministic run, template rationales")
    args = parser.parse_args(args_in)

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
            try:
                run.exposure_gaps = read_gaps(base / "exposure_gaps.json", profile.id)
            except (ValueError, OSError) as exc:
                print(f"{profile.id}: {exc}", file=sys.stderr)
                return 2
            target = write_all(run, Path(args.out), settings.policy)
            counts = {d: sum(r.delivery_decision == d for r in run.rows) for d in ("ACT", "ATTEND", "TRACK")}
            llm_failures = [r for r in run.rows if r.rationale_source.startswith("template (LLM")]
            print(
                f"{profile.id}: ACT={counts['ACT']} ATTEND={counts['ATTEND']} TRACK={counts['TRACK']} "
                f"review={sum(r.needs_review for r in run.rows)} errors={len(run.errors)} ignored={len(run.ignored)} "
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
