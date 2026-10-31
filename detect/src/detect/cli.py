# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""detect: produce detection files (asset observations + findings), one per client and source.

  plan       check a targets file and list the scans it would run (no connection)
  collect    run read-only scanners over SSH on the targets of a client, and the OpenVAS network scan
             when the targets file has an `openvas` section, then import their output
  import     import scanner output files produced elsewhere (Trivy JSON, dnf updateinfo text,
             OpenVAS XML report)
  inventory  match a records file against the assets declared in client profiles
  external   bring the latest detection of the client's external project (A2VM_EXTERNAL_PROJECT)
             into this run, as source external-scan
  serve      the detection service: receives the collectors' pushes, serves the latest detections
  agent      the collector: runs its connectors near a network and pushes to the detection service
  fetch      the daily run's first step in the cluster: the latest detections from the service
  collectors check the tenant's declaration of its collectors (collectors.yaml)

Output: <out>/<client>/<source>.json (default work/detect).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from a2vm.config import describe_llm, load_settings
from a2vm.io import Detection, read_records, write_detection
from a2vm.llm import LlmClient
from a2vm.profile import ProfileError, load_profile

from .collect import collect, load_targets, plan
from .external import pull as pull_external
from .inventory import InventoryScanner
from .openvas import load_openvas_file
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
    """Exit 0 when every scan succeeded, 3 when some failed (partial collection), 1 when none did."""
    status = 0
    for path in args.targets:
        tf = load_targets(path)
        ssh_note = "" if not args.no_ssh else " (SSH targets skipped: no key)"
        openvas = f", openvas scan of {', '.join(tf.openvas.hosts)}" if tf.openvas else ""
        print(f"{tf.client}: {len(tf.targets)} SSH targets{ssh_note}{openvas}")
        detections, errors = collect(tf, args.raw, ssh=not args.no_ssh)
        for e in errors:
            print(f"  ERROR {e}", file=sys.stderr)
        for d in detections:
            _write(args.out, d)
        if not detections:
            status = 1
        elif errors and status == 0:
            status = 3
    return status


def cmd_external(args: argparse.Namespace) -> int:
    """Exit 0 when the external detection was added, 3 when it was left out (warning), 2 on configuration error."""
    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(exc, file=sys.stderr)
        return 2
    if profile.external is None:
        print(f"{profile.id}: no `external` section in {args.profile}: external scan not used", file=sys.stderr)
        return 3
    print(
        f"{profile.id}: external detection of {profile.external.client} from {args.project} ({args.job} on {args.ref})",
        flush=True,
    )
    result = pull_external(profile, args.project, ref=args.ref, job=args.job)
    for note in result.notes:
        print(f"  {note}")
    for problem in result.problems:
        print(f"  WARN  {problem}", file=sys.stderr)
    if result.detection is None:
        print(f"{profile.id}: run goes on without the external scan", file=sys.stderr)
        return 3
    _write(args.out, result.detection)
    return 3 if result.problems else 0


def _read_secret(path: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"{path}: {exc}") from exc
    if not value:
        raise SystemExit(f"{path} is empty")
    return value


def cmd_serve(args: argparse.Namespace) -> int:
    import logging

    from .intake.registry import RegistryError, load_registry
    from .intake.server import Service, serve
    from .intake.store import FileStore

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        registry = load_registry(args.tenant, args.collectors, args.digests)
    except (RegistryError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    from a2vm.db import DatabaseError, open_database

    from .intake.pgstore import MIGRATIONS, PgStore

    try:
        db = open_database("detect", MIGRATIONS)
        if db is None:
            Path(args.store).mkdir(parents=True, exist_ok=True)  # a new volume: /readyz waits for it
    except (OSError, DatabaseError) as exc:
        print(f"store: {exc}", file=sys.stderr)
        return 2
    store = PgStore(db, args.keep) if db else FileStore(args.store, args.keep)
    readers = "set" if "read" in registry.tokens else "MISSING"
    print(
        f"{registry.tenant}: {len(registry.collectors)} collector(s) declared "
        f"({', '.join(registry.collectors) or 'none'}), read token {readers}, store {store.describe()}",
        flush=True,
    )
    service = Service(registry, store, args.max_mb * 1024 * 1024)
    httpd = serve(service, args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from .agent import AgentError, load_config, run

    try:
        cfg = load_config(args.config)
        report = run(cfg, args.connector)
    except AgentError as exc:
        print(exc, file=sys.stderr)
        return 2
    for line in report.pushed:
        print(f"{cfg.tenant} [{cfg.collector}]: pushed {line}")
    for line in report.spooled:
        print(f"  WARN  kept for the next run: {line}", file=sys.stderr)
    for line in report.errors:
        print(f"  ERROR {line}", file=sys.stderr)
    return report.status


def cmd_collectors(args: argparse.Namespace) -> int:
    from .intake.registry import RegistryError, load_collectors

    try:
        collectors = load_collectors(args.tenant, args.collectors)
    except (RegistryError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    if not collectors:
        print(f"{args.collectors}: no collector declared", file=sys.stderr)
        return 2
    if args.profile:
        try:
            client = load_profile(args.profile).id
        except ProfileError as exc:
            print(exc, file=sys.stderr)
            return 2
        if client != args.tenant:
            # The push names the tenant in its path and the client in its body: both must agree.
            print(f"{args.profile}: client {client!r} is not the tenant {args.tenant!r}", file=sys.stderr)
            return 2
    for c in collectors.values():
        variable = "A2VM_COLLECTOR_TOKEN_" + c.id.upper().replace("-", "_")
        print(f"{args.tenant}: collector {c.id} ({', '.join(c.sources)}, max {c.max_age_hours:g} h), token {variable}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    """Exit 0 when every expected source was written, 3 when some were left out (warning), 1 when none
    was (the run stops rather than report an estate without its scanners)."""
    from .intake.client import IntakeError, fetch
    from .intake.registry import RegistryError, load_collectors

    sources: list[str] = list(args.source)
    max_age: float | dict[str, float] = args.max_age_hours
    if args.collectors:
        try:
            collectors = load_collectors(args.tenant, args.collectors)
        except (RegistryError, OSError) as exc:
            print(exc, file=sys.stderr)
            return 2
        ages: dict[str, float] = {}
        for c in collectors.values():
            for s in c.sources:
                ages[s] = max(ages.get(s, 0.0), c.max_age_hours)
        sources = sources or sorted(ages)
        max_age = ages
    token = _read_secret(args.token_file)
    try:
        result = fetch(
            args.url, args.tenant, token, args.out, sources, max_age, args.ca_file, timeout=args.timeout_seconds
        )
    except IntakeError as exc:
        print(f"{args.tenant}: {exc}", file=sys.stderr)
        return 1
    for path in result.written:
        print(f"{args.tenant}: {path.stem} from the detection service -> {path}")
    for problem in result.problems:
        print(f"  WARN  {problem}", file=sys.stderr)
    if not result.written:
        print(f"{args.tenant}: no detection received from the collectors", file=sys.stderr)
        return 1
    return 3 if result.problems else 0


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
    if tf.openvas:
        o = tf.openvas
        excl = f", except {', '.join(o.exclude)}" if o.exclude else ""
        limits = f"QoD >= {o.min_qod}, max {o.timeout_minutes} min, reuse < {o.reuse_hours:g} h"
        print(f"  openvas via {o.gmp}: {', '.join(o.hosts)}{excl} ({limits})")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    if args.source == "openvas":
        _write(args.out, merge([load_openvas_file(f, args.client, args.min_qod) for f in args.files]))
        return 0
    loader = load_trivy_file if args.source == "trivy" else load_dnf_file
    _write(args.out, merge([loader(f, args.client) for f in args.files]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="detect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
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
    c.add_argument("--no-ssh", action="store_true", help="skip the SSH targets (OpenVAS only)")
    c.set_defaults(func=cmd_collect)

    e = sub.add_parser("external", help="add the latest detection of the client's external project")
    e.add_argument("profile", help="client.yaml (its `external` section names the external client)")
    e.add_argument("--project", required=True, help="external GitLab project, path or id (A2VM_EXTERNAL_PROJECT)")
    e.add_argument("--ref", default="main")
    e.add_argument("--job", default="collect", help="job of the external project that keeps work/detect/")
    e.add_argument("--out", default="work/detect")
    e.set_defaults(func=cmd_external)
    m = sub.add_parser("import", help="import scanner output files (one file per host or image)")
    m.add_argument("--client", required=True)
    m.add_argument("--source", required=True, choices=["trivy", "dnf-updateinfo", "openvas"])
    m.add_argument(
        "files",
        nargs="+",
        help="<host>.json (Trivy) or <host>.txt (dnf): the file name is the host; OpenVAS XML report",
    )
    m.add_argument("--min-qod", type=int, default=70, help="OpenVAS: minimum quality of detection (default 70)")
    m.add_argument("--out", default="work/detect")
    m.set_defaults(func=cmd_import)

    sv = sub.add_parser("serve", help="the detection service (one tenant)")
    sv.add_argument("--tenant", required=True)
    sv.add_argument("--collectors", required=True, help="the tenant's collectors.yaml")
    sv.add_argument("--digests", required=True, help="`<collector id|read> <sha256>` per line")
    sv.add_argument("--store", default="/data/detections")
    sv.add_argument("--keep", type=int, default=14, help="detections kept per source")
    sv.add_argument("--max-mb", type=int, default=200, help="largest detection accepted, uncompressed")
    sv.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a pod
    sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(func=cmd_serve)

    ag = sub.add_parser("agent", help="the collector: run connectors and push to the detection service")
    ag_sub = ag.add_subparsers(dest="agent_command", required=True)
    ar = ag_sub.add_parser("run", help="run the connectors (or one) and push their detections")
    ar.add_argument("--config", default="/etc/a2vm/collector/collector.yaml")
    ar.add_argument("--connector", help="only this connector")
    ar.set_defaults(func=cmd_agent)

    f = sub.add_parser("fetch", help="the latest detections of the tenant from the detection service")
    f.add_argument("--url", required=True, help="detection service, e.g. http://a2vm-homelab-detect:8080")
    f.add_argument("--tenant", required=True)
    f.add_argument("--token-file", required=True, help="the daily run's read token")
    f.add_argument("--source", action="append", default=[], help="expected source (repeat); default: all")
    f.add_argument("--max-age-hours", type=float, default=30, help="without --collectors")
    f.add_argument("--collectors", help="the tenant's collectors.yaml: expected sources and their max age")
    f.add_argument("--ca-file")
    f.add_argument("--timeout-seconds", type=float, default=600, help="wait for the service's answer")
    f.add_argument("--out", default="work/detect")
    f.set_defaults(func=cmd_fetch)

    cl = sub.add_parser("collectors", help="check the tenant's declaration of its collectors")
    cl.add_argument("collectors", help="collectors.yaml")
    cl.add_argument("--tenant", required=True, help="tenant id (the deploy job uses the project name)")
    cl.add_argument("--profile", help="client.yaml: its client id must be the tenant id")
    cl.set_defaults(func=cmd_collectors)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
