# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`a2vm validate client.yaml ...`: check client profiles against their schema, and the client
project's pipeline file: the template included and the code fetched must be the same version."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

from .config import env
from .profile import ProfileError, load_profile


class _CiLoader(yaml.SafeLoader):
    """Reads .gitlab-ci.yml whatever GitLab tags it uses (!reference …)."""


_CiLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def check_ci(path: str | Path, environ=None) -> list[str]:
    """Problems of the pipeline file: the include `ref:` of the A2VM project must equal A2VM_REF."""
    environ = os.environ if environ is None else environ
    data = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_CiLoader) or {}
    project = env("PROJECT", "vulnops/a2vm", environ=environ)
    includes = data.get("include") or []
    includes = [includes] if isinstance(includes, dict) else includes
    refs = [i.get("ref") for i in includes if isinstance(i, dict) and i.get("project") == project]
    if not refs:
        return []  # not a client project of this A2VM (or the template included otherwise)
    variables = data.get("variables") or {}
    declared = variables.get("A2VM_REF") or variables.get("VULNOPS_REF")
    if isinstance(declared, dict):
        declared = declared.get("value")
    running = env("REF", "", environ=environ) or declared
    problems = []
    for ref in refs:
        if ref is None:
            problems.append(f"{path}: include of {project} without `ref:` (the default branch moves under you)")
        elif running and str(ref) != str(running):
            problems.append(
                f"{path}: include ref {ref} but A2VM_REF {running}: the pipeline template and the code "
                "would come from two versions; set both to the same tag"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="a2vm", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate client profiles against the schema")
    v.add_argument("profiles", nargs="+")
    v.add_argument("--ci", default=".gitlab-ci.yml", help="client project pipeline file, checked when present")
    args = parser.parse_args(argv)

    failed = 0
    if args.ci and Path(args.ci).exists():
        try:
            problems = check_ci(args.ci)
        except yaml.YAMLError as exc:
            problems = [f"{args.ci}: not readable YAML: {exc}"]
        for p in problems:
            failed += 1
            print(f"FAIL  {p}", file=sys.stderr)
        if not problems:
            print(f"OK    {args.ci} (A2VM include ref and A2VM_REF agree)")
    for path in args.profiles:
        try:
            profile = load_profile(path)
            print(f"OK    {path} ({profile.id}, {len(profile.assets)} assets)")
            if profile.external:
                print(
                    f"      external scan: {profile.external.client} (max {profile.external.max_age_days} days), "
                    f"{len(profile.published)} published endpoint(s)"
                )
            for warning in profile.warnings:
                print(f"WARN  {path}: {warning}")
        except (ProfileError, OSError) as exc:
            failed += 1
            print(f"FAIL  {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
