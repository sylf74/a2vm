# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Secrets of the detection service of one tenant, made by the job deploy-k8s (LLD detection §8.3).

  python3 intake_secrets.py collectors.yaml --out DIR [--read-token FILE]

For each collector declared in collectors.yaml, the CI/CD variable A2VM_COLLECTOR_TOKEN_<ID> (id in
upper case, dashes as underscores; masked, text or File) holds its token, and
A2VM_COLLECTOR_TOKEN_<ID>_NEXT a second one during a rotation. Writes, in DIR (mode 0600):

  digests             `<collector id> <sha256>` per token and `read <sha256>`: the service keeps
                      only these
  detect-read-token   the token of the daily run (kept from FILE when given and not empty, so a
                      redeployment does not change it; otherwise a new random one)

Prints, per collector, whether its token is set, never a value. Standard library and PyYAML only:
it runs in the deploy job, without the A2VM packages. The same digest as detect.intake.registry.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

import yaml

ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]{32,512}$")


def variable(collector_id: str) -> str:
    return "A2VM_COLLECTOR_TOKEN_" + collector_id.upper().replace("-", "_")


def digest(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _value(name: str) -> str | None:
    """A CI/CD variable: its text, or the content of the file a File variable points to."""
    raw = os.environ.get(name, "")
    if not raw:
        return None
    path = Path(raw)
    try:
        if len(raw) < 4096 and path.is_file():
            raw = path.read_text(encoding="utf-8")
    except OSError:
        pass
    return raw.strip() or None


def collector_ids(collectors_file: Path) -> list[str]:
    data = yaml.safe_load(collectors_file.read_text(encoding="utf-8")) or {}
    entries = data.get("collectors") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{collectors_file}: no collector declared")
    ids = []
    for i, entry in enumerate(entries):
        cid = str(entry.get("id", "")) if isinstance(entry, dict) else ""
        if not ID.match(cid) or cid == "read" or cid in ids:
            raise ValueError(f"{collectors_file}: collectors[{i}]: invalid or duplicate id {cid!r}")
        ids.append(cid)
    return ids


def make(collectors_file: Path, out: Path, read_token_file: Path | None = None) -> list[str]:
    """Write the two files; return the report lines."""
    lines, report = [], []
    for cid in collector_ids(collectors_file):
        found = []
        for name in (variable(cid), variable(cid) + "_NEXT"):
            token = _value(name)
            if token is None:
                continue
            if not TOKEN.match(token):
                raise ValueError(f"{name}: a token is 32 to 512 characters without spaces (openssl rand -hex 32)")
            found.append(name)
            lines.append(f"{cid} {digest(token)}")
        state = f"token set ({', '.join(found)})" if found else f"no token: set {variable(cid)} (masked)"
        report.append(f"collector {cid}: {state}")
    read = None
    if read_token_file is not None and read_token_file.is_file():
        read = read_token_file.read_text(encoding="utf-8").strip() or None
    if read is None or not TOKEN.match(read):
        read = secrets.token_urlsafe(32)
        report.append("read token: new")
    else:
        report.append("read token: kept")
    lines.append(f"read {digest(read)}")
    out.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        (out / "digests").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (out / "detect-read-token").write_text(read, encoding="utf-8")
    finally:
        os.umask(old)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("collectors", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--read-token", type=Path, help="the read token deployed so far, if any")
    args = parser.parse_args(argv)
    try:
        report = make(args.collectors, args.out, args.read_token)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"intake secrets: {exc}", file=sys.stderr)
        return 2
    for line in report:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
