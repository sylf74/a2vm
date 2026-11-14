#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The scripts of a running cloud scanner, brought to this release.

cloud-init runs at the first boot only, and main.tf ignores later changes of the template. This
prints a shell script that writes again, from cloud-init.yaml.tftpl, every file of the template
without a Terraform value (the scripts of /opt/ngvm-scanner and the feed service); scanner.env,
the feed timer and the secrets are left as they are. Python standard library only:

    python3 deploy/scanner/update-scripts.py | ssh root@<scanner> bash
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TEMPLATE = Path(__file__).with_name("cloud-init.yaml.tftpl")
END = "NGVM_END_OF_FILE"


def write_files(text: str) -> list[tuple[str, str, str]]:
    """(path, permissions, content) of each entry of write_files, as cloud-init would write it."""
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        match = re.fullmatch(r"  - path: (\S+)", lines[i])
        if not match:
            i += 1
            continue
        path, mode = match.group(1), ""
        i += 1
        while i < len(lines) and lines[i].startswith("    ") and not lines[i].startswith("    content: |"):
            m = re.fullmatch(r'    permissions: "(\d+)"', lines[i])
            mode = m.group(1) if m else mode
            i += 1
        if i >= len(lines) or lines[i] != "    content: |":
            raise ValueError(f"{path}: no content block")
        i += 1
        body = []
        while i < len(lines) and (lines[i].startswith("      ") or lines[i] == ""):
            body.append(lines[i][6:])
            i += 1
        while body and body[-1] == "":
            body.pop()
        out.append((path, mode, "\n".join(body) + "\n"))
    return out


def has_terraform_value(content: str) -> bool:
    return re.search(r"(?<!\$)\$\{", content) is not None or re.search(r"(?<!%)%\{", content) is not None


def script(text: str) -> str:
    parts = ["set -euo pipefail"]
    for path, mode, content in write_files(text):
        if has_terraform_value(content) or path.endswith("/bootstrap.sh"):
            continue
        content = content.replace("$${", "${").replace("%%{", "%{")
        if END in content:
            raise ValueError(f"{path}: contains {END}")
        parts.append(f"install -D -m {mode or '0644'} /dev/stdin {path} <<'{END}'\n{content}{END}")
        parts.append(f'echo "updated {path}"')
    parts.append("systemctl daemon-reload")
    return "\n".join(parts) + "\n"


def main() -> int:
    sys.stdout.write(script(TEMPLATE.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
