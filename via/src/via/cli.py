# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""`via`: pillar 1 commands.

  via collect …         build a records file for a set of CVEs (intel)
  via watch …           draft alerts for what is new since the last run (alert)
  via send …            mail the alerts of a watch run to the client (alert)
  via check-sources …   read every watch source once and report (alert)
  via contacts …        check contacts.yaml and list who receives what (alert)

`via <command> -h` gives the options of each command.
"""

from __future__ import annotations

import sys

INTEL = {"collect"}
ALERT = {"watch", "send", "check-sources", "contacts"}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in INTEL:
        from .intel.cli import main as intel_main

        return intel_main(args)
    if args and args[0] in ALERT:
        from .alert.cli import main as alert_main

        return alert_main(args)
    print(__doc__.strip())
    return 0 if args[:1] in (["-h"], ["--help"]) else 2


if __name__ == "__main__":
    sys.exit(main())
