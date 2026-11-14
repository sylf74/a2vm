# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""ngvm: the common contract of the platform — data model, exchange files and their schemas, settings,
client profiles, LLM client, and the libraries every pillar runs alone: the CISA SSVC tables
(ngvm.ssvc) and the matching of declared assets (ngvm.declared)."""

__version__ = "0.24.0"


def _adopt_legacy_environment() -> None:
    """The product was A2VM until v0.25.0: a variable A2VM_<name> whose NGVM_<name> is not set is
    copied to it, with a warning, for every reader of the process (until v0.26.0)."""
    import os
    import sys

    for old in sorted(k for k in os.environ if k.startswith("A2VM_")):
        new = "NGVM_" + old[len("A2VM_") :]
        if new not in os.environ:
            os.environ[new] = os.environ[old]
            print(f"WARN  CI/CD variable {old} is deprecated: rename it {new}", file=sys.stderr)


_adopt_legacy_environment()
