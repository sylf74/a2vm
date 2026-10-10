#!/usr/bin/env bash
# Run intel -> detect -> triage locally, like the CI does.
#   scripts/run-pipeline.sh --since 26h
#   scripts/run-pipeline.sh --cve CVE-2024-3400
#   scripts/run-pipeline.sh --fixtures tests/fixtures --since 2099-10-01 --include-updated   (offline demo)
set -euo pipefail
cd "$(dirname "$0")/.."
SETTINGS=${SETTINGS:-config/settings.yaml}
PROFILES=${PROFILES:-clients/*.yaml}

vulnops-intel collect --settings "$SETTINGS" --out work/records.json "$@"
vulnops-detect inventory $PROFILES --settings "$SETTINGS" --records work/records.json --out work/findings
verdict run $PROFILES --settings "$SETTINGS" --records work/records.json --findings work/findings --out output
