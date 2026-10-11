#!/usr/bin/env bash
# Run the vulnops pipeline locally, like the CI does:
#   [collect] -> intel -> detect inventory -> assets -> verdict
#
#   scripts/run-pipeline.sh --since 26h
#   scripts/run-pipeline.sh --cve CVE-2024-3400
#   scripts/run-pipeline.sh --fixtures tests/fixtures --since 2099-10-01 --include-updated   (offline demo)
#
# Environment: SETTINGS (config/settings.yaml), PROFILES (clients/*.yaml), TARGETS (SSH collection
# targets files; empty = no collection), WORK (work), OUT (output).
set -euo pipefail
cd "$(dirname "$0")/.."
SETTINGS=${SETTINGS:-config/settings.yaml}
PROFILES=${PROFILES:-clients/*.yaml}
TARGETS=${TARGETS:-}
WORK=${WORK:-work}
OUT=${OUT:-output}

rm -rf "$WORK/detect" "$WORK/assets"
if [ -n "$TARGETS" ]; then
  vulnops-detect collect $TARGETS --raw "$WORK/scans" --out "$WORK/detect" || echo "collection incomplete, continuing"
fi
vulnops-intel collect --settings "$SETTINGS" --detect "$WORK/detect" --out "$WORK/records.json" "$@"
vulnops-detect inventory $PROFILES --settings "$SETTINGS" --records "$WORK/records.json" --out "$WORK/detect"
vulnops-assets build $PROFILES --detect "$WORK/detect" --out "$WORK/assets"
verdict run $PROFILES --settings "$SETTINGS" --records "$WORK/records.json" --assets "$WORK/assets" --out "$OUT"
