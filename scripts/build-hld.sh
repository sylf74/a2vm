#!/bin/sh
# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
# Assemble the HLD chapters (docs/hld/) into one document for a review outside GitLab.
# Usage: scripts/build-hld.sh [output-dir]   (default: build/hld)
# Always writes hld.md; also hld.html and hld.pdf when pandoc (and a PDF engine) are installed.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$here/build/hld"}
mkdir -p "$out"
md="$out/hld.md"
: > "$md"
for f in "$here"/docs/hld/0*.md "$here"/docs/hld/[1-9]*.md; do
  # Links between chapters become plain text (the chapters follow each other in the file).
  sed -E 's/\[([^]]*)\]\([0-9]{2}-[a-z-]+\.md\)/\1/g' "$f" >> "$md"
  printf '\n\n' >> "$md"
done
echo "hld: $md"
if command -v pandoc >/dev/null 2>&1; then
  pandoc "$md" -s --toc -o "$out/hld.html" --metadata title="AI-Assisted Vulnerability Management — HLD"
  echo "hld: $out/hld.html"
  pandoc "$md" --toc -o "$out/hld.pdf" 2>/dev/null && echo "hld: $out/hld.pdf" || echo "hld: no PDF engine, PDF skipped"
fi
