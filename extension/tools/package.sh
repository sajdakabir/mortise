#!/usr/bin/env bash
#
# Builds the zip you upload to the Chrome Web Store.
#
# Usage:
#   extension/tools/package.sh
#
# The archive is assembled from an explicit allowlist rather than by excluding
# known dev files. Excluding is the wrong default here: the day someone drops a
# scratch file, a .env or a private key into extension/, an exclude list ships
# it and an allowlist does not.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/extension"
OUT_DIR="$REPO_ROOT/target/extension"

# Everything the browser loads, and nothing else. NOTES.md, package.json and
# tools/ are for people working on this repo and have no business in a package
# that ships to users.
FILES=(
  manifest.json
  background.js
  capture.js
  proof.js
  popup.html
  popup.js
  popup.css
  icons/icon32.png
  icons/icon128.png
  icons/icon256.png
)

fail() { echo "error: $*" >&2; exit 1; }

command -v zip >/dev/null || fail "zip is not installed"
command -v python3 >/dev/null || fail "python3 is not installed"

# --- validate the manifest -------------------------------------------------

python3 -I - "$SRC" <<'PY' || exit 1
import json, pathlib, sys

src = pathlib.Path(sys.argv[1])
try:
    m = json.loads((src / "manifest.json").read_text())
except json.JSONDecodeError as e:
    sys.exit(f"error: manifest.json is not valid JSON: {e}")

problems = []

if m.get("manifest_version") != 3:
    problems.append("manifest_version must be 3; Chrome stopped accepting v2 uploads")

# A "key" pins the extension id for local development. Uploading one is a
# submission error for a new item, and for an existing one it fights the id the
# Store already assigned. It belongs in a local manifest, never in the package.
if "key" in m:
    problems.append('manifest.json contains a "key" field — strip it before packaging')

for field in ("name", "version", "description"):
    if not m.get(field):
        problems.append(f"{field} is missing or empty")

# The listing refuses a description over 132 characters, and finding that out
# on the dashboard after a build is a waste of a round trip.
desc = m.get("description", "")
if len(desc) > 132:
    problems.append(f"description is {len(desc)} chars; the Store caps it at 132")

if not m.get("icons", {}).get("128"):
    problems.append("a 128px icon is required for the Store listing")

pkg = src / "package.json"
if pkg.exists():
    pv = json.loads(pkg.read_text()).get("version")
    if pv and pv != m.get("version"):
        problems.append(f"version drift: manifest {m.get('version')} vs package.json {pv}")

if problems:
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    sys.exit(1)
PY

VERSION="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$SRC/manifest.json")"

# --- check every file is really there --------------------------------------

missing=0
for f in "${FILES[@]}"; do
  [[ -f "$SRC/$f" ]] || { echo "error: missing $f" >&2; missing=1; }
done
[[ "$missing" -eq 0 ]] || fail "the allowlist references files that do not exist"

# Anything in the source tree that the allowlist does not name. Not fatal —
# NOTES.md and tools/ are meant to be left out — but worth printing, because a
# genuinely new runtime file silently missing from the package produces an
# extension that breaks only once installed.
echo "Not packaged (check nothing here is needed at runtime):"
( cd "$SRC" && find . -type f ! -path '*/.*' | sed 's|^\./||' | sort ) \
  | grep -vxF -f <(printf '%s\n' "${FILES[@]}") \
  | sed 's/^/  /' || true
echo

# --- build -----------------------------------------------------------------

ZIP="$OUT_DIR/mortise-extension-$VERSION.zip"
mkdir -p "$OUT_DIR"
rm -f "$ZIP"

# -X drops the resource forks and timestamps that macOS otherwise buries in the
# archive, so the same source produces the same bytes.
( cd "$SRC" && zip -q -X "$ZIP" "${FILES[@]}" )

echo "Packaged  $ZIP"
echo "Version   $VERSION"
echo "Size      $(du -h "$ZIP" | cut -f1)"
echo
echo "Contents:"
unzip -l "$ZIP" | sed -n '4,$p' | sed '$d' | sed 's/^/  /'
echo
echo "Next: docs/publishing-the-extension.md"
