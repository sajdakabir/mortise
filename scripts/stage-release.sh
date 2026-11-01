#!/usr/bin/env bash
# Verify the universal app, then stage only explicitly named release files.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(python3 -c 'import json; print(json.load(open("crates/mortise-app/tauri.conf.json"))["version"])')
app="target/universal-apple-darwin/release/bundle/macos/Mortise.app"
dmgs=(target/universal-apple-darwin/release/bundle/dmg/*.dmg)
test "${#dmgs[@]}" -eq 1
test -f "${dmgs[0]}"

codesign --verify --deep --strict --verbose=2 "$app"
for binary in mortise-app mortise-proxy; do
  test -x "$app/Contents/MacOS/$binary"
  lipo -verify_arch arm64 x86_64 "$app/Contents/MacOS/$binary"
done
plutil -extract CFBundleURLTypes xml1 -o - "$app/Contents/Info.plist" | grep -q '<string>mortise</string>'
hdiutil verify "${dmgs[0]}"

signature='ad hoc; not Developer ID signed; not notarized'
if xcrun stapler validate "$app" >/dev/null 2>&1; then
  signature='Developer ID signed and notarized'
fi

out=$(mktemp -d target/release-assets.XXXXXX)
extension_version=$(python3 -c 'import json; print(json.load(open("extension/manifest.json"))["version"])')
cp "${dmgs[0]}" "$out/Mortise_${version}_universal.dmg"
cp "target/extension/mortise-extension-${extension_version}.zip" "$out/"
cp TESTING.md "$out/INSTALL.md"
{
  printf 'Mortise %s\n' "$version"
  printf 'Commit: %s\n' "${GITHUB_SHA:-$(git rev-parse HEAD)}"
  printf 'Architecture: universal (Apple silicon + Intel)\n'
  printf 'Minimum macOS: 11.0\n'
  printf 'Signature: %s\n' "$signature"
  if [ -n "${GITHUB_RUN_ID:-}" ]; then
    printf 'Build: https://github.com/%s/actions/runs/%s\n' "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"
  fi
} > "$out/BUILD.txt"

(
  cd "$out"
  shasum -a 256 ./*.dmg ./*.zip BUILD.txt INSTALL.md > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
ls -lh "$out"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'directory=%s\n' "$out" >> "$GITHUB_OUTPUT"
fi
