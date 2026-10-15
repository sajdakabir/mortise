#!/usr/bin/env bash
#
# Installs the native messaging host manifest, which is what tells the browser
# where to find mortise-proxy and — importantly — which extension is allowed
# to talk to it.
#
# Usage:
#   extension/tools/install-host.sh <extension-id> [--release]
#   extension/tools/install-host.sh --uninstall
#
# Get the extension id from chrome://extensions after loading this directory
# with "Load unpacked".

set -euo pipefail

HOST_NAME="com.mortise.proxy"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Every Chromium-family browser reads from its own directory.
TARGET_DIRS=(
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
  "$HOME/Library/Application Support/Google/Chrome Canary/NativeMessagingHosts"
  "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
  # Newer forks keep their user data one level down, in "<Product>/User Data".
  "$HOME/Library/Application Support/Dia/User Data/NativeMessagingHosts"
  "$HOME/Library/Application Support/Arc/User Data/NativeMessagingHosts"
  "$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts"
)

if [[ "${1:-}" == "--uninstall" ]]; then
  for dir in "${TARGET_DIRS[@]}"; do
    if [[ -f "$dir/$HOST_NAME.json" ]]; then
      rm -f "$dir/$HOST_NAME.json"
      echo "removed  $dir/$HOST_NAME.json"
    fi
  done
  echo "Done. Autofill will stop working until you reinstall."
  exit 0
fi

EXTENSION_ID="${1:-}"
if [[ -z "$EXTENSION_ID" ]]; then
  echo "error: no extension id." >&2
  echo >&2
  echo "Load $REPO_ROOT/extension as an unpacked extension, then run:" >&2
  echo "  $0 <extension-id>" >&2
  exit 1
fi

# Chrome extension ids are exactly 32 characters from a-p. Checking saves a
# confusing failure much later, when the browser silently refuses to connect.
if [[ ! "$EXTENSION_ID" =~ ^[a-p]{32}$ ]]; then
  echo "error: '$EXTENSION_ID' is not a Chrome extension id (32 characters, a-p)." >&2
  exit 1
fi

PROFILE="debug"
[[ "${2:-}" == "--release" ]] && PROFILE="release"
PROXY_PATH="$REPO_ROOT/target/$PROFILE/mortise-proxy"

if [[ ! -x "$PROXY_PATH" ]]; then
  echo "error: no proxy binary at $PROXY_PATH" >&2
  echo "build it first:  cargo build ${PROFILE/debug/} -p mortise-proxy" >&2
  exit 1
fi

# allowed_origins is the access control: only this extension may spawn the
# proxy. Leaving it broad would let any installed extension reach the vault.
MANIFEST=$(cat <<JSON
{
  "name": "$HOST_NAME",
  "description": "Mortise native messaging bridge",
  "path": "$PROXY_PATH",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXTENSION_ID/"]
}
JSON
)

installed=0
for dir in "${TARGET_DIRS[@]}"; do
  parent="$(dirname "$dir")"
  # Only install for browsers that are actually present, rather than creating
  # directories for ones that are not.
  [[ -d "$parent" ]] || continue
  mkdir -p "$dir"
  printf '%s\n' "$MANIFEST" > "$dir/$HOST_NAME.json"
  echo "installed  $dir/$HOST_NAME.json"
  installed=$((installed + 1))
done

if [[ "$installed" -eq 0 ]]; then
  echo "error: no Chromium-family browser found." >&2
  exit 1
fi

echo
echo "Proxy:     $PROXY_PATH"
echo "Extension: $EXTENSION_ID"
echo
echo "Restart your browser, then open Mortise and pair from the popup."
