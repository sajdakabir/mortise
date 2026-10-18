#!/bin/sh
# Sign the freshly built dev binary, then run it.
#
# Wired in as cargo's runner (see .cargo/config.toml), so `cargo run` and
# `cargo tauri dev` both go through it.
#
# ## Why this exists
#
# The account key lives in the login keychain. An item stored without an
# explicit access list gets a default ACL trusting the application that
# created it, and an *unsigned* binary is identified in that ACL by its
# code-directory hash. `cargo` relinks on every build, so every rebuild is a
# different application as far as the keychain is concerned, and the prompt
# comes back. Clicking "Always Allow" adds that one hash and is invalidated by
# the next build.
#
# A signed binary is matched on its signing certificate instead, which does
# not change when the code does. One prompt after the first signed build, then
# silence.
#
# ## Setting it up
#
# One self-signed certificate, created once, never leaves this Mac:
#
#   Keychain Access → Certificate Assistant → Create a Certificate…
#     Name:              Mortise Dev
#     Identity Type:     Self Signed Root
#     Certificate Type:  Code Signing
#
# Nothing here needs it. Without the certificate the binary runs unsigned,
# exactly as before, so a checkout with no certificate still works.
set -e

IDENTITY="${MORTISE_SIGN_IDENTITY:-Mortise Dev}"
BIN="$1"
shift

if security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
    # --force because the previous build's signature is still attached.
    # --preserve-metadata keeps any entitlements Tauri put there.
    codesign --force --preserve-metadata=entitlements \
        --sign "$IDENTITY" "$BIN" 2>/dev/null ||
        echo "mortise: could not sign $BIN; continuing unsigned" >&2
fi

exec "$BIN" "$@"
