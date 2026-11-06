#!/bin/bash
#
# Release gate for a signed macOS app bundle.
#
#   usage: verify-app.sh <path/to/App.app>
#
# Fails (exit 1) unless:
#   - the whole bundle verifies: codesign --verify --deep --strict;
#   - the launcher is signed with the hardened runtime;
#   - the launcher carries every entitlement a HotSpot JVM needs under the
#     hardened runtime, each set to true. Without allow-jit the app dies with
#     SIGTRAP in pthread_jit_write_protect_np inside JNI_CreateJavaVM before
#     any Java code runs (stfc/CertWizard#67).
#
# The required entitlements are listed here rather than read from
# CertWizard.entitlements, so that deleting one from that file fails the gate
# instead of silently weakening it.
#
# This only inspects the signature. To prove the signed app actually starts,
# also run <App.app>/Contents/MacOS/CertWizard --self-test, which must exit 0.

set -euo pipefail

required_entitlements=(
    com.apple.security.cs.allow-jit
    com.apple.security.cs.allow-unsigned-executable-memory
    com.apple.security.cs.disable-library-validation
    com.apple.security.cs.allow-dyld-environment-variables
)

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path/to/App.app>" >&2
    exit 2
fi
app=${1%/}
if [[ ! -f $app/Contents/Info.plist ]]; then
    echo "verify-app: $app is not an app bundle" >&2
    exit 1
fi

main_exe=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$app/Contents/Info.plist")
launcher=$app/Contents/MacOS/$main_exe
failures=0
fail() { echo "verify-app: FAIL: $*" >&2; failures=$((failures + 1)); }

echo "verify-app: codesign --verify --deep --strict $app"
if ! codesign --verify --deep --strict --verbose=2 "$app"; then
    fail "code signature of $app does not verify"
fi

signature_info=$(codesign --display --verbose=2 "$launcher" 2>&1) || true
if grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime' <<<"$signature_info"; then
    echo "verify-app: launcher is signed with the hardened runtime"
else
    fail "launcher $launcher is not signed with the hardened runtime"
fi

entitlements_xml=$(mktemp -t certwizard-entitlements)
trap 'rm -f "$entitlements_xml"' EXIT
codesign --display --entitlements - --xml "$launcher" >"$entitlements_xml" 2>/dev/null || true
for key in "${required_entitlements[@]}"; do
    value=$(/usr/libexec/PlistBuddy -c "Print :$key" "$entitlements_xml" 2>/dev/null) || value=missing
    if [[ $value == true ]]; then
        echo "verify-app: launcher entitlement $key = true"
    else
        fail "launcher entitlement $key is $value (must be true)"
    fi
done

if ((failures > 0)); then
    echo "verify-app: $failures check(s) failed for $app; the app would not start (or would not be notarizable)" >&2
    exit 1
fi
echo "verify-app: OK $app"
