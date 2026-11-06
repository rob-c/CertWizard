#!/bin/bash
#
# Sign a jpackage-built macOS app bundle, inside-out, with the hardened runtime.
#
#   usage: sign-app.sh <path/to/App.app> <identity> <entitlements.plist>
#
#   identity      codesign identity: "-" for an ad hoc signature (the default
#                 used by the Maven build), or a Developer ID such as
#                 "Developer ID Application: Example Ltd (TEAMID)".
#   entitlements  applied to the Mach-O executables: the launcher and the JDK's
#                 jspawnhelper. A HotSpot JVM under the hardened runtime cannot
#                 start without allow-jit and friends (stfc/CertWizard#67).
#
# Order:
#   1. every Mach-O file inside the bundle except the launcher (the runtime's
#      dylibs, including Contents/runtime/Contents/MacOS/libjli.dylib, and
#      lib/jspawnhelper);
#   2. nested bundles (Contents/runtime), deepest first, which seals their
#      resources over the code signed in step 1;
#   3. the app itself, which signs Contents/MacOS/<CFBundleExecutable> with the
#      entitlements and seals everything else.
#
# codesign --deep is deliberately not used for signing: it applies one set of
# options and entitlements to everything and hides what got signed how.
#
# This must run after anything that modifies the bundle (jpackage, which
# already ad hoc signs the image itself, and the Info.plist edit in pom.xml);
# any later change to the bundle invalidates the signature.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <path/to/App.app> <identity> <entitlements.plist>" >&2
    exit 2
fi

app=${1%/}
identity=$2
entitlements=$3

if [[ ! -f $app/Contents/Info.plist ]]; then
    echo "sign-app: $app is not an app bundle" >&2
    exit 1
fi
if ! plutil -lint -s "$entitlements"; then
    echo "sign-app: entitlements file $entitlements is missing or not a valid plist" >&2
    exit 1
fi

plist_get() { /usr/libexec/PlistBuddy -c "Print :$1" "$2"; }
main_exe=$(plist_get CFBundleExecutable "$app/Contents/Info.plist")
bundle_id=$(plist_get CFBundleIdentifier "$app/Contents/Info.plist")

common=(--force --sign "$identity" --options runtime)
if [[ $identity != "-" ]]; then
    # A secure timestamp is required for notarization; ad hoc signatures can't have one.
    common+=(--timestamp)
fi

echo "sign-app: signing $app with identity '$identity' (hardened runtime)"

# 1. Nested Mach-O files. Files without an Info.plist get their identifier from
#    the file name; --prefix makes that e.g. uk.ngs.certwizard.libjvm.
count=0
while IFS= read -r -d '' f; do
    kind=$(file -b "$f")
    [[ $kind == Mach-O* ]] || continue
    if [[ $kind == *executable* ]]; then
        codesign "${common[@]}" --prefix "$bundle_id." --entitlements "$entitlements" "$f"
    else
        codesign "${common[@]}" --prefix "$bundle_id." "$f"
    fi
    count=$((count + 1))
done < <(find "$app/Contents" -type f ! -path "$app/Contents/MacOS/$main_exe" -print0)
echo "sign-app: signed $count nested Mach-O files"

# 2. Nested bundles, deepest first.
while IFS= read -r plist; do
    bundle=${plist%/Contents/Info.plist}
    echo "sign-app: signing nested bundle ${bundle#"$app"/}"
    codesign "${common[@]}" "$bundle"
done < <(find "$app/Contents" -mindepth 3 -path '*/Contents/Info.plist' |
         awk -F/ '{ print NF "\t" $0 }' | sort -rn | cut -f2-)

# 3. The app bundle and its launcher.
echo "sign-app: signing $app (launcher $main_exe, entitlements $(basename "$entitlements"))"
codesign "${common[@]}" --entitlements "$entitlements" "$app"
