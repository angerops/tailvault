#!/bin/sh
set -eu

app_dir=${1:?app bundle path required}
report=${2:?notarization report path required}
identity=${CODESIGN_IDENTITY:?Set CODESIGN_IDENTITY to the Developer ID Application certificate}
profile=${NOTARYTOOL_PROFILE:?Set NOTARYTOOL_PROFILE to the existing notarization profile}
keychain=${CODESIGN_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}

case "$identity" in
  'Developer ID Application: '*) ;;
  *) echo "Release builds require a Developer ID Application identity." >&2; exit 2 ;;
esac

# Use the configured keychain; GitHub supplies a temporary one for this job.
codesign --force --deep --options runtime --timestamp \
  --keychain "$keychain" --sign "$identity" "$app_dir"
codesign --verify --deep --strict --verbose=2 "$app_dir"
signature=$(codesign --display --verbose=4 "$app_dir" 2>&1)
printf '%s\n' "$signature" | /usr/bin/grep -F "Authority=$identity"
printf '%s\n' "$signature" | /usr/bin/grep -E 'flags=.*runtime'
printf '%s\n' "$signature" | /usr/bin/grep '^Timestamp='

notary_dir=$(mktemp -d "${TMPDIR:-/tmp}/tailvault-notary.XXXXXX")
trap 'rm -rf -- "$notary_dir"' EXIT HUP INT TERM
ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$notary_dir/TailVault.zip"
xcrun notarytool submit "$notary_dir/TailVault.zip" \
  --keychain-profile "$profile" --keychain "$keychain" \
  --wait --timeout 30m --output-format json > "$report"
/usr/bin/python3 - "$report" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
print("Apple notarization:", result.get("status"), "Submission:", result.get("id"))
if result.get("status") != "Accepted":
    raise SystemExit("Apple did not accept this build; no release archive will be created.")
PY

xcrun stapler staple "$app_dir"
xcrun stapler validate "$app_dir"
codesign --verify --deep --strict --verbose=2 "$app_dir"
spctl --assess --type execute --verbose=4 "$app_dir"
