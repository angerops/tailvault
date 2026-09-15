#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  ''|--checks-only) ;;
  --release-input)
    VERSION=$(/usr/bin/python3 -I scripts/release-artifact.py version)
    export VERSION
    ;;
  *) echo "Usage: $0 [--checks-only|--release-input]" >&2; exit 2 ;;
esac
# GitHub runs this script only on its credential-free build worker.
if [[ -n ${CODESIGN_KEYCHAIN:-}${KEYCHAIN_PASSWORD:-}${CODESIGN_PRIVATE_KEY_BASE64:-}${NOTARY_KEY_BASE64:-} ]]; then
  echo 'Build and tests must not run with signing credentials.' >&2
  exit 2
fi

# Use temporary tools and caches without installing global dependencies.
tools_root=$(mktemp -d "${TMPDIR:-/tmp}/tailvault-ci-tools.XXXXXX")
cleanup() {
  chmod -R u+w "$tools_root" 2>/dev/null || true
  rm -rf -- "$tools_root"
}
trap cleanup EXIT
go_version=$(awk '$1 == "go" { print $2; exit }' go.mod)
curl --fail --silent --show-error --location \
  'https://go.dev/dl/?mode=json&include=all' -o "$tools_root/releases.json"
read -r go_archive go_sha < <(/usr/bin/python3 - "$tools_root/releases.json" "$go_version" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    releases = json.load(source)
for release in releases:
    if release["version"] == "go" + sys.argv[2] and release.get("stable"):
        for artifact in release["files"]:
            if (artifact["os"], artifact["arch"], artifact["kind"]) == ("darwin", "arm64", "archive"):
                print(artifact["filename"], artifact["sha256"])
                raise SystemExit(0)
raise SystemExit("The pinned Go release is not available for the macOS runner.")
PY
)
curl --fail --silent --show-error --location "https://go.dev/dl/$go_archive" \
  -o "$tools_root/$go_archive"
printf '%s  %s\n' "$go_sha" "$tools_root/$go_archive" | shasum -a 256 -c -
tar -C "$tools_root" -xzf "$tools_root/$go_archive"

# Pin the UI test toolchain on the credential-free worker.
node_archive=node-v22.22.3-darwin-arm64.tar.gz
node_sha=0da7ff74ef8611328c8212f17943368713a2ad953fb7d89a8c8a0eae87c23207
curl --fail --silent --show-error --location "https://nodejs.org/dist/v22.22.3/$node_archive" \
  -o "$tools_root/$node_archive"
printf '%s  %s\n' "$node_sha" "$tools_root/$node_archive" | shasum -a 256 -c -
tar -C "$tools_root" -xzf "$tools_root/$node_archive"
export PATH="$tools_root/node-v22.22.3-darwin-arm64/bin:$tools_root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export GOPATH="$tools_root/gopath" GOMODCACHE="$tools_root/gomodcache" GOCACHE="$tools_root/gocache"
export GOTELEMETRY=off GOTOOLCHAIN=local CGO_LDFLAGS='-framework UniformTypeIdentifiers'
go version
export PLAYWRIGHT_BROWSERS_PATH="$tools_root/playwright" npm_config_cache="$tools_root/npm-cache"
node --version
npm ci --ignore-scripts
npx --no-install playwright install webkit
if [[ -d .forgejo/workflows ]]; then
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .forgejo/actionlint.yaml -shellcheck= .forgejo/workflows/*.yml
fi
if [[ -d .github/workflows ]]; then
  go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .github/actionlint.yaml -shellcheck= .github/workflows/*.yml
fi
make test check
if [[ ${1:-} == --release-input ]]; then
  sh scripts/build-macos-app.sh --unsigned
  /usr/bin/python3 -I scripts/release-artifact.py package --app bin/unsigned/TailVault.app --output bin/signing-input
elif [[ ${1:-} != --checks-only ]]; then
  make build
fi
