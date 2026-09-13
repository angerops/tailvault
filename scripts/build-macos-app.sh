#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != Darwin ]; then
  echo "The Wails macOS app must be built on macOS with Xcode installed." >&2
  exit 1
fi

case "${1:-}" in
  '') output_dir=bin ;;
  --unsigned) output_dir=bin/unsigned ;;
  *) echo "Usage: $0 [--unsigned]" >&2; exit 2 ;;
esac

version=${VERSION:-$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' build/Info.plist)}
if ! printf '%s\n' "$version" | /usr/bin/grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "VERSION must be a numeric version such as 0.1.0." >&2
  exit 2
fi
# Use the compiler that supports the declared OS floor, including on newer Macs.
GOTOOLCHAIN="go$(awk '$1 == "go" { print $2; exit }' go.mod)"
export GOTOOLCHAIN
macos_min=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' build/Info.plist)
MACOSX_DEPLOYMENT_TARGET=$macos_min
export MACOSX_DEPLOYMENT_TARGET
arch=$(go env GOARCH)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/tailvault-build.XXXXXX")
trap 'rm -rf -- "$build_root"' EXIT HUP INT TERM
app_dir="$build_root/TailVault.app"
iconset="$build_root/TailVault.iconset"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources" "$iconset" "$output_dir"
CGO_ENABLED=1 CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=$macos_min" \
  CGO_CXXFLAGS="${CGO_CXXFLAGS:-} -mmacosx-version-min=$macos_min" \
  CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=$macos_min -framework UniformTypeIdentifiers" \
  go build -tags desktop,production -trimpath -ldflags="-s -w" \
  -o "$app_dir/Contents/MacOS/TailVault" ./cmd/tailvault
cp build/Info.plist "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" "$app_dir/Contents/Info.plist"
/usr/bin/python3 scripts/check-macos-target.py "$app_dir"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" build/appicon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
  double_size=$((size * 2))
  sips -z "$double_size" "$double_size" build/appicon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app_dir/Contents/Resources/icon.icns"
if [ "${1:-}" != --unsigned ]; then
  codesign --force --deep --sign - "$app_dir"
  codesign --verify --deep --strict "$app_dir"
fi
archive_name="TailVault-macos-${arch}.zip"
ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$build_root/$archive_name"
# Replace only generated outputs after building and checking the bundle.
rm -rf -- "$output_dir/TailVault.app"
mv "$app_dir" "$output_dir/TailVault.app"
mv "$build_root/$archive_name" "$output_dir/$archive_name"
(cd "$output_dir" && shasum -a 256 "$archive_name" > SHA256SUMS)
echo "Built $output_dir/TailVault.app for $arch. Archive: $output_dir/$archive_name"
