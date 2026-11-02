#!/usr/bin/env bash
set -euo pipefail

case "$(uname -m)" in
  arm64)
    cross_target=x86_64-apple-darwin
    cross_arch=x86_64
    ;;
  x86_64)
    cross_target=aarch64-apple-darwin
    cross_arch=arm64
    ;;
  *)
    echo "Unsupported macOS host architecture" >&2
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_test_target_dir="$(mktemp -d "${TMPDIR:-/tmp}/str0m-swift-targets.XXXXXX")"
trap 'rm -rf "$swift_test_target_dir"' EXIT
export CARGO_TARGET_DIR="$swift_test_target_dir"

# Linking the test binary catches archives built for the host rather than the
# requested macOS architecture. It does not require running the binary.
cargo test --locked --manifest-path "$script_dir/../Cargo.toml" --target "$cross_target" --no-run
cross_archive="$(find "$swift_test_target_dir/$cross_target/debug/build" \
  -name libStr0mCryptoKit.a -print -quit)"
test -n "$cross_archive"
xcrun lipo -verify_arch "$cross_arch" "$cross_archive"
if [[ "$cross_arch" == "x86_64" ]]; then
  mac_min_version="$(xcrun otool -l "$cross_archive" | awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
    in_build && $1 == "minos" { print $2; in_build = 0 }
  ')"
  if [[ "$mac_min_version" != "10.15" ]]; then
    echo "Intel Swift bridge has minimum '$mac_min_version', expected 10.15" >&2
    exit 1
  fi
fi

for ios_target in aarch64-apple-ios aarch64-apple-ios-sim; do
  ios_expected_version=13.0
  ios_expected_platform=2
  if [[ "$ios_target" == "aarch64-apple-ios-sim" ]]; then
    ios_expected_version=14.0
    ios_expected_platform=7
  fi
  cargo build --locked --manifest-path "$script_dir/../Cargo.toml" --target "$ios_target"
  ios_archive="$(find "$swift_test_target_dir/$ios_target/debug/build" \
    -name libStr0mCryptoKit.a -print -quit)"
  test -n "$ios_archive"
  xcrun lipo -verify_arch arm64 "$ios_archive"
  ios_min_version="$(xcrun otool -l "$ios_archive" | awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
    in_build && $1 == "minos" { print $2; in_build = 0 }
  ')"
  if [[ "$ios_min_version" != "$ios_expected_version" ]]; then
    echo "$ios_target Swift bridge has minimum '$ios_min_version', expected $ios_expected_version" >&2
    exit 1
  fi
  ios_platform="$(xcrun otool -l "$ios_archive" | awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
    in_build && $1 == "platform" { print $2; in_build = 0 }
  ')"
  if [[ "$ios_platform" != "$ios_expected_platform" ]]; then
    echo "$ios_target Swift bridge has platform '$ios_platform', expected $ios_expected_platform" >&2
    exit 1
  fi
done

# A newer deployment target must reach the Swift compiler as well as rustc.
# Check two successive targets in the same Cargo directory so changing the
# setting also invalidates the cached bridge build.
check_newer_deployment_target() {
  local target="$1"
  local deployment_var="$2"
  local expected archive actual
  shift 2
  for expected in "$@"; do
    env "$deployment_var=$expected" CARGO_TARGET_DIR="$swift_test_target_dir/newer" \
      cargo build --locked --manifest-path "$script_dir/../Cargo.toml" --target "$target"
    archive="$(find "$swift_test_target_dir/newer/$target/debug/build" \
      -name libStr0mCryptoKit.a -print -quit)"
    test -n "$archive"
    actual="$(xcrun otool -l "$archive" | awk '
      $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
      in_build && $1 == "minos" { print $2; in_build = 0 }
    ')"
    if [[ "$actual" != "$expected" ]]; then
      echo "$target Swift bridge has minimum '$actual', expected $expected" >&2
      return 1
    fi
  done
}

check_newer_deployment_target "$cross_target" MACOSX_DEPLOYMENT_TARGET 15.0 15.1
check_newer_deployment_target aarch64-apple-ios IPHONEOS_DEPLOYMENT_TARGET 15.0 16.0
