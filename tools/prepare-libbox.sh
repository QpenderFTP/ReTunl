#!/usr/bin/env bash
# The core for Android: libbox, built from sing-box-lx with the Clash API
# (tools/build-libbox.sh), unpacked where the Android build looks for it:
#   classes   → crates/vpn-android/android/libs/libbox.jar
#   libraries → crates/vpn-android/android/src/main/jniLibs/<abi>/libbox.so
# Both are git-ignored. Run once before `tauri android build`.
#
#   LIBBOX_AAR=path/to/libbox.aar  use this build instead of making one
#   LIBBOX_ABIS="arm64-v8a"        only these phone architectures
set -euo pipefail

VERSION=1.14.4-lx.32 # keep in step with SING_BOX_LX_VERSION in crates/core/src/lib.rs
ABIS=${LIBBOX_ABIS:-arm64-v8a armeabi-v7a x86_64}

root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/crates/vpn-android/android"
aar="${LIBBOX_AAR:-$root/.tools/libbox-$VERSION-retunl.aar}"
stamp="$dest/libs/.version"
want="$VERSION $ABIS $(stat -c %s "$aar" 2>/dev/null || echo 0)"
if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
  echo "libbox $VERSION is already in place"
  exit 0
fi
if [ ! -f "$aar" ]; then
  bash "$root/tools/build-libbox.sh" "$aar"
  want="$VERSION $ABIS $(stat -c %s "$aar")"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$aar" -d "$tmp"
rm -rf "$dest/libs" "$dest/src/main/jniLibs"
mkdir -p "$dest/libs"
cp "$tmp/classes.jar" "$dest/libs/libbox.jar"
for abi in $ABIS; do
  mkdir -p "$dest/src/main/jniLibs/$abi"
  cp "$tmp/jni/$abi/libbox.so" "$dest/src/main/jniLibs/$abi/libbox.so"
done
echo "$want" > "$stamp"
echo "libbox $VERSION: $ABIS"
