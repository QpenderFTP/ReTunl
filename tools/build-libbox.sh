#!/usr/bin/env bash
# Builds libbox, the sing-box-lx core for Android, with the Clash API.
#
# sing-box-lx's own Android build leaves the Clash API out, but ReTunl's
# engine talks to the core through it (status, connections, latency tests),
# the same way as on Windows and macOS. Everything else matches the lx
# release: AmneziaWG, XHTTP and the rest of its Android tags.
#
#   tools/build-libbox.sh [output.aar]
#
# Needs Go (the version in sing-box-lx's go.version), the Android NDK
# (ANDROID_NDK_HOME) and a JDK. tools/prepare-libbox.sh calls this when the
# .aar is missing, then unpacks it into the VPN plugin.
set -euo pipefail

VERSION=1.14.4-lx.32
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${LIBBOX_SRC:-$ROOT/.tools/sing-box-lx-src}
OUT=${1:-$ROOT/.tools/libbox-$VERSION-retunl.aar}
# arm64 and armv7 phones, x86_64 emulators
TARGETS=${LIBBOX_TARGETS:-android/arm64,android/arm,android/amd64}

TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_naive_outbound,badlinkname,tfogo_checklinkname0
TAGS=$TAGS,with_xhttp,with_awg,with_lx_command,with_lx_chain,with_lx_idle_suspend
TAGS=$TAGS,with_openvpn,with_openconnect,with_trusttunnel
TAGS=$TAGS,with_tailscale,ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient
TAGS=$TAGS,ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird
TAGS=$TAGS,with_clash_api

if [ ! -d "$SRC" ]; then
  git clone --depth 1 -b "v$VERSION" https://github.com/Leadaxe/sing-box-lx.git "$SRC"
fi
cd "$SRC"
# uTLS and friends are git submodules
git submodule update --init --depth 1

# gomobile and gobind at the version sing-box-lx pins in go.mod
go install github.com/sagernet/gomobile/cmd/gomobile github.com/sagernet/gomobile/cmd/gobind
GOBIN_DIR="$(go env GOPATH)/bin"
# Git Bash on Windows: go prints C:\…, PATH wants /c/…
if command -v cygpath >/dev/null; then GOBIN_DIR=$(cygpath -u "$GOBIN_DIR"); fi
PATH="$GOBIN_DIR:$PATH"

gomobile bind -v \
  -o "$OUT" \
  -target "$TARGETS" \
  -androidapi 24 \
  -javapkg=io.nekohasekai \
  -libname=box \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=$VERSION -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" \
  -tags "$TAGS" \
  ./experimental/libbox

echo "libbox: $OUT"
