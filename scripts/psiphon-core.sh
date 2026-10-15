#!/usr/bin/env bash
# Build the Psiphon client that Postern ships (Ruling S2-26): psiphon-tunnel-core's
# ConsoleClient at the commit of scripts/psiphon-core.env, statically, for
# linux/amd64 and linux/arm64.
#
#   bash scripts/psiphon-core.sh <outdir>
#
# writes <outdir>/psiphon-core-linux-amd64 and <outdir>/psiphon-core-linux-arm64.
# The release build (scripts/release.sh build) runs it; the build job has no
# secret. What it does:
#
#   1. downloads the source archive of the commit from GitHub and checks it
#      against PSIPHON_CORE_SOURCE_SHA256 before anything of it is used;
#   2. unpacks it (tar --no-same-owner --no-same-permissions, into a fresh
#      directory) and checks that the vendor directory is what go.mod and go.sum
#      say: go mod vendor writes the vendor tree again into a scratch directory
#      (modules fetched through the proxy and checked against go.sum and the
#      checksum database), and the shipped vendor/ must equal it, file for file.
#      The build uses vendor/ (-mod=vendor), so this checks what it compiles;
#      go mod verify would check the module cache, which the build never reads.
#      The build also runs with the proxy and the checksum database set here,
#      and GOFLAGS, GOPRIVATE, GONOSUMDB, GONOSUMCHECK and GOINSECURE unset, so
#      that the environment of the runner cannot weaken the check;
#   3. builds ./ConsoleClient with the toolchain of its go.mod (GOTOOLCHAIN,
#      which Go fetches and checks against its checksum database), CGO_ENABLED=0,
#      -trimpath, -buildvcs=false, no build id, and the build information of
#      upstream's make.bash (the repository, the revision of 10 digits, the date
#      of the commit, the Go version), so that two builds are the same bytes:
#      the SHA-256s are pinned in internal/panel/releases/builtin.json, and
#      the release tool (check-build) refuses others.
#
# It needs curl, tar, sha256sum (or shasum) and go, and the network.
set -euo pipefail

log() { printf 'psiphon-core.sh: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}

[ "$#" -eq 1 ] || die "usage: bash scripts/psiphon-core.sh <outdir>"
out=$1
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/psiphon-core.env
. "$here/psiphon-core.env"

for v in PSIPHON_CORE_COMMIT PSIPHON_CORE_SOURCE_SHA256 PSIPHON_CORE_GO PSIPHON_CORE_DATE; do
  [ -n "${!v:-}" ] || die "$v is not set in scripts/psiphon-core.env"
done
[[ $PSIPHON_CORE_COMMIT =~ ^[0-9a-f]{40}$ ]] || die "PSIPHON_CORE_COMMIT is not a commit"
[[ $PSIPHON_CORE_SOURCE_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "PSIPHON_CORE_SOURCE_SHA256 is not a SHA-256"

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/psiphon-core.XXXXXX")
trap 'chmod -R u+w "$work" 2> /dev/null; rm -rf "$work"' EXIT

url=https://codeload.github.com/Psiphon-Labs/psiphon-tunnel-core/tar.gz/$PSIPHON_CORE_COMMIT
log "downloading psiphon-tunnel-core $PSIPHON_CORE_COMMIT"
curl -fsSL --retry 3 --proto '=https' --max-filesize 209715200 -o "$work/src.tar.gz" "$url"
got=$(sha256_of "$work/src.tar.gz")
[ "$got" = "$PSIPHON_CORE_SOURCE_SHA256" ] ||
  die "the source archive has the SHA-256 $got, and scripts/psiphon-core.env pins $PSIPHON_CORE_SOURCE_SHA256"

mkdir "$work/src"
tar -x -z -f "$work/src.tar.gz" -C "$work/src" --strip-components=1 --no-same-owner --no-same-permissions
src=$work/src
[ -f "$src/ConsoleClient/main.go" ] && [ -f "$src/vendor/modules.txt" ] || die "the archive is not the source of psiphon-tunnel-core with its vendor directory"

unset GONOSUMDB GONOSUMCHECK GOINSECURE GOPRIVATE GOFLAGS
export GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org
export GOTOOLCHAIN=$PSIPHON_CORE_GO CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0
export GOPATH=$work/gopath GOMODCACHE=$work/gopath/pkg/mod GOCACHE=$work/gocache
unset GOARCH
log "checking that vendor/ is what go.mod and go.sum say (go mod vendor, diff)"
(cd "$src" && go mod vendor -o "$work/vendor-check")
# Upstream's .gitignore has "build/", so its vendor/ lacks ginkgo's build
# package (the test runner's, which no build of ConsoleClient imports). That is
# the one difference that is known; any other is an error.
rm -rf "$work/vendor-check/github.com/onsi/ginkgo/v2/ginkgo/build"
diff -r "$src/vendor" "$work/vendor-check" > "$work/vendor.diff" ||
  die "vendor/ differs from go mod vendor of go.mod and go.sum: $(head -c 400 "$work/vendor.diff")"

info=github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo
ldflags="-s -w -buildid= \
-X $info.buildDate=$PSIPHON_CORE_DATE \
-X $info.buildRepo=https://github.com/Psiphon-Labs/psiphon-tunnel-core.git \
-X $info.buildRev=${PSIPHON_CORE_COMMIT:0:10} \
-X $info.goVersion=$PSIPHON_CORE_GO"
for arch in amd64 arm64; do
  log "building psiphon-core for linux/$arch with $PSIPHON_CORE_GO"
  (cd "$src" && GOARCH=$arch GOFLAGS=-mod=vendor go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out/psiphon-core-linux-$arch" ./ConsoleClient)
  log "psiphon-core-linux-$arch: $(sha256_of "$out/psiphon-core-linux-$arch")"
done
