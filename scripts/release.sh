#!/usr/bin/env bash
# Build, sign and check the release of a tag of Postern.
#
#   bash scripts/release.sh build <tag> <outdir>          the job that builds: no secret
#   bash scripts/release.sh sign <tag> <indir> <outdir>   the job that signs: the key, no build
#   bash scripts/release.sh <tag>                          a workstation only, never CI: both, into dist/
#
# The release workflow (.github/workflows/release.yml) runs the first two in
# two jobs, so that what the build runs (npm packages above all) never runs
# where the key is.
#
# build writes into <outdir> the six binaries and MANIFEST, their SHA-256 in
# the format of sha256sum:
#   1. the tag is exported with git archive into a temporary directory: the
#      working tree is never touched, and what is built is what the tag holds;
#   2. the web UI is built there (npm ci --ignore-scripts, npm run build) and put
#      over the placeholder page in internal/panel/webui/dist/;
#   3. the binaries are built there with CGO_ENABLED=0 and -trimpath, the
#      version of the tag, the first 12 hex digits of its commit and the time of
#      its commit;
#   4. the Psiphon client, psiphon-core, is built from its pinned upstream
#      commit, statically, for both architectures (scripts/psiphon-core.sh,
#      Ruling S2-26): the bytes that the panel pins.
#
# sign takes such a directory and writes into <outdir> the files of the release:
#
#   postern-node-linux-amd64    postern-node-linux-arm64     each with <file>.minisig
#   postern-panel-linux-amd64   postern-panel-linux-arm64
#   psiphon-core-linux-amd64    psiphon-core-linux-arm64     (not in the bundle; the upload takes them in a tar)
#   SHA256SUMS                  SHA256SUMS.minisig
#   postern-<tag>-bundle.tar    all of the above, for a panel that takes a release as an upload
#
# It builds no binary and runs none: it builds its tool (scripts/release) from
# the tag itself (go.sum checks its modules), and checks the binaries with it
# before it signs them, in this order: the directory holds the six binaries and
# MANIFEST and nothing else; MANIFEST has the SHA-256 that the job that built
# gave (POSTERN_MANIFEST_SHA256); the binaries have the sums of MANIFEST; each is
# a static Go program of its command and architecture, with the version and the
# commit of the tag (psiphon-core: the SHA-256 that the panel pins). Then it signs each binary with the release key ("postern
# <component> <tag> linux/<arch>"), writes and signs SHA256SUMS ("postern
# sha256sums <tag>"), verifies every signature with the public half of the key,
# and makes the bundle. The checks prove that the files are those that the job
# that built made, not that it built them honestly (docs/releasing.md).
#
# A tag with a "-" in it (v0.5.0-rc.1) is a prerelease. A release that is not one
# has to be signed by one of the production release keys of the tag
# (internal/release/keys.go), or sign refuses it: the binaries that run could not
# verify it. Only a prerelease takes POSTERN_EXTRA_PUBLIC_KEYS: test keys,
# minisign public keys apart by commas, that its binaries then trust as well
# (-X .../internal/release.extraPublicKeys), for test servers; build and sign
# refuse them for a release.
#
# The mode for a workstation runs build and sign one after the other and puts
# the release in dist/ of the repository. There the key is in the shell that
# runs npm, so it is for test keys and for trying the script out, not for the
# key of the releases. It needs git, Go and Node 24 with npm: on a workstation, a
# container that has them (docs/releasing.md).
#
# Environment:
#   POSTERN_RELEASE_KEY           the text of the secret release key file (sign, workstation)
#   POSTERN_RELEASE_KEY_PASSWORD  its password, when it is encrypted
#   POSTERN_MANIFEST_SHA256       the SHA-256 of MANIFEST that build gave (sign)
#   POSTERN_EXTRA_PUBLIC_KEYS     test keys of a prerelease (see above)
#   POSTERN_NODE_IMAGE            the node image of the release, a name without a
#                                 tag (ghcr.io/<OWNER>/postern-node): the panel
#                                 binaries get it as their default node image
#                                 (-X .../internal/version.NodeImage), which the
#                                 panel tags with its version (build, workstation)
#
# Nothing of the key or of its password is printed. Both are taken out of the
# environment before anything else runs, and only the tool that signs gets the
# password. The key is a file of the temporary directory only while it is used:
# to read its public half, and to sign.

# Tracing (bash -x) would print the key.
set +x
set -euo pipefail

log() { printf 'release.sh: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}
usage() {
  die "usage: bash scripts/release.sh build <tag> <outdir> | sign <tag> <indir> <outdir> | <tag> (a workstation)"
}

indir=
outdir=
case ${1:-} in
  build)
    [ "$#" -eq 3 ] || usage
    mode=build tag=$2 outdir=$3
    ;;
  sign)
    [ "$#" -eq 4 ] || usage
    mode=sign tag=$2 indir=$3 outdir=$4
    ;;
  *)
    [ "$#" -eq 1 ] || usage
    mode=workstation tag=$1
    ;;
esac
# The directories are named from where the script was started.
absolute() {
  case $1 in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$PWD" "$1" ;;
  esac
}
[ -z "$indir" ] || indir=$(absolute "$indir")
[ -z "$outdir" ] || outdir=$(absolute "$outdir")

# v<major>.<minor>.<patch>, and a prerelease after a "-": a version to
# internal/release, a tag of a Docker image and a part of a file name at once.
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ! [[ $tag =~ $semver ]] || [ "${#tag}" -gt 64 ]; then
  die "$tag is not the tag of a version: v<major>.<minor>.<patch>, with -<prerelease> after it for a prerelease (v0.5.0, v0.5.0-rc.1)"
fi
case $tag in
  *-*) prerelease=true ;;
  *) prerelease=false ;;
esac

key_text=${POSTERN_RELEASE_KEY:-}
password=${POSTERN_RELEASE_KEY_PASSWORD:-}
manifest_sha=${POSTERN_MANIFEST_SHA256:-}
extra=${POSTERN_EXTRA_PUBLIC_KEYS:-}
node_image=${POSTERN_NODE_IMAGE:-}
unset POSTERN_RELEASE_KEY POSTERN_RELEASE_KEY_PASSWORD POSTERN_MINISIGN_PASSWORD POSTERN_MANIFEST_SHA256 POSTERN_EXTRA_PUBLIC_KEYS POSTERN_NODE_IMAGE
if [ "$mode" != build ] && [ -z "$key_text" ]; then
  die "POSTERN_RELEASE_KEY is empty: it holds the text of the secret release key file"
fi
if [ "$mode" = sign ] && ! [[ $manifest_sha =~ ^[0-9a-f]{64}$ ]]; then
  die "POSTERN_MANIFEST_SHA256 is not the SHA-256 of a MANIFEST (64 lower-case hex digits): it is what build gave"
fi
if [ -n "$extra" ]; then
  if [ "$prerelease" = false ]; then
    die "POSTERN_EXTRA_PUBLIC_KEYS is set, and $tag is not a prerelease: test keys go into prereleases only"
  fi
  # The value goes into -ldflags: base64 and commas, nothing else.
  if ! [[ $extra =~ ^[A-Za-z0-9+/=]+(,[A-Za-z0-9+/=]+)*$ ]]; then
    die "POSTERN_EXTRA_PUBLIC_KEYS is not a list of minisign public keys apart by commas"
  fi
fi
# The value goes into -ldflags, and the panel refuses to start with a default
# that is not a reference (internal/panel/nodes): an optional registry host with
# a port, then lower-case path components, and no tag and no digest, since the
# panel adds its version as the tag and the release pushes <name>:<tag>.
name_part='[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*'
host='[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?'
if [ -n "$node_image" ] && { ! [[ $node_image =~ ^($host/)?$name_part(/$name_part)*$ ]] || [ "${#node_image}" -gt 255 ]; }; then
  die "POSTERN_NODE_IMAGE is not the name of an image without a tag (ghcr.io/<OWNER>/postern-node)"
fi

tools="git go tar"
[ "$mode" = sign ] || tools="$tools node npm curl"
for tool in $tools; do
  command -v "$tool" > /dev/null 2>&1 ||
    die "$tool is not on PATH: $mode needs $tools (docs/releasing.md)"
done
if [ "$mode" != sign ]; then
  node_version=$(node --version)
  case $node_version in
    v24.*) ;;
    *) die "the UI of a release is built with Node 24, and this is Node $node_version" ;;
  esac
fi
if [ -n "$outdir" ] && [ -e "$outdir" ] && [ -n "$(ls -A "$outdir" 2> /dev/null || echo x)" ]; then
  die "$outdir is there and not an empty directory: name a new one"
fi
if [ -n "$indir" ] && ! [ -d "$indir" ]; then
  die "$indir is not a directory"
fi

root=$(git rev-parse --show-toplevel) || die "git takes $PWD for no repository (above is why): run release.sh in a checkout of Postern"
cd "$root"
commit=$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}") || die "there is no tag $tag"
short=${commit:0:12}
epoch=$(git log -1 --format=%ct "$commit")
date=$(TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ "$commit")

work=$(mktemp -d "${TMPDIR:-/tmp}/postern-release.XXXXXX")
src=$work/src
key=$work/release.key
tool=$work/release-tool
# The directory goes however the script ends, and the key first: a signal (a
# job that is cancelled) is made an exit, which runs the EXIT trap, and a
# process of the build that is still writing into the directory when the shell
# exits (npm, killed with it) can make the first rm -rf fail.
cleanup() {
  rm -f "$key"
  rm -rf "$work" 2> /dev/null || {
    sleep 2
    rm -rf "$work"
  }
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

log "exporting $tag ($short) into $src"
mkdir "$src"
git archive --format=tar "$commit" | tar -x -f - -C "$src"

log "building the release tool of $tag"
tool_env=()
if [ "$mode" = sign ]; then
  # The tool that holds the key is built with caches of its own: a cache that
  # the runner restored could hold a trojaned package, written there by a job
  # that ran npm (S5-12). -modcacherw lets the cleanup remove the modules.
  tool_env=(GOCACHE="$work/gocache" GOMODCACHE="$work/gomod" GOFLAGS="-mod=readonly -modcacherw")
fi
(cd "$src" && env -u GOOS -u GOARCH CGO_ENABLED=0 GOFLAGS=-mod=readonly ${tool_env[@]+"${tool_env[@]}"} go build -trimpath -o "$tool" ./scripts/release)

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# move_to <dir> <destination>: the destination, which is empty or not there,
# becomes dir.
move_to() {
  rmdir "$2" 2> /dev/null || true
  mkdir -p "$(dirname "$2")"
  mv "$1" "$2"
}

write_key() { (umask 077 && printf '%s\n' "$key_text" > "$key"); }

# check_key reads the public half of the key into pub and refuses a key that is
# not a production release key of the tag for a release that is not a
# prerelease.
pub=
check_key() {
  write_key
  pub=$(POSTERN_MINISIGN_PASSWORD=$password "$tool" pubkey --key "$key") || die "the release key does not open (see above)"
  rm -f "$key"
  log "the release key is $pub"
  # keys says on stderr when a set has no production key, or one that is malformed.
  if "$tool" keys | awk -v key="$pub" '$1 == "release" && $3 == key { found = 1 } END { exit !found }'; then
    log "it is a production release key of $tag"
  elif [ "$prerelease" = true ]; then
    log "it is not a production release key of $tag, which is a prerelease"
  else
    die "$tag is not a prerelease, and the release key is not one of the production release keys of $tag (internal/release/keys.go): the binaries that run could not verify the release"
  fi
}

# build_into <dir>: the six binaries and MANIFEST.
build_into() {
  local out=$1 arch component ldflags more version_pkg=github.com/urbnywrt/postern/internal/version
  log "building the web UI (npm ci, npm run build)"
  # Install scripts of packages are not run: the build needs none of them.
  (cd "$src/web" && npm ci --no-audit --no-fund --ignore-scripts && npm run build)
  [ -f "$src/web/dist/index.html" ] || die "the build of the UI made no web/dist/index.html"
  cp -R "$src/web/dist/." "$src/internal/panel/webui/dist/"

  mkdir "$out"
  ldflags="-s -w -X $version_pkg.Version=$tag -X $version_pkg.Commit=$short -X $version_pkg.Date=$date"
  if [ -n "$extra" ]; then
    ldflags="$ldflags -X github.com/urbnywrt/postern/internal/release.extraPublicKeys=$extra"
    log "the binaries trust the test keys of POSTERN_EXTRA_PUBLIC_KEYS as well"
  fi
  # Everything in the flags is public, and they are what it takes to build the
  # same binaries again (-trimpath leaves -ldflags out of go version -m).
  log "go build flags: -trimpath -buildvcs=false -ldflags \"$ldflags\""
  # The default node image goes into the panel only.
  local panel_more=
  if [ -n "$node_image" ]; then
    panel_more=" -X $version_pkg.NodeImage=$node_image"
    log "and for postern-panel:$panel_more"
  fi
  for arch in amd64 arm64; do
    for component in node panel; do
      more=
      [ "$component" != panel ] || more=$panel_more
      log "building postern-$component for linux/$arch"
      # The defaults of the architectures and of the module, whatever the
      # environment says: a release runs on every amd64 and arm64 machine.
      (cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOAMD64=v1 GOARM64=v8.0 GOFLAGS=-mod=readonly \
        go build -trimpath -buildvcs=false -ldflags "$ldflags$more" -o "$out/postern-$component-linux-$arch" "./cmd/$component")
    done
  done
  # The Psiphon client, from its pinned upstream commit (Ruling S2-26).
  bash "$src/scripts/psiphon-core.sh" "$out"
  "$tool" sums "$out/postern-node-linux-amd64" "$out/postern-node-linux-arm64" \
    "$out/postern-panel-linux-amd64" "$out/postern-panel-linux-arm64" \
    "$out/psiphon-core-linux-amd64" "$out/psiphon-core-linux-arm64"
  mv "$out/SHA256SUMS" "$out/MANIFEST"
}

# sign_into <indir> <manifest sha256> <dir>: the files of the release.
sign_into() {
  local in=$work/in out=$3 arch component
  # The files are checked and signed in a copy of their own, which nothing else
  # writes to; cp -R copies a link as a link, and check-build refuses it.
  mkdir "$in"
  cp -R "$1/." "$in/"
  "$tool" check-build --version "$tag" --commit "$short" --manifest-sha256 "$2" "$in"
  [ -n "$pub" ] || check_key

  mkdir "$out"
  for arch in amd64 arm64; do
    for component in postern-node postern-panel psiphon-core; do
      cp "$in/$component-linux-$arch" "$out/"
      chmod 0755 "$out/$component-linux-$arch"
    done
  done
  log "signing"
  write_key
  for arch in amd64 arm64; do
    for component in postern-node postern-panel psiphon-core; do
      POSTERN_MINISIGN_PASSWORD=$password "$tool" sign --key "$key" \
        --component "$component" --version "$tag" --arch "$arch" "$out/$component-linux-$arch"
    done
  done
  "$tool" sums "$out/postern-node-linux-amd64" "$out/postern-node-linux-arm64" \
    "$out/postern-panel-linux-amd64" "$out/postern-panel-linux-arm64" \
    "$out/psiphon-core-linux-amd64" "$out/psiphon-core-linux-arm64"
  POSTERN_MINISIGN_PASSWORD=$password "$tool" sign --key "$key" --component sha256sums --version "$tag" "$out/SHA256SUMS"
  rm -f "$key"

  log "verifying every signature with $pub"
  for arch in amd64 arm64; do
    for component in postern-node postern-panel psiphon-core; do
      "$tool" verify --pubkey "$pub" --component "$component" --version "$tag" --arch "$arch" \
        "$out/$component-linux-$arch"
    done
  done
  "$tool" verify --pubkey "$pub" --component sha256sums --version "$tag" "$out/SHA256SUMS"
  SOURCE_DATE_EPOCH=$epoch "$tool" bundle --version "$tag" "$out"
}

case $mode in
  build)
    build_into "$work/unsigned"
    move_to "$work/unsigned" "$outdir"
    log "$outdir holds the build of $tag; the SHA-256 of its MANIFEST is $(sha256_of "$outdir/MANIFEST")"
    ;;
  sign)
    sign_into "$indir" "$manifest_sha" "$work/dist"
    move_to "$work/dist" "$outdir"
    log "$outdir holds the release $tag:"
    (cd "$outdir" && ls -l && cat SHA256SUMS) >&2
    ;;
  workstation)
    # The key is checked before the build, which takes minutes.
    check_key
    build_into "$work/unsigned"
    sign_into "$work/unsigned" "$(sha256_of "$work/unsigned/MANIFEST")" "$work/dist"
    rm -rf "${root:?}/dist"
    move_to "$work/dist" "$root/dist"
    log "dist/ holds the release $tag:"
    (cd "$root/dist" && ls -l && cat SHA256SUMS) >&2
    ;;
esac
