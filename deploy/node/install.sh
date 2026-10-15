#!/usr/bin/env bash
# Postern node installer.
#
#   sudo bash install.sh --bundle postern-node-bundle.tar --version v1.2.3
#   sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node
#
# What it does:
#
#   1. checks the arguments, root, Docker with the Compose plugin, that Docker does
#      not remap user namespaces, the bundle and the binary. These checks run before
#      the PKI, the state, the links, the launcher or the compose file of an existing
#      installation are touched, so a bad argument leaves a working node alone.
#   2. creates the layout under /opt/postern (README.md has the picture).
#   3. state: the node id from the bundle is kept in data/state/node-id. When the
#      state directory holds the state of another node (a different id, or no id at
#      all), it is moved aside to data/state.bak-<unix time> first, so a node that is
#      installed again under a new identity never reports an old generation.
#   4. unpacks the bundle into pki/ (key and certificates 0600).
#   5. installs the binary as bin/postern-node-<version> and points bin/current at it.
#      The version bin/current pointed to before becomes bin/previous, which is what
#      the launcher rolls back to. The signature of the binary, the release's
#      postern-node-linux-<arch>.minisig or <binary>.minisig beside a --binary, is
#      kept beside it as bin/.postern-node-<version>.minisig, also on a re-run, once
#      its trusted comment names this version and architecture: the agent verifies
#      it before it rolls the edge to a version that it does not run itself.
#   6. copies launcher.sh and compose.yaml, which must be next to this script.
#   7. reserves the loopback ports of the node, 20000-40999, in
#      net.ipv4.ip_local_reserved_ports, so that the kernel never picks one as the
#      local port of an outgoing connection: set at once with sysctl -w, and kept
#      for the next boots in /etc/sysctl.d/90-postern.conf. The ports that are
#      reserved already stay reserved. The same file and sysctl -w set
#      net.ipv4.tcp_migrate_req = 1 (Linux 5.14 or later), so that an edge roll
#      moves the connections still in the accept queue of the old generation to
#      the new one instead of aborting them. What cannot be done (the file cannot
#      be written, sysctl refuses a setting, the kernel has no tcp_migrate_req)
#      is a warning, and the install goes on.
#   8. starts the agent with: docker compose -f /opt/postern/compose.yaml up -d
#      --force-recreate. Recreating the container is what makes a re-run pick up a
#      new binary or a new bundle. It only restarts the management agent: the edge
#      and the engines are separate containers and keep serving, the edge with the
#      binary that it was started with (see --roll-edge).
#
#   sudo bash install.sh --roll-edge
#
# asks the agent of the node for a new generation of the edge, which runs the binary
# of bin/current: it writes data/run/roll-edge, and changes nothing else.
#
# Running it again is safe: same arguments change nothing but the agent restart.
# Docker is not installed by this script.
#
# Environment:
#   POSTERN_RELEASE_BASE  the base URL of the release downloads; --version needs it,
#                         and curl. It has to be https:// (or file://, for a mirror
#                         on this host): the binary runs as root, so nothing that is
#                         sent in the clear is taken. Any other scheme, http://
#                         included, is refused.
#   POSTERN_HOME          the install root, /opt/postern. For tests only: the compose
#                         file and the agent assume /opt/postern.
#   POSTERN_SYSCTL_DIR    where the sysctl file goes, /etc/sysctl.d. For tests only.

if [ -z "${BASH_VERSION:-}" ]; then
  echo "install.sh: run it with bash:  sudo bash install.sh --bundle <file>" >&2
  exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "install.sh: bash 4 or newer is required" >&2
  exit 1
fi

set -euo pipefail
export LC_ALL=C

NODE_ID_RE='^[0-9A-Z]{26}$'
VERSION_RE='^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'
# The most that one file of the bundle may hold, in bytes.
MAX_FILE=65536
# The loopback ports of the node: engines, engine APIs, the SOCKS ports of the edge
# and of the egress helpers, and the service listeners (Global Constraints).
RESERVED_PORTS=20000-40999
RESERVED_PORTS_KEY=net.ipv4.ip_local_reserved_ports
# What makes an edge roll safe for the connections in the accept queue of the
# generation that drains (finding F2); MIGRATE_REQ_SUPPORTED is set when the
# kernel has it (Linux 5.14 or later).
MIGRATE_REQ_KEY=net.ipv4.tcp_migrate_req
MIGRATE_REQ_SUPPORTED=

HOME_DIR=${POSTERN_HOME:-/opt/postern}
HOME_DIR=${HOME_DIR%/}
BIN_DIR=$HOME_DIR/bin
PKI_DIR=$HOME_DIR/pki
STATE_DIR=$HOME_DIR/data/state
SYSCTL_DIR=${POSTERN_SYSCTL_DIR:-/etc/sysctl.d}
SYSCTL_DIR=${SYSCTL_DIR%/}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Set by parse_args.
BUNDLE=
BINARY=
VERSION=
ROLL_EDGE=
# Set by read_bundle.
NODE_ID=
MGMT_PORT=
# Set by prepare_binary: the file name under bin/, and the verified file to move
# there (empty when the file is in place already).
BIN_NAME=
BIN_SRC=
# Set by prepare_binary: the checked signature to keep beside the binary, or empty.
SIG_SRC=
# Temporary directories, removed on exit.
STAGE=
STAGE_BIN=

cleanup() {
  if [ -n "$STAGE" ]; then rm -rf -- "$STAGE"; fi
  if [ -n "$STAGE_BIN" ]; then rm -rf -- "$STAGE_BIN"; fi
}

step() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'install.sh: warning: %s\n' "$*" >&2; }
die() {
  printf 'install.sh: error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat << 'EOF'
usage: sudo bash install.sh --bundle <file> [--binary <path>] [--version <v>]
       sudo bash install.sh --roll-edge

  --bundle <file>   postern-node-bundle.tar from the panel: the node's certificate
                    and key, the CA and the management port. Required.
  --binary <path>   the postern-node binary to install.
  --version <v>     with --binary, the version to install it under (default: what
                    the binary prints for "version"); without it, the release to
                    download (needs POSTERN_RELEASE_BASE and curl, see README.md).
                    With neither, the installed binary is kept.
  --roll-edge       on its own: ask the agent of the installed node to start a new
                    generation of the edge, with the binary of bin/current, and to
                    drain the running one. Use it after an update of the binary:
                    until then the edge runs the binary that it was started with.
  -h, --help        this text.

Environment:
  POSTERN_RELEASE_BASE   base URL of the release downloads, for --version: https://
                         (or file://, for a mirror on this host), nothing else
EOF
}

usage_error() {
  printf 'install.sh: %s\n\n' "$1" >&2
  usage >&2
  exit 2
}

valid_node_id() { [[ $1 =~ $NODE_ID_RE ]]; }
valid_version() { [[ $1 =~ $VERSION_RE ]]; }

set_option() {
  case $1 in
    --bundle) BUNDLE=$2 ;;
    --binary) BINARY=$2 ;;
    --version) VERSION=$2 ;;
  esac
}

parse_args() {
  if [ $# -eq 0 ]; then
    usage >&2
    exit 2
  fi
  while [ $# -gt 0 ]; do
    case $1 in
      -h | --help)
        usage
        exit 0
        ;;
      --bundle | --binary | --version)
        [ $# -ge 2 ] || usage_error "$1 needs a value"
        set_option "$1" "$2"
        shift 2
        ;;
      --bundle=* | --binary=* | --version=*)
        set_option "${1%%=*}" "${1#*=}"
        shift
        ;;
      --roll-edge)
        ROLL_EDGE=1
        shift
        ;;
      *) usage_error "unknown argument: $1" ;;
    esac
  done
  if [ -n "$ROLL_EDGE" ]; then
    [ -z "$BUNDLE$BINARY$VERSION" ] || usage_error "--roll-edge goes on its own: it installs nothing"
    return 0
  fi
  [ -n "$BUNDLE" ] || usage_error "--bundle is required"
  if [ -n "$VERSION" ] && ! valid_version "$VERSION"; then
    usage_error "invalid --version: $VERSION"
  fi
  # GNU tar takes the name of an archive with a colon in it (host:file) for a
  # file on another machine, unless a slash comes before the colon. Every
  # relative name starts with ./, so that every tar reads a local file and no
  # option is needed for it: busybox tar knows no --force-local.
  case $BUNDLE in
    /*) ;;
    *) BUNDLE=./$BUNDLE ;;
  esac
}

# ---- checks ----------------------------------------------------------------------

require_root() {
  [ "$(id -u)" -eq 0 ] || die "this script must run as root: sudo bash install.sh ..."
}

docker_help() {
  cat >&2 << 'EOF'

The Postern node agent runs in Docker, and this script does not install Docker.
Install Docker Engine with the Compose v2 plugin, then run this script again.
On Debian and Ubuntu that is:

    apt-get install -y docker.io docker-compose-v2

On other systems follow the Docker Engine installation guide for your distribution.
EOF
}

check_docker() {
  local security
  if ! command -v docker > /dev/null 2>&1; then
    docker_help
    die "Docker is not installed"
  fi
  if ! security=$(docker info --format '{{.SecurityOptions}}' 2> /dev/null); then
    die "cannot talk to the Docker daemon: is it running?"
  fi
  case $security in
    *name=userns*)
      die "Docker runs with user namespace remapping (userns-remap), which Postern does not support:" \
        "the edge generations have to share their ports under the same UID. Remove \"userns-remap\"" \
        "from /etc/docker/daemon.json, restart Docker and run this script again."
      ;;
  esac
  if ! docker compose version > /dev/null 2>&1; then
    docker_help
    die "the Docker Compose v2 plugin is missing: 'docker compose version' fails"
  fi
}

check_sources() {
  local f
  for f in launcher.sh compose.yaml; do
    [ -f "$SCRIPT_DIR/$f" ] || die "$f must be next to install.sh (looked in $SCRIPT_DIR)"
  done
}

# ---- the bundle ------------------------------------------------------------------

# json_field JSON KEY KIND prints the value of the key KEY (KIND is string or
# integer). It fails unless the key occurs exactly once and has such a value.
# bundle.json is one flat object written by the panel; whatever is read here is
# checked again by the caller.
json_field() {
  local json=$1 key=$2 kind=$3 count value
  count=$(printf '%s\n' "$json" | { grep -o "\"$key\"" || true; } | wc -l)
  [ "$count" -eq 1 ] || return 1
  case $kind in
    string) value=$(printf '%s\n' "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') ;;
    integer) value=$(printf '%s\n' "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*\([,}].*\)\{0,1\}$/\1/p') ;;
    *) return 1 ;;
  esac
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

# read_member ARCHIVE ENTRY DEST copies the content of one member of the archive
# into the file DEST (private: umask 077). The copy stops after MAX_FILE + 1
# bytes, as it is written: a member can be of any size, and none of it may be
# written to the disk beyond what the caller needs to tell that it is too big
# (more than MAX_FILE bytes arrive). It fails when tar cannot read the member or
# DEST cannot be written; a tar that is cut off by the cap has not failed. tar is
# given only the options that busybox tar knows as well, and ARCHIVE is a name
# that every tar reads as a local file (see parse_args).
read_member() {
  (
    # The statuses of both ends of the pipe are wanted, not the verdict of the
    # shell on them.
    set +e +o pipefail
    umask 077
    tar -xOf "$1" -- "$2" 2> /dev/null | head -c "$((MAX_FILE + 1))" > "$3"
    status=("${PIPESTATUS[@]}")
    [ "${status[1]}" -eq 0 ] || exit 1
    # head stops reading when it has enough, and tar is then cut off (a broken
    # pipe): that is how a member that is too big ends, and is not a failure.
    [ "${status[0]}" -eq 0 ] || [ "$(wc -c < "$3")" -gt "$MAX_FILE" ]
  )
}

# read_bundle checks the bundle strictly, as the panel's own parser does: exactly
# the four files of a version 1 bundle, each once and at most 64 KiB, and a node id
# and a port that make sense. Nothing is unpacked from the archive: the content of
# each file is read to a file of ours (read_member, which stops at the size limit),
# so the archive decides neither names nor modes nor owners. The files land in
# $STAGE; NODE_ID and MGMT_PORT are set.
read_bundle() {
  local file=$1 entries entry name size json version
  local -A found=()
  [ -f "$file" ] || die "bundle not found: $file"
  entries=$(tar -tf "$file" 2> /dev/null) || die "$file is not a tar archive; expected the postern-node-bundle.tar from the panel"
  while IFS= read -r entry; do
    name=${entry#./}
    case $name in
      '') continue ;;
      bundle.json | ca.pem | node.pem | node-key.pem) ;;
      *) die "unexpected entry in the bundle: $entry" ;;
    esac
    [ -z "${found[$name]:-}" ] || die "the bundle lists $name twice"
    found[$name]=$entry
  done <<< "$entries"
  for name in bundle.json ca.pem node.pem node-key.pem; do
    [ -n "${found[$name]:-}" ] || die "the bundle has no $name"
    read_member "$file" "${found[$name]}" "$STAGE/$name" 2> /dev/null || die "cannot read $name from the bundle"
    size=$(wc -c < "$STAGE/$name")
    if [ "$size" -eq 0 ] || [ "$size" -gt "$MAX_FILE" ]; then
      die "$name in the bundle is empty or larger than 64 KiB"
    fi
  done

  json=$(< "$STAGE/bundle.json")
  version=$(json_field "$json" version integer) || die "bundle.json has no usable \"version\""
  [ "$version" = 1 ] || die "unsupported bundle version $version: this installer reads version 1"
  NODE_ID=$(json_field "$json" node_id string) || die "bundle.json has no usable \"node_id\""
  valid_node_id "$NODE_ID" || die "the node id in the bundle is not valid: expected 26 characters, 0-9 and A-Z"
  MGMT_PORT=$(json_field "$json" mgmt_port integer) || die "bundle.json has no usable \"mgmt_port\""
  if [ "${#MGMT_PORT}" -gt 5 ] || [ $((10#$MGMT_PORT)) -lt 1 ] || [ $((10#$MGMT_PORT)) -gt 65535 ]; then
    die "the management port in the bundle is out of range: $MGMT_PORT"
  fi
  MGMT_PORT=$((10#$MGMT_PORT))

  grep -q -- '-----BEGIN CERTIFICATE-----' "$STAGE/ca.pem" || die "ca.pem in the bundle is not a PEM certificate"
  grep -q -- '-----BEGIN CERTIFICATE-----' "$STAGE/node.pem" || die "node.pem in the bundle is not a PEM certificate"
  grep -Eq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$STAGE/node-key.pem" || die "node-key.pem in the bundle is not a PEM private key"
}

# ---- files -----------------------------------------------------------------------

# make_dir MODE DIR
make_dir() {
  mkdir -p -- "$2"
  chmod "$1" -- "$2"
}

# make_layout creates the directories of the node (spec 5.1). Everything that holds
# keys, credentials or client data is root only.
make_layout() {
  local d
  make_dir 0755 "$HOME_DIR"
  make_dir 0755 "$BIN_DIR"
  make_dir 0700 "$PKI_DIR"
  make_dir 0700 "$HOME_DIR/data"
  for d in state edge run run/launcher instances certs; do
    make_dir 0700 "$HOME_DIR/data/$d"
  done
  make_dir 0755 "$HOME_DIR/data/artifacts"
}

# put_file MODE SRC DEST copies SRC over DEST in one rename, so a running reader
# never sees half a file, and DEST is never readable by others on the way.
put_file() {
  local mode=$1 src=$2 dest=$3 tmp
  tmp=$(dirname -- "$dest")/.$(basename -- "$dest").new.$$
  rm -f -- "$tmp"
  (umask 077 && cp -- "$src" "$tmp")
  chmod "$mode" -- "$tmp"
  mv -f -- "$tmp" "$dest"
}

# set_link NAME TARGET makes bin/NAME a symlink to TARGET, in one rename. The link is
# relative: the volume is mounted at the same path in the agent, but the edge and the
# engines see the files under other paths.
set_link() {
  local tmp=$BIN_DIR/.$1.new.$$
  rm -f -- "$tmp"
  ln -s -- "$2" "$tmp"
  mv -f -- "$tmp" "$BIN_DIR/$1"
}

sha256_of() {
  sha256sum -- "$1" | awk '{ print $1 }'
}

# ---- the binary ------------------------------------------------------------------

# without_userinfo TEXT prints TEXT with the user name and password taken out of
# every URL in it (scheme://user:password@host/... becomes scheme://host/...): a
# release base may carry credentials, and nothing that the script prints repeats
# them.
without_userinfo() {
  printf '%s\n' "$1" | sed 's|\([A-Za-z][A-Za-z0-9+.-]*://\)[^/?#[:space:]]*@|\1|g'
}

# need_curl dies unless curl is installed. A release is downloaded with curl and
# nothing else: wget cannot be kept from following a redirect from https to http,
# and the binary runs as root.
need_curl() {
  command -v curl > /dev/null 2>&1 \
    || die "release downloads (--version) need curl, which is not installed: install curl, or install the postern-node binary of the panel's node kit with --binary (see README.md)"
}

# fetch URL DEST downloads URL to DEST with curl, which is told to take https and
# file URLs only, and to follow a redirect over https only (so a server cannot send
# it on to http, or to a file of this host). The caller has checked the URL already
# (download_release); this is the second lock on the door. What curl says about a
# failure is passed on, without the credentials of a URL.
fetch() {
  local err
  if ! err=$(try_fetch "$1" "$2" 2>&1); then
    if [ -n "$err" ]; then without_userinfo "$err" >&2; fi
    die "download failed: $(without_userinfo "$1")"
  fi
}

# try_fetch URL DEST is fetch that fails instead of dying, with what curl says on
# stderr, for a file that the install can go without.
try_fetch() {
  curl --fail --silent --show-error --location --proto '=https,file' --proto-redir '=https' --retry 3 \
    --connect-timeout 15 --output "$2" "$1"
}

# host_arch prints the architecture of this host as the release assets name it.
host_arch() {
  case $(uname -m) in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
}

# check_signature FILE VERSION dies unless FILE is a minisign signature of
# postern-node VERSION for this host, by its trusted comment, "postern postern-node
# <version> linux/<arch>", as the release job signs one: four lines, the comments
# and two of base64, at most MAX_FILE bytes. The key and the signature are not
# checked here (this script has no minisign): the agent verifies them with its
# release keys before an edge runs the binary, and refuses a bad one.
check_signature() {
  local file=$1 version=$2 arch size
  arch=$(host_arch)
  size=$(wc -c < "$file")
  [ "$size" -le "$MAX_FILE" ] || die "the signature of postern-node $version is larger than $MAX_FILE bytes: it is no minisign signature"
  awk -v want="trusted comment: postern postern-node $version linux/$arch" '
    NR == 1 && !/^untrusted comment: / { exit 1 }
    (NR == 2 || NR == 4) && !/^[A-Za-z0-9+\/]+=?=?$/ { exit 1 }
    NR == 3 && $0 != want { exit 1 }
    NR > 4 { exit 1 }
    END { if (NR != 4) exit 1 }
  ' "$file" || die "the signature beside postern-node $version is not a minisign signature of postern-node $version for linux/$arch (its trusted comment must be: postern postern-node $version linux/$arch)"
}

# download_signature BASE VERSION downloads the signature of the node binary of a
# release, <base>/<version>/postern-node-linux-<arch>.minisig, into STAGE_BIN,
# checks it (check_signature) and sets SIG_SRC to it. A release without one still
# installs, with a warning: the binary has passed SHA256SUMS, but an edge rolls to
# a version only with its signature kept, or while the agent runs that version.
download_signature() {
  local url
  url=$1/$2/postern-node-linux-$(host_arch).minisig
  if try_fetch "$url" "$STAGE_BIN/postern-node.minisig" 2> /dev/null; then
    check_signature "$STAGE_BIN/postern-node.minisig" "$2"
    SIG_SRC=$STAGE_BIN/postern-node.minisig
  else
    rm -f -- "$STAGE_BIN/postern-node.minisig"
    warn "no signature downloaded from $(without_userinfo "$url"): none is kept for postern-node $2, and the edge rolls to it only while the agent runs it"
  fi
}

# fetch_signature VERSION fetches the signature of a release that is installed
# already but has none kept (an older install.sh kept none), when
# POSTERN_RELEASE_BASE says where from and curl is there. The install does not need
# it, so what keeps it from being fetched is a note, not an error.
fetch_signature() {
  local base=${POSTERN_RELEASE_BASE:-}
  case ${base,,} in
    https://?* | file://?*) ;;
    *)
      note "no signature is kept for postern-node $1; an https:// POSTERN_RELEASE_BASE would fetch it"
      return
      ;;
  esac
  if ! command -v curl > /dev/null 2>&1; then
    note "no signature is kept for postern-node $1; with curl installed it would be fetched"
    return
  fi
  STAGE_BIN=$(mktemp -d "$BIN_DIR/.stage.XXXXXX")
  download_signature "${base%/}" "$1"
}

# check_release_base BASE dies unless BASE is an https:// URL, or a file:// one for a
# mirror on this host. The binary that is downloaded runs as root, so it is never
# taken over a connection that is not encrypted, and any other scheme (ftp://, a
# bare host name, ...) is not a place that a release is known to be at. The value is
# not echoed: a base may have a password in it.
check_release_base() {
  case ${1,,} in
    https://?* | file://?*) ;;
    http://*) die "POSTERN_RELEASE_BASE is a plain http:// URL, which is refused: the binary would be downloaded over a connection that is not encrypted, and it runs as root. Use an https:// base (or file:// for a mirror on this host)" ;;
    *) die "POSTERN_RELEASE_BASE must start with https:// (or file:// for a mirror on this host): no other scheme is taken" ;;
  esac
}

# download_release VERSION DEST downloads and verifies the node binary of a release:
# <base>/<version>/postern-node-linux-<arch>, checked against <base>/<version>/SHA256SUMS.
# The base is POSTERN_RELEASE_BASE, https:// or file:// only (check_release_base),
# and the download takes curl (need_curl). The checksum file comes from the same
# place as the binary, so it catches a broken or partial download, not a
# compromised release host.
download_release() {
  local version=$1 dest=$2 base arch asset expected actual
  base=${POSTERN_RELEASE_BASE:-}
  [ -n "$base" ] || die "--version needs POSTERN_RELEASE_BASE, the base URL of the release downloads (see README.md); or download the binary yourself and pass --binary"
  check_release_base "$base"
  need_curl
  base=${base%/}
  arch=$(host_arch)
  asset=postern-node-linux-$arch
  step "downloading $asset $version"
  fetch "$base/$version/$asset" "$dest"
  fetch "$base/$version/SHA256SUMS" "$STAGE_BIN/SHA256SUMS"
  expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$STAGE_BIN/SHA256SUMS")
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "SHA256SUMS has no entry for $asset"
  actual=$(sha256_of "$dest")
  [ "$actual" = "$expected" ] || die "checksum mismatch for $asset: expected $expected, got $actual"
  download_signature "$base" "$version"
}

# prepare_binary decides which binary goes in and checks it, without changing the
# installation. It sets BIN_NAME and BIN_SRC, and SIG_SRC when there is a signature
# to keep beside the binary: <binary>.minisig beside a --binary, the release's
# <asset>.minisig for --version (also for a release that is installed already
# without one).
prepare_binary() {
  local staged out running_version
  BIN_NAME=
  BIN_SRC=
  SIG_SRC=

  if [ -z "$BINARY" ] && [ -z "$VERSION" ]; then
    BIN_NAME=$(readlink "$BIN_DIR/current" 2> /dev/null || true)
    if [ -z "$BIN_NAME" ] || [ ! -x "$BIN_DIR/current" ]; then
      die "no binary to install: pass --binary <path> or --version <v>"
    fi
    note "keeping the installed binary $BIN_NAME"
    return
  fi

  # A release that is installed already is not downloaded again.
  if [ -z "$BINARY" ] && [ -f "$BIN_DIR/postern-node-$VERSION" ]; then
    BIN_NAME=postern-node-$VERSION
    note "$BIN_NAME is installed already"
    if [ ! -f "$BIN_DIR/.$BIN_NAME.minisig" ]; then fetch_signature "$VERSION"; fi
    return
  fi

  STAGE_BIN=$(mktemp -d "$BIN_DIR/.stage.XXXXXX")
  staged=$STAGE_BIN/postern-node
  if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || die "binary not found: $BINARY"
    cp -- "$BINARY" "$staged"
  else
    download_release "$VERSION" "$staged"
  fi
  chmod 0755 "$staged"

  # Run it once: this finds a binary for the wrong CPU now, not in a restart loop, and
  # tells the version when none was given. The staging directory is inside bin/,
  # so this works where /tmp is mounted noexec.
  out=$("$staged" version 2>&1) || die "the binary does not run on this host ($(uname -m)): ${out:-no output}"
  if [ -n "$VERSION" ]; then
    running_version=$VERSION
  else
    running_version=${out%%[[:space:]]*}
    valid_version "$running_version" || die "cannot tell the version of the binary (it printed: ${out:-nothing}): pass --version <v> to name it"
  fi
  if [ -n "$BINARY" ]; then
    if [ -f "$BINARY.minisig" ]; then
      cp -- "$BINARY.minisig" "$STAGE_BIN/postern-node.minisig"
      check_signature "$STAGE_BIN/postern-node.minisig" "$running_version"
      SIG_SRC=$STAGE_BIN/postern-node.minisig
    else
      note "no signature beside the binary ($BINARY.minisig): the edge rolls to $running_version only while the agent runs it"
    fi
  fi

  BIN_NAME=postern-node-$running_version
  BIN_SRC=$staged
  if [ -e "$BIN_DIR/$BIN_NAME" ]; then
    if [ "$(sha256_of "$BIN_DIR/$BIN_NAME")" != "$(sha256_of "$staged")" ]; then
      die "$BIN_NAME is installed already with different content: a version is never replaced, because bin/current or bin/previous may be running it. Pass another --version, or remove $BIN_DIR/$BIN_NAME first."
    fi
    BIN_SRC=
    note "$BIN_NAME is installed already"
  fi
}

# install_binary puts the file in place, then points bin/current at it. What bin/current
# pointed to becomes bin/previous. When bin/current points to the version already,
# nothing changes: a re-run must not make previous equal to current.
install_binary() {
  local cur
  if [ -n "$BIN_SRC" ]; then
    mv -f -- "$BIN_SRC" "$BIN_DIR/$BIN_NAME"
    BIN_SRC=
  fi
  # The signature goes beside the binary in one rename, where UpdateSelf keeps one:
  # bin/.postern-node-<version>.minisig. The agent needs it to roll the edge to a
  # version that it does not run itself (UpdateEdge), and verifies it then.
  if [ -n "$SIG_SRC" ]; then
    chmod 0644 -- "$SIG_SRC"
    mv -f -- "$SIG_SRC" "$BIN_DIR/.$BIN_NAME.minisig"
    SIG_SRC=
    note "bin/.$BIN_NAME.minisig: its signature, kept for the edge"
  fi
  cur=$(readlink "$BIN_DIR/current" 2> /dev/null || true)
  if [ "$cur" = "$BIN_NAME" ]; then
    return
  fi
  if [ -n "$cur" ] && [[ $cur != */* ]] && [ -f "$BIN_DIR/$cur" ]; then
    set_link previous "$cur"
    note "bin/previous -> $cur"
  fi
  set_link current "$BIN_NAME"
  note "bin/current -> $BIN_NAME"
}

# ---- state and keys --------------------------------------------------------------

# state_has_data succeeds when DIR holds anything besides the node id file.
state_has_data() (
  shopt -s dotglob nullglob
  local f
  for f in "$1"/*; do
    [ "${f##*/}" = node-id ] || exit 0
  done
  exit 1
)

stop_agent() {
  if docker inspect --type container postern-agent > /dev/null 2>&1; then
    note "stopping the running agent: its state is about to be replaced"
    docker stop postern-agent > /dev/null || die "cannot stop the running postern-agent"
  fi
}

# install_identity keeps data/state/node-id in step with the bundle. State that
# belongs to another node is moved aside, never deleted.
install_identity() {
  local idfile=$STATE_DIR/node-id existing= bak ts i=0
  if [ -f "$idfile" ]; then
    IFS= read -r -n 64 existing < "$idfile" || true
  fi
  if [ "$existing" != "$NODE_ID" ] && state_has_data "$STATE_DIR"; then
    stop_agent
    ts=$(date +%s)
    bak=$HOME_DIR/data/state.bak-$ts
    while [ -e "$bak" ]; do
      i=$((i + 1))
      bak=$HOME_DIR/data/state.bak-$ts-$i
    done
    mv -- "$STATE_DIR" "$bak"
    make_dir 0700 "$STATE_DIR"
    if valid_node_id "$existing"; then
      note "the state of node $existing is moved to ${bak#"$HOME_DIR"/}"
    else
      note "state of unknown origin is moved to ${bak#"$HOME_DIR"/}"
    fi
    note "the panel sends the desired state again when the node connects"
  fi
  printf '%s\n' "$NODE_ID" > "$STATE_DIR/node-id.new.$$"
  chmod 0600 "$STATE_DIR/node-id.new.$$"
  mv -f -- "$STATE_DIR/node-id.new.$$" "$idfile"
}

install_pki() {
  local f
  make_dir 0700 "$PKI_DIR"
  for f in ca.pem node.pem node-key.pem bundle.json; do
    put_file 0600 "$STAGE/$f" "$PKI_DIR/$f"
  done
}

# ---- reserved ports --------------------------------------------------------------

# port_list_union LIST... prints the union of the LISTs, each a comma-separated
# list of ports and ranges of ports as net.ipv4.ip_local_reserved_ports has them
# (8080,20000-40999), in that form: in order, with the ranges that overlap or
# touch joined. Blanks do not count, and an empty LIST adds nothing. It fails, and
# prints nothing, unless every item is a port or a range of ports from 0 to 65535.
port_list_union() {
  local list item lo hi first='' last='' out=''
  local -a items=() parts=()
  for list in "$@"; do
    list=${list//[[:space:]]/}
    [ -n "$list" ] || continue
    [[ $list =~ ^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$ ]] || return 1
    IFS=, read -r -a parts <<< "$list"
    for item in "${parts[@]}"; do
      lo=$((10#${item%-*}))
      hi=$((10#${item#*-}))
      if [ "$lo" -gt "$hi" ] || [ "$hi" -gt 65535 ]; then return 1; fi
      items+=("$lo $hi")
    done
  done
  [ "${#items[@]}" -gt 0 ] || return 0
  while read -r lo hi; do
    if [ -z "$first" ]; then
      first=$lo last=$hi
    elif [ "$lo" -le $((last + 1)) ]; then
      if [ "$hi" -gt "$last" ]; then last=$hi; fi
    else
      out=$out${out:+,}$first
      if [ "$last" -ne "$first" ]; then out=$out-$last; fi
      first=$lo last=$hi
    fi
  done < <(printf '%s\n' "${items[@]}" | sort -n -k1,1)
  out=$out${out:+,}$first
  if [ "$last" -ne "$first" ]; then out=$out-$last; fi
  printf '%s' "$out"
}

# reserved_ports_file LIST prints the sysctl file that reserves the ports of LIST,
# and sets net.ipv4.tcp_migrate_req when the kernel has it.
reserved_ports_file() {
  cat << EOF
# Written by the Postern node installer (install.sh), and again by each run of it.
# The loopback ports of the node, $RESERVED_PORTS, are reserved: the kernel never
# picks one of them as the local port of an outgoing connection, so the engines and
# the edge always find their ports free. The ports that were reserved already when
# the installer ran are in the list too.
$RESERVED_PORTS_KEY = $1
EOF
  if [ -n "$MIGRATE_REQ_SUPPORTED" ]; then
    cat << EOF
# The connections in the accept queue of an edge generation that drains move to
# the generation that takes over, instead of being aborted (Linux 5.14 or later).
$MIGRATE_REQ_KEY = 1
EOF
  fi
}

# check_migrate_req finds out whether the kernel has net.ipv4.tcp_migrate_req
# (MIGRATE_REQ_SUPPORTED), and warns when it does not: without it an edge roll
# aborts the connections still in the accept queue of the old generation.
check_migrate_req() {
  if sysctl -n "$MIGRATE_REQ_KEY" > /dev/null 2>&1; then
    MIGRATE_REQ_SUPPORTED=1
  else
    warn "this kernel has no $MIGRATE_REQ_KEY (it came with Linux 5.14): an edge roll may abort the connections still waiting to be accepted (see README.md)"
  fi
}

# enable_migrate_req sets net.ipv4.tcp_migrate_req = 1 in the running kernel with
# sysctl -w, that one key, and reads it back; the sysctl file (reserve_ports) keeps
# it for the boots to come. What goes wrong is a warning.
enable_migrate_req() {
  local now err
  [ -n "$MIGRATE_REQ_SUPPORTED" ] || return 0
  if now=$(sysctl -n "$MIGRATE_REQ_KEY" 2> /dev/null) && [ "$now" = 1 ]; then
    note "$MIGRATE_REQ_KEY = 1"
    return 0
  fi
  if ! err=$(sysctl -w "$MIGRATE_REQ_KEY=1" 2>&1 > /dev/null); then
    warn "sysctl -w $MIGRATE_REQ_KEY=1 failed ($(one_line "${err:-no message}")): an edge roll may abort the connections still waiting to be accepted until the next boot (see README.md)"
    return 0
  fi
  if now=$(sysctl -n "$MIGRATE_REQ_KEY" 2> /dev/null) && [ "$now" = 1 ]; then
    note "$MIGRATE_REQ_KEY = 1"
  else
    warn "sysctl -w $MIGRATE_REQ_KEY=1 did not take${err:+ (sysctl said: $(one_line "$err"))} (see README.md)"
  fi
  return 0
}

# write_sysctl_file FILE CONTENT puts CONTENT and a newline into FILE (mode 0644), in
# one rename so that a boot never reads half of it, and makes the directory when
# there is none. Unlike put_file it never ends the script: it fails, with the reason
# on stderr, and leaves nothing of its own behind. /etc/sysctl.d can be read-only,
# and a file that cannot be written there is a warning of the caller, not the end of
# the install. Every step is chained here and not left to set -e, which does nothing
# inside the condition of an if.
write_sysctl_file() {
  local file=$1 content=$2 dir tmp
  dir=$(dirname -- "$file")
  tmp=$dir/.$(basename -- "$file").new.$$
  # mv would put the file into a directory of that name, and succeed.
  if [ -d "$file" ]; then
    echo "$file is a directory" >&2
    return 1
  fi
  mkdir -p -- "$dir" || return 1
  # tee and not a redirection: its message names the file, where the message of the
  # shell names a line of this script.
  if ! (umask 077 && tee -- "$tmp" > /dev/null <<< "$content") || ! chmod 0644 -- "$tmp" || ! mv -f -- "$tmp" "$file"; then
    rm -f -- "$tmp" 2> /dev/null
    return 1
  fi
}

# one_line TEXT prints TEXT with its line breaks turned into "; ", for a warning.
one_line() {
  printf '%s' "${1//$'\n'/; }"
}

# reserve_ports puts the loopback ports of the node (RESERVED_PORTS) into
# net.ipv4.ip_local_reserved_ports, now and from the next boot on. The kernel takes
# a reserved port for no connection that leaves the choice to it (an outgoing
# connection, a listener on port 0), and a program that names the port still gets
# it. The file SYSCTL_DIR/90-postern.conf holds the union of what is reserved when
# the script runs and the node's ports, so that no reservation of other software is
# dropped; the same list is set in the running kernel with sysctl -w, and read back
# (the sysctl of procps ignores a key that a user who is not root may not set, says
# so, and succeeds). sysctl -w sets this one key, from no file: sysctl --system
# would load every setting of the host again. Nothing that goes wrong ends the
# install, a file that cannot be written least of all: each is a warning, and the
# node works without the reservation, with a small chance that an outgoing
# connection holds the port of an engine when it starts.
reserve_ports() {
  local file=$SYSCTL_DIR/90-postern.conf current merged content err now want kept= later=
  if ! current=$(sysctl -n "$RESERVED_PORTS_KEY" 2> /dev/null); then
    warn "cannot read $RESERVED_PORTS_KEY: the ports $RESERVED_PORTS are not reserved (see README.md)"
    return 0
  fi
  if ! merged=$(port_list_union "$current" "$RESERVED_PORTS"); then
    warn "$RESERVED_PORTS_KEY is not a list of ports ($current): it is left alone, and the ports $RESERVED_PORTS are not reserved (see README.md)"
    return 0
  fi

  # The file is for the boots to come: the running kernel is set below whether it
  # could be written or not.
  content=$(reserved_ports_file "$merged")
  if [ -f "$file" ] && [ "$(cat -- "$file")" = "$content" ]; then
    kept=1
  elif err=$(write_sysctl_file "$file" "$content" 2>&1); then
    kept=1
    note "$file: $RESERVED_PORTS_KEY = $merged"
  else
    warn "cannot write $file ($(one_line "${err:-no message}")): without it the reservation of the ports $RESERVED_PORTS may not survive a reboot (see README.md)"
  fi
  if [ -n "$kept" ]; then
    later="; the file $file reserves them from the next boot on"
  fi

  if [ "$(port_list_union "$current")" = "$merged" ]; then
    note "the ports $RESERVED_PORTS are reserved"
    return 0
  fi
  if ! err=$(sysctl -w "$RESERVED_PORTS_KEY=$merged" 2>&1 > /dev/null); then
    warn "sysctl -w $RESERVED_PORTS_KEY=$merged failed ($(one_line "${err:-no message}")): the ports $RESERVED_PORTS are not reserved now$later (see README.md)"
    return 0
  fi
  if now=$(sysctl -n "$RESERVED_PORTS_KEY" 2> /dev/null) && now=$(port_list_union "$now") \
    && want=$(port_list_union "$now" "$RESERVED_PORTS") && [ "$now" = "$want" ]; then
    note "the ports $RESERVED_PORTS are reserved"
  else
    warn "sysctl -w $RESERVED_PORTS_KEY=$merged did not take: $RESERVED_PORTS_KEY does not hold the ports $RESERVED_PORTS${err:+ (sysctl said: $(one_line "$err"))}$later (see README.md)"
  fi
  return 0
}

# ---- run -------------------------------------------------------------------------

# request_edge_roll asks the agent for a new generation of the edge (--roll-edge):
# it writes data/run/roll-edge, private, with the time of the request in Unix
# seconds, in one rename, and touches nothing else. On its next pass the agent
# starts edge generation N+1 beside the running one, which drains, and deletes the
# file (README.md, "Rolling the edge").
request_edge_roll() {
  local run=$HOME_DIR/data/run file tmp running
  [ -d "$run" ] || die "no Postern node is installed in $HOME_DIR (it has no data/run): install one first"
  file=$run/roll-edge
  tmp=$run/.roll-edge.new.$$
  if [ -e "$file" ]; then
    note "an edge roll was asked for already, and the agent has not taken it yet; it is asked for again"
  fi
  rm -f -- "$tmp"
  (umask 077 && date +%s > "$tmp")
  chmod 0600 -- "$tmp"
  mv -f -- "$tmp" "$file"
  step "edge roll asked for"
  note "On its next pass, within about 30 seconds, the agent starts a new generation of the edge"
  note "with the binary of bin/current, and the running one drains. docker logs -f postern-agent shows it."
  running=$(docker inspect --type container --format '{{.State.Running}}' postern-agent 2> /dev/null || true)
  if [ "$running" != true ]; then
    warn "the postern-agent container is not running: the edge is rolled when it runs again"
  fi
}

start_agent() {
  docker compose -f "$HOME_DIR/compose.yaml" up -d --force-recreate \
    || die "docker compose failed. The files are installed; fix the problem and run this script again."
}

summary() {
  cat << EOF

Postern node installed.

  Node id: $NODE_ID
  Binary: $BIN_NAME (bin/current)
  Management port: $MGMT_PORT/tcp (mTLS)

Allow the panel's address to reach the management port in the firewall.
The bundle file holds the node's private key: delete it once the node is online.
Logs: docker logs -f postern-agent
EOF
}

main() {
  parse_args "$@"
  require_root
  case $HOME_DIR in
    /opt/postern) ;;
    /*) warn "POSTERN_HOME is $HOME_DIR, not /opt/postern: the compose file mounts /opt/postern (meant for tests)" ;;
    *) die "POSTERN_HOME must be an absolute path" ;;
  esac
  if [ -n "$ROLL_EDGE" ]; then
    request_edge_roll
    return 0
  fi
  check_docker
  check_sources

  trap cleanup EXIT
  STAGE=$(mktemp -d)
  step "checking the bundle"
  read_bundle "$BUNDLE"
  note "node $NODE_ID, management port $MGMT_PORT"

  step "preparing $HOME_DIR"
  make_layout
  prepare_binary

  step "installing"
  install_identity
  install_pki
  install_binary
  put_file 0755 "$SCRIPT_DIR/launcher.sh" "$BIN_DIR/launcher.sh"
  put_file 0644 "$SCRIPT_DIR/compose.yaml" "$HOME_DIR/compose.yaml"

  step "reserving the loopback ports $RESERVED_PORTS"
  check_migrate_req
  reserve_ports
  enable_migrate_req

  step "starting the agent"
  start_agent
  summary
}

# Sourced by the tests, which call the functions one by one.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
