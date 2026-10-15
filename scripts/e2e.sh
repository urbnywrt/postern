#!/usr/bin/env bash
# End-to-end test: the panel, a node agent in Docker installed from the
# panel's bundle, the edge and the telemt engine it starts, and a fake-TLS
# client that goes through the edge (test/e2e).
#
#   bash scripts/e2e.sh [test binary flags]      for example -test.run TestPanelToNodeFakeTLS
#
# From Git Bash on Windows: bash scripts/wsl 'bash scripts/e2e.sh'
#
# It makes a throwaway release key (scripts/release keygen --unencrypted) and
# builds for Linux and the architecture of the Docker daemon (docker info:
# x86_64 is amd64, aarch64 is arm64; another one with POSTERN_E2E_GOARCH),
# into a temporary directory, with the key's public half among the trusted
# keys (release.extraPublicKeys): postern-node v0.90.0-e2e (installed),
# postern-node and postern-panel v0.90.1-e2e (the update and the panel of
# TestVersions) and the stand-in engine of TestVersions. From the installed node binary
# it builds the node image of the run, postern-node:e2e-<run>
# (deploy/node/Dockerfile with PREBUILT, a context of that binary and the
# launcher alone), which TestDockerJoin starts with the command of the panel;
# the test and the panels that it starts get it in POSTERN_E2E_NODE_IMAGE and
# POSTERN_NODE_IMAGE. Then it runs
# go test -tags e2e ./test/e2e/ -timeout 60m with the environment pointing to
# them and to the key. It needs Docker, and GitHub for the telemt release (the
# test skips without it). scripts/e2e_test.sh tests the choice of the
# architecture.
#
# The agent of the test runs on the host network, as deploy/node/compose.yaml
# runs it, and the test reaches it, the edge and the engines on 127.0.0.1. On a
# Linux Docker engine that is the host's network and the test runs directly. On
# Docker Desktop the host network of containers is that of Docker's VM, which a
# process outside a container cannot reach: there the test binary runs in a
# container of its own on the host network, as the user who runs this script,
# with the Docker socket, the repository and the work directory mounted at the
# same paths as outside. Docker Desktop takes the paths of bind mounts as paths
# of the WSL distribution that the request comes from, also when it comes from
# inside a container, so the node's directory in the work directory is one and
# the same directory for the test, the agent and the containers that the agent
# starts.
#
# Whatever happens, the containers of the run (label postern.e2e=<run>, and
# those that the agent made with a mount from the work directory), its networks
# (label postern.e2e=<run>), the sysctl helpers that a node bootstrap may have
# left (postern-sysctl-*), the node image of the run and the work directory
# are removed at the end.
#
# POSTERN_E2E_ONLINE=1 runs the online subtests as well (see test/e2e).
# POSTERN_E2E_TELEMT_VERSION, POSTERN_E2E_MTG_VERSION and POSTERN_E2E_XRAY_VERSION
# make the tests run that upstream release of
# the component (test/e2e/overrides.go): the job of the stable list sets them.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

runner_image='alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8'

log() { printf 'e2e.sh: %s\n' "$*" >&2; }

# The binaries run in containers of the Docker daemon, and the panel and the
# test next to them, so they are built for the daemon's architecture.
if [ -n "${POSTERN_E2E_GOARCH:-}" ]; then
  arch=$POSTERN_E2E_GOARCH
else
  if ! daemon_arch=$(docker info --format '{{.Architecture}}' 2> /dev/null); then
    log "cannot ask the Docker daemon for its architecture (docker info fails): is Docker running?"
    exit 1
  fi
  case $daemon_arch in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
      log "the Docker daemon runs on '$daemon_arch', which Postern nodes do not: set POSTERN_E2E_GOARCH to build for another architecture"
      exit 1
      ;;
  esac
fi

# The versions of the binaries, as test/e2e names them (nodeVersion,
# updateVersion): the node is installed with the first; the panel and the
# update of the node in TestVersions are the second.
node_version=v0.90.0-e2e
update_version=v0.90.1-e2e

run=$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')
work=$(mktemp -d "${TMPDIR:-/tmp}/postern-e2e.XXXXXX")
node_image=postern-node:e2e-$run
image_built=

cleanup() {
  local status=$? ids id src nets
  set +e
  # The containers of the run: the test's own (it removes them itself, unless
  # it was killed) and those that the agent made for the node.
  ids=$(docker ps -aq --filter "label=postern.e2e=$run")
  for id in $(docker ps -aq --filter label=postern.managed=true); do
    while IFS= read -r src; do
      case $src in
        "$work"/*)
          ids="$ids $id"
          break
          ;;
      esac
    done < <(docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2> /dev/null)
  done
  if [ -n "${ids// /}" ]; then
    log "removing containers left by the run: $ids"
    # shellcheck disable=SC2086 # one word per container ID
    docker rm -f $ids > /dev/null
  fi
  # The one-shot sysctl helpers of a bootstrap (TestDockerJoin) remove
  # themselves; a bootstrap that was killed leaves one behind.
  ids=$(docker ps -aq --filter name=postern-sysctl- --filter label=postern.role=helper)
  if [ -n "$ids" ]; then
    log "removing sysctl helpers left by the run: ${ids//$'\n'/ }"
    # shellcheck disable=SC2086 # one word per container ID
    docker rm -f $ids > /dev/null
  fi
  if [ -n "$image_built" ]; then
    docker image rm -f "$node_image" > /dev/null 2>&1
  fi
  # The networks of the run, once no container of it is on them.
  nets=$(docker network ls -q --filter "label=postern.e2e=$run")
  if [ -n "$nets" ]; then
    log "removing networks left by the run: ${nets//$'\n'/ }"
    # shellcheck disable=SC2086 # one word per network ID
    docker network rm $nets > /dev/null
  fi
  # The agent and the engines leave files of root and of 65534 behind when the
  # test cannot clean up after itself: only root removes them.
  if ! rm -rf "$work" 2> /dev/null; then
    docker run --rm --label "postern.e2e=$run" --network none -v "$work:$work" "$runner_image" \
      sh -c 'rm -rf "$1"/* "$1"/.[!.]*' sh "$work" > /dev/null
    rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

# A throwaway release key, made for this run alone: the binaries trust its
# public half (release.extraPublicKeys), and TestVersions signs the update of
# the node with it. It never leaves the work directory, and nothing prints it.
# The binaries are built with the production keys emptied: a set with
# production keys ignores test keys, and these binaries must trust this key.
# The tool is built for this machine, before GOOS and GOARCH are set.
log "making a throwaway release key in $work/key"
mkdir -p "$work/bin" "$work/key"
pubkey=$(go run ./scripts/release keygen --unencrypted --out "$work/key")

log "building postern-node $node_version and $update_version, postern-panel $update_version and the stand-in engine for linux/$arch in $work/bin"
export CGO_ENABLED=0 GOOS=linux GOARCH="$arch"
ldflags() {
  printf '%s' "-X github.com/urbnywrt/postern/internal/version.Version=$1 -X github.com/urbnywrt/postern/internal/release.extraPublicKeys=$pubkey -X github.com/urbnywrt/postern/internal/release.productionReleaseKeys= -X github.com/urbnywrt/postern/internal/release.productionStableKeys="
}
go build -trimpath -ldflags "$(ldflags "$node_version")" -o "$work/bin/postern-node" ./cmd/node
go build -trimpath -ldflags "$(ldflags "$update_version")" -o "$work/bin/postern-node-update" ./cmd/node
go build -trimpath -ldflags "$(ldflags "$update_version")" -o "$work/bin/postern-panel" ./cmd/panel
go build -trimpath -o "$work/bin/badengine" ./test/e2e/testdata/badengine

# The node image of the run (TestDockerJoin): the installed node binary, byte
# for byte, as the image of a release takes the binary of the release.
log "building the node image $node_image from postern-node $node_version"
mkdir -p "$work/image/dist" "$work/image/deploy/node"
cp "$work/bin/postern-node" "$work/image/dist/postern-node-linux-$arch"
cp deploy/node/launcher.sh "$work/image/deploy/node/launcher.sh"
image_built=1
docker build --quiet --platform "linux/$arch" --build-arg PREBUILT=dist --build-arg VERSION="$node_version" \
  -f deploy/node/Dockerfile -t "$node_image" "$work/image" > /dev/null
export POSTERN_E2E_NODE_IMAGE=$node_image POSTERN_NODE_IMAGE=$node_image

export POSTERN_E2E_NODE_BIN="$work/bin/postern-node"
export POSTERN_E2E_PANEL_BIN="$work/bin/postern-panel"
export POSTERN_E2E_NODE_UPDATE_BIN="$work/bin/postern-node-update"
export POSTERN_E2E_BADENGINE_BIN="$work/bin/badengine"
export POSTERN_E2E_RELEASE_KEY="$work/key/postern-release.key"
export POSTERN_E2E_WORKDIR="$work"
export POSTERN_E2E_RUN="$run"

os=$(docker info --format '{{.OperatingSystem}}')
case $os in
  *"Docker Desktop"*)
    log "$os: running the test in a container on the host network of Docker's VM (run $run)"
    go test -c -tags e2e -o "$work/bin/e2e.test" ./test/e2e/
    sock_gid=$(stat -c %g /var/run/docker.sock)
    export POSTERN_E2E_CONTAINER="postern-e2e-$run"
    docker run --rm --name "$POSTERN_E2E_CONTAINER" --label "postern.e2e=$run" \
      --network host --user "$(id -u):$(id -g)" --group-add "$sock_gid" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$work:$work" -v "$root:$root:ro" -w "$root/test/e2e" \
      -e POSTERN_E2E_NODE_BIN -e POSTERN_E2E_PANEL_BIN -e POSTERN_E2E_WORKDIR -e POSTERN_E2E_RUN -e POSTERN_E2E_CONTAINER \
      -e POSTERN_E2E_NODE_UPDATE_BIN -e POSTERN_E2E_BADENGINE_BIN -e POSTERN_E2E_RELEASE_KEY \
      -e POSTERN_E2E_LOGS -e POSTERN_E2E_ONLINE -e POSTERN_E2E_NODE_IMAGE -e POSTERN_NODE_IMAGE \
      -e POSTERN_E2E_TELEMT_VERSION -e POSTERN_E2E_MTG_VERSION -e POSTERN_E2E_XRAY_VERSION \
      "$runner_image" "$work/bin/e2e.test" -test.v -test.count=1 -test.timeout=60m "$@"
    ;;
  *)
    log "$os: running the test here (run $run)"
    unset GOOS GOARCH CGO_ENABLED
    go test -tags e2e -count=1 -v -timeout 60m ./test/e2e/ -args "$@"
    ;;
esac
