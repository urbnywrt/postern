#!/usr/bin/env bash
# Run the integration tests of one package where the Docker daemon's host
# network is.
#
#   bash scripts/itest.sh <package> [test binary flags]   for example ./internal/engines/mtg -test.run TestIntegrationMTG
#
# From Git Bash on Windows: bash scripts/wsl 'bash scripts/itest.sh ./internal/engines/mtg'
#
# Some integration tests (internal/engines/mtg) talk from the test process to
# the containers they start on the host network, at 127.0.0.1, and share a
# scratch directory with them by path. On a Linux Docker engine that is the
# host's own network and file system, and the test binary runs directly. On
# Docker Desktop the host network of containers is the network of Docker's VM,
# which a process outside a container cannot reach: there the test binary runs
# in a container of its own on that network, as the user who runs this script,
# with the Docker socket, the package directory and a scratch directory (its
# TMPDIR) mounted at the same paths as outside. Docker Desktop takes the paths
# of bind mounts as paths of the WSL distribution that the request comes from,
# also when it comes from inside a container, so the test and the containers it
# starts see the same files.
#
# The test binary is built with the integration tag and CGO_ENABLED=0 (on Docker
# Desktop it runs in the runner image) into the scratch directory, which is
# removed at the end.
#
# POSTERN_ITEST_ROOT=1 runs the test as root on Docker Desktop (a test that
# talks to the edge's control socket, which is root's, needs it; elsewhere run
# the script as root). POSTERN_ITEST_NODE_BINARIES names a directory of
# prebuilt agent binaries that a test reads (internal/node/agent): it is
# mounted read-only at the same path and passed on. POSTERN_ITEST_PSIPHON_CORE
# names a directory with the Psiphon client that scripts/psiphon-core.sh built
# (psiphon-core-linux-<arch>), which the trial and the Psiphon tests run; it is
# passed on the same way.
#
# A run that is killed leaves the containers of its test behind, an engine
# among them. Before and after every run, the containers that carry the labels
# of the tests that run through this script (sweep_labels) are removed.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: bash scripts/itest.sh <package> [test binary flags]" >&2
  exit 2
fi
pkg=$1
shift

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

runner_image='alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8'

# The labels of the containers of the tests that run through this script.
sweep_labels=(postern.test=mtg-driver)

log() { printf 'itest.sh: %s\n' "$*" >&2; }

sweep() {
  local label ids
  for label in "${sweep_labels[@]}"; do
    ids=$(docker ps -aq --filter "label=$label")
    if [ -n "$ids" ]; then
      log "removing containers ($label) $1: $(echo "$ids" | tr '\n' ' ')"
      # shellcheck disable=SC2086 # one word per container ID
      docker rm -f $ids > /dev/null
    fi
  done
}

if ! os=$(docker info --format '{{.OperatingSystem}}' 2> /dev/null); then
  log "cannot ask the Docker daemon about itself (docker info fails): is Docker running?"
  exit 1
fi

dir=$(go list -f '{{.Dir}}' "$pkg")
work=$(mktemp -d "${TMPDIR:-/tmp}/postern-itest.XXXXXX")

cleanup() {
  local status=$?
  set +e
  sweep "left by this run"
  # Containers of the test may leave files of other users behind: only root
  # removes them.
  if ! rm -rf "$work" 2> /dev/null; then
    docker run --rm --network none -v "$work:$work" "$runner_image" \
      sh -c 'rm -rf "$1"/* "$1"/.[!.]*' sh "$work" > /dev/null || true
    rm -rf "$work" || true
  fi
  exit "$status"
}
trap cleanup EXIT

sweep "left by an earlier run"

CGO_ENABLED=0 go test -c -tags integration -o "$work/itest.test" "$pkg"
if [ ! -x "$work/itest.test" ]; then
  log "$pkg has no test files"
  exit 0
fi

case $os in
  *"Docker Desktop"*)
    log "$os: running the test in a container on the host network of Docker's VM"
    sock_gid=$(stat -c %g /var/run/docker.sock)
    user="$(id -u):$(id -g)"
    if [ "${POSTERN_ITEST_ROOT:-}" = 1 ]; then
      user=0:0
    fi
    extra=()
    if [ -n "${POSTERN_ITEST_NODE_BINARIES:-}" ]; then
      extra=(-v "$POSTERN_ITEST_NODE_BINARIES:$POSTERN_ITEST_NODE_BINARIES:ro" -e POSTERN_ITEST_NODE_BINARIES="$POSTERN_ITEST_NODE_BINARIES")
    fi
    if [ -n "${POSTERN_ITEST_PSIPHON_CORE:-}" ]; then
      extra+=(-v "$POSTERN_ITEST_PSIPHON_CORE:$POSTERN_ITEST_PSIPHON_CORE:ro" -e POSTERN_ITEST_PSIPHON_CORE="$POSTERN_ITEST_PSIPHON_CORE")
    fi
    docker run --rm --network host --user "$user" --group-add "$sock_gid" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$work:$work" -v "$dir:$dir:ro" -w "$dir" -e TMPDIR="$work" \
      -e POSTERN_E2E_ONLINE="${POSTERN_E2E_ONLINE:-}" "${extra[@]}" \
      "$runner_image" "$work/itest.test" -test.v "$@"
    ;;
  *)
    (cd "$dir" && TMPDIR="$work" "$work/itest.test" -test.v "$@")
    ;;
esac
