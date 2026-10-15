#!/usr/bin/env bash
# Run `go test -race` inside the official golang image.
#
# The race detector needs cgo, and so a C compiler, which the WSL distro does
# not have. Run it in a container instead:
#
#   bash scripts/wsl 'bash scripts/race.sh ./gen/...'
#
# Arguments go straight to `go test -race`; without any, the whole module is
# tested. The repository is mounted at /src. The module cache and the build
# cache live in named Docker volumes (postern-gomod, postern-gocache), so only
# the first run downloads and compiles the dependencies.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)

if [ "$#" -eq 0 ]; then
  set -- ./...
fi

# MSYS_NO_PATHCONV keeps Git Bash from rewriting /src and the container paths
# into Windows paths when the script is run outside WSL.
MSYS_NO_PATHCONV=1 exec docker run --rm \
  -v "$root:/src" \
  -v postern-gomod:/go/pkg/mod \
  -v postern-gocache:/root/.cache/go-build \
  -w /src \
  golang:1.27 \
  go test -race "$@"
