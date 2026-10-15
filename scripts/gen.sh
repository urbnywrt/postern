#!/usr/bin/env bash
# Lint the protobuf sources and regenerate the Go code under gen/go (committed).
#
#   bash scripts/wsl 'bash scripts/gen.sh'
#
# buf, protoc-gen-go and protoc-gen-connect-go are Go tools pinned in go.mod, so
# nothing has to be installed beyond the Go toolchain.
set -euo pipefail

cd "$(dirname "$0")/.."

go tool buf lint
go tool buf generate
