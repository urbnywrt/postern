#!/usr/bin/env bash
# Point git at the versioned hooks in .githooks/. Run once per clone.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

chmod +x .githooks/* scripts/wsl scripts/*.sh
git config core.hooksPath .githooks
echo "git hooks installed (core.hooksPath=.githooks)"
