#!/usr/bin/env bash
# Tests for scripts/e2e.sh: the architecture that it builds the binaries for.
# They run the real script with a fake docker and a fake go first on PATH, so
# nothing is built and no container is started; every call is recorded.
#
#   bash scripts/wsl 'bash scripts/e2e_test.sh'

set -u

root=$(cd "$(dirname "$0")/.." && pwd) || exit 1
e2e_sh=$root/scripts/e2e.sh

tmproot=$(mktemp -d "${TMPDIR:-/tmp}/postern-e2e-test.XXXXXX") || exit 1
trap 'rm -rf "$tmproot"' EXIT
trap 'exit 1' HUP INT TERM

checks=0
failed=0

ok() {
  checks=$((checks + 1))
  printf '  ok   %s\n' "$1"
}

bad() {
  checks=$((checks + 1))
  failed=$((failed + 1))
  printf '  FAIL %s\n' "$1"
  if [ -n "${2:-}" ]; then printf '       %s\n' "$2"; fi
}

eq() { # eq DESCRIPTION EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2], got [$3]"; fi
}

has() { # has DESCRIPTION HAYSTACK NEEDLE
  if [[ $2 == *"$3"* ]]; then ok "$1"; else bad "$1" "no [$3] in [$2]"; fi
}

lacks() { # lacks DESCRIPTION HAYSTACK NEEDLE
  if [[ $2 == *"$3"* ]]; then bad "$1" "unexpected [$3] in [$2]"; else ok "$1"; fi
}

fakebin=$tmproot/fakebin
mkdir -p "$fakebin"

# Fake docker: a Linux engine (not Docker Desktop) whose architecture is
# FAKE_DOCKER_ARCH; docker info fails when FAKE_DOCKER_DOWN is set. It knows of
# no container but the sysctl helpers FAKE_DOCKER_HELPERS, and of the networks
# FAKE_DOCKER_NETWORKS. docker build writes down what its context holds.
cat > "$fakebin/docker" << 'EOF'
#!/bin/sh
printf 'docker %s\n' "$*" >> "$FAKE_LOG"
case "$1 $2 $3" in
  "info --format {{.Architecture}}")
    [ -z "${FAKE_DOCKER_DOWN:-}" ] || { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    echo "$FAKE_DOCKER_ARCH"
    ;;
  "info --format {{.OperatingSystem}}")
    [ -z "${FAKE_DOCKER_DOWN:-}" ] || exit 1
    echo "Ubuntu 24.04 LTS"
    ;;
  "network ls -q")
    for n in ${FAKE_DOCKER_NETWORKS:-}; do echo "$n"; done
    ;;
  "ps -aq --filter")
    case $4 in
      name=postern-sysctl-*) for h in ${FAKE_DOCKER_HELPERS:-}; do echo "$h"; done ;;
    esac
    ;;
esac
if [ "$1" = build ]; then
  for context; do :; done
  (cd "$context" && find . -type f | sort | sed 's/^/context /') >> "$FAKE_LOG"
fi
exit 0
EOF
# Fake go: writes down what it is asked to build or test, and for which
# architecture (a test: with the node image that it gets), and makes the file
# that a build names.
cat > "$fakebin/go" << 'EOF'
#!/bin/sh
printf 'go %s GOOS=%s GOARCH=%s CGO_ENABLED=%s\n' "$1" "${GOOS:-unset}" "${GOARCH:-unset}" "${CGO_ENABLED:-unset}" >> "$FAKE_LOG"
if [ "$1" = test ]; then
  printf 'env POSTERN_E2E_NODE_IMAGE=%s POSTERN_NODE_IMAGE=%s\n' "${POSTERN_E2E_NODE_IMAGE:-unset}" "${POSTERN_NODE_IMAGE:-unset}" >> "$FAKE_LOG"
fi
if [ "$1" = build ]; then
  while [ $# -gt 0 ]; do
    if [ "$1" = -o ]; then : > "$2"; fi
    shift
  done
fi
exit 0
EOF
chmod 755 "$fakebin/docker" "$fakebin/go"

n=0
# run_e2e ENV... runs e2e.sh with the fakes and the variables ENV (NAME=VALUE),
# and sets $out (stdout and stderr), $rc and $log (the calls of the fakes).
run_e2e() {
  n=$((n + 1))
  local tmp=$tmproot/tmp$n
  mkdir -p "$tmp"
  export FAKE_LOG=$tmproot/calls$n.log
  : > "$FAKE_LOG"
  out=$(env -u POSTERN_E2E_GOARCH -u FAKE_DOCKER_DOWN -u FAKE_DOCKER_NETWORKS -u FAKE_DOCKER_HELPERS -u POSTERN_NODE_IMAGE -u POSTERN_E2E_NODE_IMAGE PATH="$fakebin:$PATH" TMPDIR="$tmp" "$@" bash "$e2e_sh" 2>&1)
  rc=$?
  log=$(cat "$FAKE_LOG")
  left=$(find "$tmp" -mindepth 1 -maxdepth 1 | wc -l)
}

t_builds_for_the_architecture_of_the_daemon() {
  local a want
  for a in x86_64:amd64 amd64:amd64 aarch64:arm64 arm64:arm64; do
    want=${a#*:}
    run_e2e FAKE_DOCKER_ARCH="${a%%:*}"
    eq "a daemon on ${a%%:*}: the run goes through" 0 "$rc"
    has "${a%%:*}: the binaries are built for linux/$want" "$out" "for linux/$want"
    eq "${a%%:*}: the four builds are for $want" 4 "$(grep -c "^go build GOOS=linux GOARCH=$want CGO_ENABLED=0$" <<< "$log")"
    has "${a%%:*}: the throwaway key is made by the tool built for this machine" "$log" "go run GOOS=unset GOARCH=unset CGO_ENABLED=unset"
    has "${a%%:*}: the test runs on the Linux engine, built for this machine" "$log" "go test GOOS=unset GOARCH=unset CGO_ENABLED=unset"
    eq "${a%%:*}: the work directory is removed" 0 "$left"
  done
}

t_an_architecture_of_no_node_stops_the_run() {
  run_e2e FAKE_DOCKER_ARCH=riscv64
  eq "a daemon on riscv64: the run stops" 1 "$rc"
  has "and says why" "$out" "'riscv64'"
  has "and what to do" "$out" "POSTERN_E2E_GOARCH"
  lacks "nothing is built" "$log" "go "
  eq "and nothing is left" 0 "$left"
}

t_a_daemon_that_does_not_answer_stops_the_run() {
  run_e2e FAKE_DOCKER_ARCH=x86_64 FAKE_DOCKER_DOWN=1
  eq "docker info fails: the run stops" 1 "$rc"
  has "and says so" "$out" "docker info fails"
  lacks "nothing is built" "$log" "go "
  eq "and nothing is left" 0 "$left"
}

t_POSTERN_E2E_GOARCH_wins() {
  run_e2e FAKE_DOCKER_ARCH=x86_64 POSTERN_E2E_GOARCH=arm64
  eq "POSTERN_E2E_GOARCH=arm64 on an x86_64 daemon: the run goes through" 0 "$rc"
  eq "the four builds are for arm64" 4 "$(grep -c '^go build GOOS=linux GOARCH=arm64 CGO_ENABLED=0$' <<< "$log")"
  lacks "the daemon is not asked for its architecture" "$log" "{{.Architecture}}"
}

t_the_networks_of_the_run_are_removed() {
  run_e2e FAKE_DOCKER_ARCH=x86_64 FAKE_DOCKER_NETWORKS="net1 net2"
  eq "networks are left: the run goes through" 0 "$rc"
  has "the networks are looked for by the label of the run" "$log" "docker network ls -q --filter label=postern.e2e="
  has "and removed" "$log" "docker network rm net1 net2"
  run_e2e FAKE_DOCKER_ARCH=x86_64
  lacks "no network is left: none is removed" "$log" "docker network rm"
}

t_the_node_image_is_built_from_the_node_binary() {
  local tag
  run_e2e FAKE_DOCKER_ARCH=aarch64
  eq "the run goes through" 0 "$rc"
  tag=$(grep -o 'postern-node:e2e-[0-9a-f]*' <<< "$log" | head -n 1)
  has "the image is tagged postern-node:e2e-<run>" "$tag" "postern-node:e2e-"
  has "it is built from the prebuilt binary" "$log" "--build-arg PREBUILT=dist"
  has "for the architecture of the daemon" "$log" "--platform linux/arm64"
  has "with the version of the installed node" "$log" "--build-arg VERSION=v0.90.0-e2e"
  has "with the Dockerfile of the node" "$log" "-f deploy/node/Dockerfile"
  has "the context holds the node binary under the name the Dockerfile takes" "$log" "context ./dist/postern-node-linux-arm64"
  has "and the launcher" "$log" "context ./deploy/node/launcher.sh"
  eq "the context holds nothing else" 2 "$(grep -c '^context ' <<< "$log")"
  has "the test gets the image" "$log" "env POSTERN_E2E_NODE_IMAGE=$tag POSTERN_NODE_IMAGE=$tag"
  has "the image is removed at the end" "$log" "docker image rm -f $tag"
  eq "after the test" 1 "$(sed -n '/^go test/,$p' <<< "$log" | grep -c "^docker image rm -f $tag$")"
  eq "the work directory is removed" 0 "$left"
}

t_sysctl_helpers_that_are_left_are_removed() {
  run_e2e FAKE_DOCKER_ARCH=x86_64 FAKE_DOCKER_HELPERS="h1 h2"
  eq "sysctl helpers are left: the run goes through" 0 "$rc"
  has "they are looked for by name and role" "$log" "docker ps -aq --filter name=postern-sysctl- --filter label=postern.role=helper"
  has "and removed" "$log" "docker rm -f h1 h2"
  run_e2e FAKE_DOCKER_ARCH=x86_64
  lacks "no helper is left: none is removed" "$log" "docker rm -f"
}

for t in \
  t_builds_for_the_architecture_of_the_daemon \
  t_an_architecture_of_no_node_stops_the_run \
  t_a_daemon_that_does_not_answer_stops_the_run \
  t_POSTERN_E2E_GOARCH_wins \
  t_the_networks_of_the_run_are_removed \
  t_the_node_image_is_built_from_the_node_binary \
  t_sysctl_helpers_that_are_left_are_removed; do
  echo "$t"
  "$t"
done

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then exit 1; fi
