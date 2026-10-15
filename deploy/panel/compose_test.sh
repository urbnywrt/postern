#!/bin/sh
# Tests for the port that compose.yaml publishes (POSTERN_BIND and POSTERN_PORT),
# and for the POSTERN_NODE_IMAGE that it passes to the container.
# They run docker compose config, which reads the file and fills in the variables
# without starting anything, and check the address and the port on the host:
#
#   POSTERN_BIND not set, or empty   no address: Docker publishes the port on every
#                                    interface, IPv4 and IPv6
#   POSTERN_BIND=127.0.0.1           on that address only
#   POSTERN_BIND=[::1]               on ::1 only (an IPv6 address goes in brackets)
#
# From the repository root:
#
#   bash scripts/wsl 'sh deploy/panel/compose_test.sh'
#
# Without docker compose it says so and is skipped. Neither a .env next to
# compose.yaml nor the environment of the caller changes what it checks.

set -u

here=$(cd "$(dirname "$0")" && pwd) || exit 1
compose=$here/compose.yaml

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
  if [ -n "${2:-}" ]; then
    printf '       %s\n' "$2"
  fi
}

# eq DESCRIPTION EXPECTED ACTUAL
eq() {
  if [ "$2" = "$3" ]; then
    ok "$1"
  else
    bad "$1" "expected [$2], got [$3]"
  fi
}

# published BIND PORT prints how the port of the panel is published with
# POSTERN_BIND=BIND and POSTERN_PORT=PORT ("-" leaves the variable unset):
# "<address on the host> <port on the host>", the address "-" when there is
# none, and then the number of ports, "ports=1".
published() {
  (
    unset POSTERN_BIND POSTERN_PORT POSTERN_IMAGE POSTERN_TRUSTED_PROXIES POSTERN_NODE_IMAGE
    if [ "$1" != - ]; then
      POSTERN_BIND=$1
      export POSTERN_BIND
    fi
    if [ "$2" != - ]; then
      POSTERN_PORT=$2
      export POSTERN_PORT
    fi
    # --env-file: a .env next to compose.yaml is not read.
    if ! json=$(docker compose --env-file /dev/null -f "$compose" config --format json 2>&1); then
      printf 'docker compose config failed: %s\n' "$json"
      exit 0
    fi
    ports=$(printf '%s\n' "$json" | grep -c '"published"')
    address=$(printf '%s\n' "$json" | sed -n 's/.*"host_ip": *"\([^"]*\)".*/\1/p')
    port=$(printf '%s\n' "$json" | sed -n 's/.*"published": *"\([^"]*\)".*/\1/p')
    printf '%s %s ports=%s\n' "${address:--}" "${port:--}" "$ports"
  )
}

# node_image VALUE prints the POSTERN_NODE_IMAGE that the container gets with
# POSTERN_NODE_IMAGE=VALUE ("-" leaves it unset), "<none>" when it gets none.
node_image() {
  (
    unset POSTERN_BIND POSTERN_PORT POSTERN_IMAGE POSTERN_TRUSTED_PROXIES POSTERN_NODE_IMAGE
    if [ "$1" != - ]; then
      POSTERN_NODE_IMAGE=$1
      export POSTERN_NODE_IMAGE
    fi
    if ! json=$(docker compose --env-file /dev/null -f "$compose" config --format json 2>&1); then
      printf 'docker compose config failed: %s\n' "$json"
      exit 0
    fi
    if ! printf '%s\n' "$json" | grep -q '"POSTERN_NODE_IMAGE"'; then
      echo '<none>'
      exit 0
    fi
    printf '%s\n' "$json" | sed -n 's/.*"POSTERN_NODE_IMAGE": *"\([^"]*\)".*/\1/p'
  )
}

if ! docker compose version > /dev/null 2>&1; then
  echo "compose_test.sh: skipped: docker compose is not available"
  exit 0
fi

echo "the port of the panel"
eq "without POSTERN_BIND: no address, so every interface, IPv4 and IPv6" "- 8080 ports=1" "$(published - -)"
eq "an empty POSTERN_BIND is the same" "- 8080 ports=1" "$(published "" -)"
eq "POSTERN_BIND=127.0.0.1: the loopback only" "127.0.0.1 8080 ports=1" "$(published 127.0.0.1 -)"
eq "POSTERN_BIND=[::1]: the IPv6 loopback only" "::1 8080 ports=1" "$(published '[::1]' -)"
eq "POSTERN_BIND=[2001:db8::1]: that address" "2001:db8::1 8080 ports=1" "$(published '[2001:db8::1]' -)"
eq "POSTERN_PORT=9090 without POSTERN_BIND" "- 9090 ports=1" "$(published - 9090)"
eq "both" "127.0.0.1 9090 ports=1" "$(published 127.0.0.1 9090)"

echo "the node image"
eq "POSTERN_NODE_IMAGE is passed to the container" "ghcr.io/owner/postern-node:v1.2.3" "$(node_image ghcr.io/owner/postern-node:v1.2.3)"
eq "without it the container gets an empty one: the default of the image" "" "$(node_image -)"

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
