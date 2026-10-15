#!/usr/bin/env bash
# Tests for install.sh. They run the real script against a fake root: POSTERN_HOME
# and POSTERN_SYSCTL_DIR point into a temporary directory, and fake "docker", "id"
# and "sysctl" programs come first on PATH, so nothing touches the host and every
# Docker and sysctl call is recorded.
#
# From the repository root (GNU userland: the tests use stat -c and GNU tar):
#
#   bash scripts/wsl 'bash deploy/node/install_test.sh'
#
# One test also runs the bundle checks with busybox tar, in the runner image, when
# the Docker daemon has that image; it does not pull it.

set -u

here=$(cd "$(dirname "$0")" && pwd) || exit 1
install_sh=$here/install.sh
real_bash=$(command -v bash)
real_curl=$(command -v curl || true)
real_tar=$(command -v tar)
real_docker=$(command -v docker || true)
runner_image=alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

tmproot=$(mktemp -d "${TMPDIR:-/tmp}/postern-install-test.XXXXXX") || exit 1
trap 'rm -rf "$tmproot"' EXIT
trap 'exit 1' HUP INT TERM

# Two example ULIDs (the ones from the ULID specification).
ID_A=01ARZ3NDEKTSV4RRFFQ69G5FAV
ID_B=01BX5ZZKBKACTAV9WEVGEMMVRZ

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

# note TEXT: a line that is not a check, such as a case that is skipped.
note() { printf '  note %s\n' "$1"; }

eq() { # eq DESCRIPTION EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2], got [$3]"; fi
}

has() { # has DESCRIPTION HAYSTACK NEEDLE
  if [[ $2 == *"$3"* ]]; then ok "$1"; else bad "$1" "no [$3] in [$2]"; fi
}

lacks() { # lacks DESCRIPTION HAYSTACK NEEDLE
  if [[ $2 == *"$3"* ]]; then bad "$1" "unexpected [$3] in [$2]"; else ok "$1"; fi
}

absent() { # absent DESCRIPTION PATH
  if [ -e "$2" ] || [ -L "$2" ]; then bad "$1" "$2 exists"; else ok "$1"; fi
}

present() { # present DESCRIPTION PATH
  if [ -e "$2" ] || [ -L "$2" ]; then ok "$1"; else bad "$1" "$2 is missing"; fi
}

same_file() { # same_file DESCRIPTION FILE FILE
  if cmp -s "$2" "$3"; then ok "$1"; else bad "$1" "$2 and $3 differ"; fi
}

mode() { stat -c %a "$1"; }
target() { readlink "$1" 2> /dev/null || true; }

fails() { # fails DESCRIPTION: the last run_install failed
  if [ "$rc" -ne 0 ]; then ok "$1"; else bad "$1" "the script succeeded: $out"; fi
}

# ---- fakes -----------------------------------------------------------------------

fakebin=$tmproot/fakebin
mkdir -p "$fakebin"

cat > "$fakebin/docker" << 'EOF'
#!/bin/sh
# Fake docker: records every call, answers from FAKE_DOCKER_* variables.
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case $1 in
  info)
    if [ -n "${FAKE_DOCKER_USERNS:-}" ]; then
      echo '[name=seccomp,profile=builtin name=userns name=cgroupns]'
    else
      echo '[name=seccomp,profile=builtin name=cgroupns]'
    fi
    ;;
  compose)
    if [ "$2" = version ]; then
      [ -z "${FAKE_DOCKER_NO_COMPOSE:-}" ] || exit 1
      echo 'Docker Compose version v2.0.0'
    elif [ "$2" = -f ] && [ -n "${FAKE_DOCKER_COMPOSE_FAIL:-}" ]; then
      echo 'fake docker: compose failed' >&2
      exit 1
    fi
    ;;
  inspect)
    # The agent container runs when FAKE_DOCKER_AGENT is set, and does not exist otherwise.
    [ -n "${FAKE_DOCKER_AGENT:-}" ] || exit 1
    case "$*" in *--format*) echo true ;; esac
    ;;
esac
exit 0
EOF
cat > "$fakebin/id" << 'EOF'
#!/bin/sh
# Fake id: root, unless FAKE_UID says otherwise.
if [ "${1:-}" = -u ]; then echo "${FAKE_UID:-0}"; else exec /usr/bin/id "$@"; fi
EOF
# Fake sysctl: a kernel whose net.ipv4.ip_local_reserved_ports is the content of
# the file FAKE_SYSCTL_STATE. It knows two calls, sysctl -n KEY and sysctl -w
# KEY=VALUE; any other call (sysctl -p, sysctl --system, which reload more than the
# installer means to) is an error. It records every call, and fails as
# FAKE_SYSCTL_FAIL says: "read" (sysctl -n), "w" (sysctl -w), both separated by a
# comma; with FAKE_SYSCTL_DEAF set sysctl -w sets nothing, says so, and succeeds,
# as the sysctl of procps does for a user that is not root. Its
# net.ipv4.tcp_migrate_req is the content of FAKE_SYSCTL_MIGRATE; with
# FAKE_SYSCTL_NO_MIGRATE set the kernel has no such key (Linux before 5.14).
cat > "$fakebin/sysctl" << 'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SYSCTL_LOG"
key=net.ipv4.ip_local_reserved_ports
mkey=net.ipv4.tcp_migrate_req
fails() { case ",${FAKE_SYSCTL_FAIL:-}," in *",$1,"*) return 0 ;; esac; return 1; }
if [ "$2" = "$mkey" ] || [ "${2%%=*}" = "$mkey" ]; then
  if [ -n "${FAKE_SYSCTL_NO_MIGRATE:-}" ]; then
    echo "sysctl: cannot stat /proc/sys/net/ipv4/tcp_migrate_req: No such file or directory" >&2
    exit 255
  fi
  case "$1" in
    -n) cat "$FAKE_SYSCTL_MIGRATE" ;;
    -w)
      [ "$2" = "$mkey=1" ] || { echo "fake sysctl: unexpected setting $2" >&2; exit 2; }
      if fails w; then echo "sysctl: setting key \"$mkey\": Read-only file system" >&2; exit 255; fi
      if [ -n "${FAKE_SYSCTL_DEAF:-}" ]; then
        echo "sysctl: permission denied on key \"$mkey\", ignoring" >&2
      else
        echo 1 > "$FAKE_SYSCTL_MIGRATE"
      fi
      echo "$mkey = 1"
      ;;
    *) echo "fake sysctl: unexpected call: $*" >&2; exit 2 ;;
  esac
  exit 0
fi
case "$1" in
  -n)
    [ "$2" = "$key" ] || { echo "fake sysctl: unexpected key $2" >&2; exit 2; }
    if fails read; then echo "sysctl: cannot stat /proc/sys/net/ipv4/ip_local_reserved_ports" >&2; exit 1; fi
    cat "$FAKE_SYSCTL_STATE"
    ;;
  -w)
    case "$2" in
      "$key"=*) ;;
      *) echo "fake sysctl: unexpected setting $2" >&2; exit 2 ;;
    esac
    if fails w; then echo "sysctl: setting key \"$key\": Read-only file system" >&2; exit 255; fi
    if [ -n "${FAKE_SYSCTL_DEAF:-}" ]; then
      echo "sysctl: permission denied on key \"$key\", ignoring" >&2
    else
      printf '%s\n' "${2#"$key"=}" > "$FAKE_SYSCTL_STATE"
    fi
    echo "$key = ${2#"$key"=}"
    ;;
  *)
    echo "fake sysctl: unexpected call: $*" >&2
    exit 2
    ;;
esac
EOF
# Fake curl: writes every call to $FAKE_CURL_LOG. With FAKE_CURL_ROOT set it is a
# release host that needs no network and no certificate: the URLs that start with
# FAKE_CURL_PREFIX are served from that directory, and any other URL is an error.
# Without it the real curl runs, which is what a file:// URL needs, and its exit
# status goes to the log as "exit <status>".
cat > "$fakebin/curl" << EOF
#!/bin/sh
printf '%s\n' "\$*" >> "\${FAKE_CURL_LOG:-/dev/null}"
if [ -n "\${FAKE_CURL_ROOT:-}" ]; then
  out= url=
  while [ \$# -gt 0 ]; do
    case \$1 in
      --output) out=\$2; shift ;;
      -*) ;;
      *) url=\$1 ;;
    esac
    shift
  done
  case \$url in
    "\$FAKE_CURL_PREFIX"*) ;;
    *) echo "fake curl: unexpected URL \$url" >&2; exit 6 ;;
  esac
  src=\$FAKE_CURL_ROOT/\${url#"\$FAKE_CURL_PREFIX"}
  [ -f "\$src" ] || { echo "fake curl: not found: \$url" >&2; exit 22; }
  cp "\$src" "\$out"
  exit 0
fi
"${real_curl:-/nonexistent/curl}" "\$@"
rc=\$?
printf 'exit %s\n' "\$rc" >> "\${FAKE_CURL_LOG:-/dev/null}"
exit "\$rc"
EOF
chmod 755 "$fakebin/docker" "$fakebin/id" "$fakebin/curl" "$fakebin/sysctl"

# mkfakebin PATH VERSION [SALT] makes a fake postern-node that prints its version.
mkfakebin() {
  printf '#!/bin/sh\n# %s\nif [ "$1" = version ]; then echo "%s (abc1234, 2026-10-04T00:00:00Z)"; fi\n' \
    "${3:-}" "$2" > "$1"
  chmod 755 "$1"
}

# bundle_dir ID PORT prints a directory with the four files of a valid bundle.
bundle_dir() {
  local d
  d=$(mktemp -d "$tmproot/bundle.XXXXXX")
  printf '{"version":1,"node_id":"%s","mgmt_port":%s}' "$1" "$2" > "$d/bundle.json"
  printf -- '-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n' > "$d/ca.pem"
  printf -- '-----BEGIN CERTIFICATE-----\nTk9ERQ==\n-----END CERTIFICATE-----\n' > "$d/node.pem"
  # The marker is built in two pieces so that no scanner takes this file for a key.
  printf -- '%s%s\nS0VZ\n%s%s\n' '-----BEGIN PRIV' 'ATE KEY-----' '-----END PRIV' 'ATE KEY-----' > "$d/node-key.pem"
  printf '%s' "$d"
}

# tar_dir OUT DIR packs every file of DIR, flat, in ustar format like the panel does.
tar_dir() {
  (cd "$2" && tar --format=ustar -cf "$1" -- *)
}

# mkbundle ID PORT sets $bundle to a bundle with that node id and port. The file
# name keeps only letters and digits of the id, so that a hostile id still gives a
# usable name.
mkbundle() {
  local d
  d=$(bundle_dir "$1" "$2")
  bundle=$tmproot/bundle-${1//[^0-9A-Za-z]/_}-$2.tar
  tar_dir "$bundle" "$d"
}

n=0
# new_root starts a new fake host: an install root that does not exist yet, a
# sysctl directory that does not either, and a kernel that has no reserved ports.
new_root() {
  n=$((n + 1))
  root=$tmproot/opt$n
  sysctl_dir=$tmproot/sysctl$n.d
  sysctl_state=$tmproot/sysctl$n.state
  sysctl_migrate=$tmproot/sysctl$n.migrate
  slog=$tmproot/sysctl$n.log
  dlog=$tmproot/docker$n.log
  : > "$dlog"
  : > "$slog"
  : > "$sysctl_state"
  echo 1 > "$sysctl_migrate" # a kernel whose handoff is safe already
  unset FAKE_SYSCTL_NO_MIGRATE
  unset FAKE_DOCKER_USERNS FAKE_DOCKER_NO_COMPOSE FAKE_DOCKER_AGENT FAKE_DOCKER_COMPOSE_FAIL FAKE_UID POSTERN_RELEASE_BASE
  unset FAKE_CURL_LOG FAKE_CURL_ROOT FAKE_CURL_PREFIX FAKE_SYSCTL_FAIL FAKE_SYSCTL_DEAF
  tar_bin_dir=
}

# run_install ARGS... runs install.sh and sets $out (stdout and stderr) and $rc.
# When tar_bin_dir is set, the tar in it is the one that install.sh finds.
run_install() {
  out=$(PATH="${tar_bin_dir:+$tar_bin_dir:}$fakebin:$PATH" POSTERN_HOME="$root" FAKE_DOCKER_LOG="$dlog" \
    POSTERN_SYSCTL_DIR="$sysctl_dir" FAKE_SYSCTL_STATE="$sysctl_state" FAKE_SYSCTL_LOG="$slog" \
    FAKE_SYSCTL_MIGRATE="$sysctl_migrate" \
    "$real_bash" "$install_sh" "$@" 2>&1)
  rc=$?
}

docker_log() { cat "$dlog"; }
sysctl_log() { cat "$slog"; }
# warnings prints the warnings of the last run, but the one that every test gets
# for its POSTERN_HOME.
warnings() { printf '%s\n' "$out" | grep 'warning' | grep -v 'warning: POSTERN_HOME is '; }
reserved() { cat "$sysctl_state"; }
# reserved_in_file prints the value of the key in the sysctl file of the root.
reserved_in_file() {
  sed -n 's/^net\.ipv4\.ip_local_reserved_ports = //p' "$sysctl_dir/90-postern.conf" 2> /dev/null
}

# ---- tests -----------------------------------------------------------------------

t_fresh_install() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node-0.1.0" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node-0.1.0"
  eq "succeeds" 0 "$rc"
  has "prints the management port" "$out" "Management port: 43117/tcp"

  eq "root mode" 755 "$(mode "$root")"
  eq "bin mode" 755 "$(mode "$root/bin")"
  eq "pki mode" 700 "$(mode "$root/pki")"
  eq "data mode" 700 "$(mode "$root/data")"
  for d in state edge run run/launcher instances certs; do
    eq "data/$d is root only" 700 "$(mode "$root/data/$d")"
  done
  eq "data/artifacts mode" 755 "$(mode "$root/data/artifacts")"

  for f in ca.pem node.pem node-key.pem bundle.json; do
    eq "pki/$f mode" 600 "$(mode "$root/pki/$f")"
  done
  d=$tmproot/unpacked$n
  mkdir "$d"
  tar -xf "$bundle" -C "$d"
  same_file "the key is installed unchanged" "$d/node-key.pem" "$root/pki/node-key.pem"
  same_file "the CA certificate is installed unchanged" "$d/ca.pem" "$root/pki/ca.pem"
  same_file "the node certificate is installed unchanged" "$d/node.pem" "$root/pki/node.pem"
  same_file "bundle.json is kept" "$d/bundle.json" "$root/pki/bundle.json"

  eq "node id is persisted" "$ID_A" "$(cat "$root/data/state/node-id")"
  eq "node-id mode" 600 "$(mode "$root/data/state/node-id")"
  eq "binary mode" 755 "$(mode "$root/bin/postern-node-v0.1.0")"
  eq "current is a relative link" postern-node-v0.1.0 "$(target "$root/bin/current")"
  absent "there is no previous yet" "$root/bin/previous"
  same_file "launcher is installed" "$here/launcher.sh" "$root/bin/launcher.sh"
  eq "launcher mode" 755 "$(mode "$root/bin/launcher.sh")"
  same_file "compose file is installed" "$here/compose.yaml" "$root/compose.yaml"
  eq "compose mode" 644 "$(mode "$root/compose.yaml")"
  eq "nothing is left over in bin/" "" "$(ls -A "$root/bin" | grep '^\.' || true)"

  has "docker was asked about userns" "$(docker_log)" "info --format {{.SecurityOptions}}"
  has "the agent is started" "$(docker_log)" "compose -f $root/compose.yaml up -d --force-recreate"

  eq "the loopback ports are reserved in the kernel" 20000-40999 "$(reserved)"
  eq "and in the sysctl file, for the next boot" 20000-40999 "$(reserved_in_file)"
  eq "sysctl file mode" 644 "$(mode "$sysctl_dir/90-postern.conf")"
  eq "the setting is made with sysctl -w, and nothing else is set" \
    "-n net.ipv4.tcp_migrate_req
-n net.ipv4.ip_local_reserved_ports
-w net.ipv4.ip_local_reserved_ports=20000-40999
-n net.ipv4.ip_local_reserved_ports
-n net.ipv4.tcp_migrate_req" "$(sysctl_log)"
  eq "no leftover of the file in the sysctl directory" 90-postern.conf "$(ls -A "$sysctl_dir")"
  eq "no warning" "" "$(warnings)"
}

t_rerun_is_idempotent() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node-0.1.0" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node-0.1.0"
  printf 'desired' > "$root/data/state/desired.json"
  run_install --bundle "$bundle" --binary "$tmproot/node-0.1.0"
  eq "succeeds again" 0 "$rc"
  absent "previous does not become a copy of current" "$root/bin/previous"
  eq "current is unchanged" postern-node-v0.1.0 "$(target "$root/bin/current")"
  eq "the state of the same node is kept" desired "$(cat "$root/data/state/desired.json")"
  eq "no state is moved aside" "" "$(ls -d "$root"/data/state.bak-* 2> /dev/null || true)"
  eq "the agent is started both times" 2 "$(grep -c 'up -d --force-recreate' "$dlog")"
}

t_new_binary_keeps_the_old_one_as_previous() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node-1" v0.1.0
  mkfakebin "$tmproot/node-2" v0.2.0
  run_install --bundle "$bundle" --binary "$tmproot/node-1"
  run_install --bundle "$bundle" --binary "$tmproot/node-2"
  eq "succeeds" 0 "$rc"
  eq "current is the new version" postern-node-v0.2.0 "$(target "$root/bin/current")"
  eq "previous is the old version" postern-node-v0.1.0 "$(target "$root/bin/previous")"
  present "the old file stays" "$root/bin/postern-node-v0.1.0"

  run_install --bundle "$bundle" --binary "$tmproot/node-2"
  eq "installing the same version again leaves previous alone" postern-node-v0.1.0 "$(target "$root/bin/previous")"

  run_install --bundle "$bundle" --binary "$tmproot/node-1"
  eq "going back makes the other one current" postern-node-v0.1.0 "$(target "$root/bin/current")"
  eq "and the one left becomes previous" postern-node-v0.2.0 "$(target "$root/bin/previous")"
}

t_binary_options() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/dev-build" "dev"
  run_install --bundle "$bundle" --binary "$tmproot/dev-build"
  eq "the version is read from the binary: dev build" postern-node-dev "$(target "$root/bin/current")"

  mkfakebin "$tmproot/named" v1.0.0 named
  run_install --bundle "$bundle" --binary "$tmproot/named" --version custom-1
  eq "--version names a local binary" postern-node-custom-1 "$(target "$root/bin/current")"

  run_install --bundle "$bundle"
  eq "without binary options the installed one is kept" 0 "$rc"
  eq "and stays current" postern-node-custom-1 "$(target "$root/bin/current")"
  has "and says so" "$out" "keeping the installed binary postern-node-custom-1"

  new_root
  run_install --bundle "$bundle"
  fails "a first install needs a binary"
  has "and says what to pass" "$out" "--binary"
  absent "and leaves no binary" "$root/bin/current"

  printf '#!/bin/sh\nexit 0\n' > "$tmproot/silent"
  chmod 755 "$tmproot/silent"
  run_install --bundle "$bundle" --binary "$tmproot/silent"
  fails "a binary that does not tell its version needs --version"
  has "and the message says so" "$out" "pass --version"

  printf '#!/bin/sh\nexit 1\n' > "$tmproot/broken"
  chmod 755 "$tmproot/broken"
  run_install --bundle "$bundle" --binary "$tmproot/broken"
  fails "a binary that does not run is refused"
  has "and the message says so" "$out" "does not run on this host"
  absent "nothing is linked" "$root/bin/current"

  run_install --bundle "$bundle" --binary "$tmproot/does-not-exist"
  fails "a missing binary is refused"
}

t_same_version_other_content_is_refused() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node-a" v0.1.0 one
  mkfakebin "$tmproot/node-b" v0.1.0 two
  run_install --bundle "$bundle" --binary "$tmproot/node-a"
  run_install --bundle "$bundle" --binary "$tmproot/node-b"
  fails "a different binary under an installed version is refused"
  has "and the message says why" "$out" "installed already with different content"
  same_file "the installed file is intact" "$tmproot/node-a" "$root/bin/postern-node-v0.1.0"
}

t_other_node_state_is_moved_aside() {
  new_root
  mkbundle "$ID_A" 43117
  mkbundle "$ID_B" 43118
  mkfakebin "$tmproot/node" v0.1.0
  run_install --bundle "$tmproot/bundle-$ID_A-43117.tar" --binary "$tmproot/node"
  printf 'generation 57' > "$root/data/state/desired.json"
  printf 'x' > "$root/data/state/runtime.json"

  export FAKE_DOCKER_AGENT=1
  run_install --bundle "$tmproot/bundle-$ID_B-43118.tar" --binary "$tmproot/node"
  eq "succeeds" 0 "$rc"
  has "the running agent is stopped first" "$(docker_log)" "stop postern-agent"
  bak=$(ls -d "$root"/data/state.bak-* 2> /dev/null | head -n 1)
  if [[ ${bak##*/} =~ ^state\.bak-[0-9]+$ ]]; then
    ok "the old state is moved to state.bak-<unix time>"
  else
    bad "the old state is moved to state.bak-<unix time>" "found [$bak]"
  fi
  eq "the old desired state is in the backup" "generation 57" "$(cat "$bak/desired.json" 2> /dev/null)"
  eq "the backup remembers whose it was" "$ID_A" "$(cat "$bak/node-id" 2> /dev/null)"
  absent "the new state directory starts empty: no desired.json" "$root/data/state/desired.json"
  absent "no runtime.json either" "$root/data/state/runtime.json"
  eq "the new node id is stored" "$ID_B" "$(cat "$root/data/state/node-id")"
  eq "the state directory is private" 700 "$(mode "$root/data/state")"
  has "the operator is told" "$out" "moved to data/state.bak-"
  eq "the new management port is installed" '{"version":1,"node_id":"'"$ID_B"'","mgmt_port":43118}' "$(cat "$root/pki/bundle.json")"

  run_install --bundle "$tmproot/bundle-$ID_B-43118.tar" --binary "$tmproot/node"
  eq "the same node again moves nothing more" 1 "$(ls -d "$root"/data/state.bak-* | wc -l)"
}

t_state_of_unknown_origin_is_moved_aside() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  mkdir -p "$root/data/state"
  printf 'old' > "$root/data/state/desired.json"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "succeeds" 0 "$rc"
  eq "state without a node id is moved aside" old "$(cat "$root"/data/state.bak-*/desired.json)"
  eq "and the node id is stored" "$ID_A" "$(cat "$root/data/state/node-id")"
  lacks "the running agent was not stopped: there was none" "$(docker_log)" "stop postern-agent"
}

t_empty_state_is_not_moved() {
  new_root
  mkbundle "$ID_A" 43117
  mkbundle "$ID_B" 43118
  mkfakebin "$tmproot/node" v0.1.0
  run_install --bundle "$tmproot/bundle-$ID_A-43117.tar" --binary "$tmproot/node"
  run_install --bundle "$tmproot/bundle-$ID_B-43118.tar" --binary "$tmproot/node"
  eq "a state directory with only a node id has nothing to save" "" "$(ls -d "$root"/data/state.bak-* 2> /dev/null || true)"
  eq "the new id replaces the old" "$ID_B" "$(cat "$root/data/state/node-id")"
}

t_invalid_node_ids_are_refused() {
  local id
  for id in 01arz3ndektsv4rrffq69g5fav 01ARZ3NDEKTSV4RRFFQ69G5FA 01ARZ3NDEKTSV4RRFFQ69G5FAVX '../../etc/passwd/../../xx' '01ARZ3NDEKTSV4RRFFQ69G5FA!' '01ARZ3NDEKTSV4RRFFQ69G5FA-'; do
    new_root
    mkbundle "$id" 43117 2> /dev/null || true
    run_install --bundle "$bundle" --binary /bin/true
    fails "node id [$id] is refused"
    has "with a message about the node id" "$out" "node id"
    absent "and nothing was created" "$root"
    host_untouched "node id [$id]"
  done
}

# host_untouched WHAT: the last run left the host alone: no sysctl file was
# written, and sysctl was not even run.
host_untouched() {
  absent "$1: no sysctl file was written" "$sysctl_dir"
  eq "$1: sysctl was not run" "" "$(sysctl_log)"
}

t_refusals_leave_the_host_alone() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0

  export FAKE_DOCKER_USERNS=1
  run_install --bundle "$bundle" --binary "$tmproot/node"
  fails "userns-remap is refused"
  has "with the reason" "$out" "userns-remap"
  absent "and nothing was created" "$root"
  host_untouched "userns-remap"
  unset FAKE_DOCKER_USERNS

  export FAKE_UID=1000
  run_install --bundle "$bundle" --binary "$tmproot/node"
  fails "a non-root user is refused"
  has "with the reason" "$out" "must run as root"
  absent "and nothing was created" "$root"
  host_untouched "a non-root user"
  unset FAKE_UID

  export FAKE_DOCKER_NO_COMPOSE=1
  run_install --bundle "$bundle" --binary "$tmproot/node"
  fails "a missing compose plugin is refused"
  has "with the reason" "$out" "Compose v2 plugin"
  absent "and nothing was created" "$root"
  host_untouched "no compose plugin"
  unset FAKE_DOCKER_NO_COMPOSE

  run_install
  eq "no arguments is a usage error" 2 "$rc"
  has "and prints the usage" "$out" "usage:"
  run_install --bundle "$bundle" --version '../x'
  eq "a path as a version is a usage error" 2 "$rc"
  run_install --bundle "$bundle" --frobnicate
  eq "an unknown option is a usage error" 2 "$rc"
  run_install --bundle
  eq "a missing value is a usage error" 2 "$rc"
  run_install --help
  eq "--help succeeds" 0 "$rc"
  absent "and nothing was created" "$root"
  host_untouched "usage errors"
}

t_missing_docker_prints_instructions() {
  new_root
  mkbundle "$ID_A" 43117
  local tools=$tmproot/tools t
  mkdir -p "$tools"
  for t in dirname cat basename; do ln -sf "$(command -v "$t")" "$tools/$t"; done
  ln -sf "$fakebin/id" "$tools/id"
  out=$(PATH="$tools" POSTERN_HOME="$root" POSTERN_SYSCTL_DIR="$sysctl_dir" "$real_bash" "$install_sh" \
    --bundle "$bundle" --binary /bin/true 2>&1)
  rc=$?
  fails "without Docker the script stops"
  has "it says Docker is not installed" "$out" "Docker is not installed"
  has "and prints how to install it" "$out" "apt-get install -y docker.io docker-compose-v2"
  absent "and nothing was created" "$root"
  absent "nor a sysctl file" "$sysctl_dir"
}

# The loopback ports of the node are reserved in the kernel, and in a sysctl file
# for the boots to come. What other software reserved stays reserved, and what
# goes wrong is a warning that does not stop the install.
t_reserved_ports() {
  local f
  # fresh: a new host, whose sysctl file is f.
  fresh() {
    new_root
    f=$sysctl_dir/90-postern.conf
  }
  fresh
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0

  printf '8080,30000-50000\n' > "$sysctl_state"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "with other reservations: succeeds" 0 "$rc"
  eq "the other reservations are kept, and the ranges that overlap are joined" 8080,20000-50000 "$(reserved)"
  eq "the file holds the same list" 8080,20000-50000 "$(reserved_in_file)"
  has "the file says what it is" "$(cat "$f")" "# Written by the Postern node installer"
  has "the list is set with sysctl -w" "$(sysctl_log)" "-w net.ipv4.ip_local_reserved_ports=8080,20000-50000"
  lacks "and no file is reloaded" "$(sysctl_log)" "-p"
  lacks "nor are all of them" "$(sysctl_log)" "--system"
  eq "no warning" "" "$(warnings)"

  # The same again: nothing to apply, and the file is not touched.
  cp -p "$f" "$tmproot/sysctl-before"
  : > "$slog"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "a second run succeeds" 0 "$rc"
  same_file "and leaves the file as it is" "$tmproot/sysctl-before" "$f"
  lacks "and sets nothing" "$(sysctl_log)" "-w"
  has "and says that the ports are reserved" "$out" "the ports 20000-40999 are reserved"
  eq "the reservations are the same" 8080,20000-50000 "$(reserved)"

  # Reserved by hand, in no file: the file is written for the next boot, and
  # nothing needs to be applied.
  fresh
  printf '20000-40999\n' > "$sysctl_state"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "reserved already: the file is written" 20000-40999 "$(reserved_in_file)"
  lacks "and nothing is set" "$(sysctl_log)" "-w"

  # Ranges that touch the node's are joined with it; the others stay apart.
  fresh
  printf '1-5,19999,41000-41010,60000\n' > "$sysctl_state"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "ranges that touch are joined" 1-5,19999-41010,60000 "$(reserved)"

  # sysctl -w fails: a warning, the file for the next boot, and the agent starts.
  fresh
  export FAKE_SYSCTL_FAIL=w
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "sysctl -w fails: the install goes on" 0 "$rc"
  has "with a warning that says what failed" "$out" "sysctl -w net.ipv4.ip_local_reserved_ports=20000-40999 failed"
  has "and what sysctl said" "$out" "Read-only file system"
  has "and that the file is there for the next boot" "$out" "from the next boot on"
  eq "the file is there for the next boot" 20000-40999 "$(reserved_in_file)"
  eq "the kernel is as it was" "" "$(reserved)"
  lacks "no other way is tried: not --system" "$(sysctl_log)" "--system"
  lacks "nor -p" "$(sysctl_log)" "-p"
  has "the agent is started" "$(docker_log)" "up -d --force-recreate"

  # sysctl says that it set the list, and the kernel has not changed.
  fresh
  export FAKE_SYSCTL_DEAF=1
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "the kernel did not take it: the install goes on" 0 "$rc"
  has "with a warning" "$out" "does not hold the ports 20000-40999"
  has "that repeats what sysctl said" "$out" "permission denied on key"
  eq "the file is there for the next boot" 20000-40999 "$(reserved_in_file)"
  has "the agent is started" "$(docker_log)" "up -d --force-recreate"

  # The reserved ports cannot be read: nothing is written.
  fresh
  export FAKE_SYSCTL_FAIL=read
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "the list cannot be read: the install goes on" 0 "$rc"
  has "with a warning" "$out" "cannot read net.ipv4.ip_local_reserved_ports"
  absent "and no file is written, which could drop a reservation" "$f"
  lacks "nothing is set" "$(sysctl_log)" "-w"

  # What is not a list of ports is left alone.
  fresh
  printf 'not a list\n' > "$sysctl_state"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "a list that makes no sense: the install goes on" 0 "$rc"
  has "with a warning" "$out" "is not a list of ports"
  absent "and no file is written" "$f"
  eq "and the kernel's list is left alone" "not a list" "$(reserved)"
  lacks "and nothing is set" "$(sysctl_log)" "-w"
}

# net.ipv4.tcp_migrate_req = 1 (finding F2) moves the connections in the accept
# queue of an edge generation that drains to the one that takes over: it goes
# into the sysctl file next to the reserved ports and is set with sysctl -w. A
# kernel without it (before 5.14) is a warning, and the install goes on.
t_tcp_migrate_req() {
  local f
  new_root
  f=$sysctl_dir/90-postern.conf
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0

  echo 0 > "$sysctl_migrate"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "tcp_migrate_req 0: succeeds" 0 "$rc"
  eq "the kernel takes it" 1 "$(cat "$sysctl_migrate")"
  has "with sysctl -w" "$(sysctl_log)" "-w net.ipv4.tcp_migrate_req=1"
  has "the file sets it for the next boot" "$(cat "$f")" "net.ipv4.tcp_migrate_req = 1"
  eq "next to the reserved ports" 20000-40999 "$(reserved_in_file)"
  has "and says so" "$out" "net.ipv4.tcp_migrate_req = 1"
  eq "no warning" "" "$(warnings)"

  # Set already: nothing to set, the file is kept.
  : > "$slog"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  lacks "set already: nothing is set" "$(sysctl_log)" "-w"

  # A kernel without the key: a warning, no line in the file, the install goes on.
  new_root
  f=$sysctl_dir/90-postern.conf
  export FAKE_SYSCTL_NO_MIGRATE=1
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "no tcp_migrate_req: the install goes on" 0 "$rc"
  has "with a warning that names the key" "$(warnings)" "net.ipv4.tcp_migrate_req"
  has "and the kernel it needs" "$(warnings)" "5.14"
  eq "only that warning" 1 "$(warnings | wc -l)"
  lacks "the file does not name it" "$(cat "$f")" "tcp_migrate_req"
  eq "the ports are reserved all the same" 20000-40999 "$(reserved_in_file)"
  lacks "and nothing sets it" "$(sysctl_log)" "-w net.ipv4.tcp_migrate_req"
  has "the agent is started" "$(docker_log)" "up -d --force-recreate"

  # sysctl -w refuses it: a warning, the file for the next boot.
  new_root
  f=$sysctl_dir/90-postern.conf
  echo 0 > "$sysctl_migrate"
  printf '20000-40999\n' > "$sysctl_state"
  export FAKE_SYSCTL_FAIL=w
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "sysctl -w fails: the install goes on" 0 "$rc"
  has "with a warning" "$(warnings)" "sysctl -w net.ipv4.tcp_migrate_req=1 failed"
  has "the file sets it for the next boot" "$(cat "$f")" "net.ipv4.tcp_migrate_req = 1"
  eq "the kernel is as it was" 0 "$(cat "$sysctl_migrate")"
}

# The sysctl file is for the boots to come, and a directory that cannot take it
# does not stop the install: a warning, the ports are reserved in the running
# kernel all the same, and the agent starts. Nothing is left behind in the
# directory.
t_sysctl_dir_cannot_be_written() {
  local f real_uid
  real_uid=$(/usr/bin/id -u)

  # The directory cannot be made: its parent is a file.
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  printf 'a file\n' > "$tmproot/not-a-directory"
  sysctl_dir=$tmproot/not-a-directory/sysctl.d
  f=$sysctl_dir/90-postern.conf
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "a directory that cannot be made: the install completes" 0 "$rc"
  has "with a warning that names the file" "$out" "cannot write $f"
  has "that says what is lost" "$out" "may not survive a reboot"
  eq "only that warning" 1 "$(warnings | wc -l)"
  eq "the ports are reserved in the running kernel all the same" 20000-40999 "$(reserved)"
  has "with sysctl -w" "$(sysctl_log)" "-w net.ipv4.ip_local_reserved_ports=20000-40999"
  has "and said so" "$out" "the ports 20000-40999 are reserved"
  has "the agent is started" "$(docker_log)" "compose -f $root/compose.yaml up -d --force-recreate"
  present "the node is installed" "$root/bin/current"
  has "the summary is printed" "$out" "Postern node installed."
  absent "nothing is made of the directory" "$sysctl_dir"
  eq "the file it is under is as it was" "a file" "$(cat "$tmproot/not-a-directory")"

  # The file cannot be replaced: it is a directory.
  new_root
  mkdir -p "$sysctl_dir/90-postern.conf"
  f=$sysctl_dir/90-postern.conf
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "a file that cannot be replaced: the install completes" 0 "$rc"
  has "with a warning that names the file" "$out" "cannot write $f"
  eq "the ports are reserved in the running kernel" 20000-40999 "$(reserved)"
  eq "no temporary file is left in the directory" 90-postern.conf "$(ls -A "$sysctl_dir")"
  has "the agent is started" "$(docker_log)" "up -d --force-recreate"

  # A directory that is not writable (root writes anywhere, and cannot be tried).
  new_root
  f=$sysctl_dir/90-postern.conf
  if [ "$real_uid" -eq 0 ]; then
    note "running as root: a read-only directory does not stop root, so that case is not tried"
  else
    mkdir -p "$sysctl_dir"
    chmod 555 "$sysctl_dir"
    run_install --bundle "$bundle" --binary "$tmproot/node"
    eq "a read-only directory: the install completes" 0 "$rc"
    has "with a warning that names the file" "$out" "cannot write $f"
    eq "the ports are reserved in the running kernel" 20000-40999 "$(reserved)"
    eq "nothing is left in the directory" "" "$(ls -A "$sysctl_dir")"
    has "the agent is started" "$(docker_log)" "up -d --force-recreate"
    chmod 755 "$sysctl_dir"
  fi

  # Neither the file nor the setting works: two warnings, and the agent starts.
  new_root
  sysctl_dir=$tmproot/not-a-directory/sysctl.d
  f=$sysctl_dir/90-postern.conf
  export FAKE_SYSCTL_FAIL=w
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "nothing can be done: the install completes" 0 "$rc"
  has "a warning for the file" "$out" "cannot write $f"
  has "and one for the setting" "$out" "failed"
  eq "two warnings" 2 "$(warnings | wc -l)"
  eq "the kernel is as it was" "" "$(reserved)"
  has "the agent is started" "$(docker_log)" "up -d --force-recreate"

  # The ports are reserved already: only the file is a warning, and nothing is set.
  new_root
  sysctl_dir=$tmproot/not-a-directory/sysctl.d
  f=$sysctl_dir/90-postern.conf
  printf '20000-40999\n' > "$sysctl_state"
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "reserved by hand, and the file cannot be written: the install completes" 0 "$rc"
  has "with a warning for the file" "$out" "cannot write $f"
  eq "one warning" 1 "$(warnings | wc -l)"
  lacks "nothing is set" "$(sysctl_log)" "-w"
}

# tree_of DIR prints every path under DIR with its type, mode and link target, and
# the checksum of every file: two prints that are the same are the same tree.
tree_of() {
  (
    cd "$1" || exit 1
    find . -printf '%p %y %m %l\n' | LC_ALL=C sort
    find . -type f -exec sha256sum {} + | LC_ALL=C sort
  )
}

# --roll-edge writes data/run/roll-edge for the agent, and does nothing else: no
# bundle, no binary, no Docker but a look at the agent, no sysctl.
t_roll_edge() {
  local f before now t
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node"
  f=$root/data/run/roll-edge
  before=$(tree_of "$root")
  : > "$dlog"
  : > "$slog"

  export FAKE_DOCKER_AGENT=1
  run_install --roll-edge
  eq "--roll-edge succeeds" 0 "$rc"
  has "and says what happens next" "$out" "the agent starts a new generation of the edge"
  eq "no warning" "" "$(warnings)"
  present "data/run/roll-edge is written" "$f"
  eq "it is private" 600 "$(mode "$f")"
  t=$(cat "$f")
  now=$(date +%s)
  if [[ $t =~ ^[0-9]+$ ]] && [ $((now - t)) -ge 0 ] && [ $((now - t)) -le 60 ]; then
    ok "it holds the time of the request in Unix seconds"
  else
    bad "it holds the time of the request in Unix seconds" "it holds [$t], the time is $now"
  fi
  eq "nothing else changed" "$before" "$(tree_of "$root" | grep -v '^\./data/run/roll-edge \|  \./data/run/roll-edge$')"
  eq "Docker was only asked whether the agent runs" "inspect --type container --format {{.State.Running}} postern-agent" "$(docker_log)"
  eq "sysctl was not run" "" "$(sysctl_log)"

  # Asked for again before the agent took it.
  printf '1\n' > "$f"
  run_install --roll-edge
  eq "asking again succeeds" 0 "$rc"
  has "and says that a roll was asked for already" "$out" "asked for already"
  if [ "$(cat "$f")" != 1 ]; then
    ok "the time of the request is the new one"
  else
    bad "the time of the request is the new one" "it is the old one"
  fi
  eq "the file stays private" 600 "$(mode "$f")"

  # The agent does not run: the request waits for it.
  rm -f "$f"
  unset FAKE_DOCKER_AGENT
  run_install --roll-edge
  eq "without a running agent: succeeds" 0 "$rc"
  has "with a warning" "$out" "the postern-agent container is not running"
  present "and the request is there for the agent" "$f"

  # Not as root.
  rm -f "$f"
  export FAKE_UID=1000
  run_install --roll-edge
  fails "--roll-edge as another user than root is refused"
  has "with the reason" "$out" "must run as root"
  absent "and nothing is written" "$f"
  unset FAKE_UID

  # With options that install: a usage error, and nothing is written.
  for args in "--roll-edge --bundle $bundle" "--bundle $bundle --roll-edge" "--roll-edge --binary $tmproot/node" \
    "--roll-edge --version v0.1.0"; do
    # shellcheck disable=SC2086 # one word per argument
    run_install $args
    eq "[$args] is a usage error" 2 "$rc"
    absent "[$args]: nothing is written" "$f"
  done
  has "the message says why" "$out" "--roll-edge goes on its own"

  # No node.
  new_root
  run_install --roll-edge
  fails "--roll-edge where no node is installed is refused"
  has "with the reason" "$out" "no Postern node is installed"
  absent "and nothing is created" "$root"
}

# write_sysctl_file of install.sh, on its own: what it writes, and that a step that
# fails makes it fail, with nothing of its own left in the directory. The steps are
# made to fail by functions of their names, which the shell takes before the programs.
t_write_sysctl_file() {
  local r d=$tmproot/wsf
  rm -rf "$d"
  mkdir -p "$d/adir"
  r=$(
    # shellcheck source=/dev/null
    source "$install_sh"
    set +e
    f=$d/90-postern.conf
    # try TAG FILE CONTENT: write_sysctl_file, and what is left in the directory.
    try() {
      write_sysctl_file "$2" "$3" 2> /dev/null
      rc=$?
      echo "$1 rc=$rc files=$(ls -A "$(dirname "$2")" 2> /dev/null | tr '\n' ',')"
    }
    try new "$f" first
    echo "new mode=$(stat -c %a "$f") content=$(tr '\n' '|' < "$f")"
    try replace "$f" second
    echo "replace content=$(tr '\n' '|' < "$f")"
    mv() { return 1; }
    try mv-fails "$f" third
    echo "mv-fails content=$(tr '\n' '|' < "$f")"
    unset -f mv
    chmod() { return 1; }
    try chmod-fails "$f" third
    unset -f chmod
    tee() { cat > "$2"; return 1; } # writes the file, and fails
    try tee-fails "$f" third
    unset -f tee
    try directory "$d/adir" third
    mkdir() { return 1; }
    try mkdir-fails "$d/sub/90-postern.conf" third
    unset -f mkdir
    echo "one_line=$(one_line $'first\nsecond')"
  )
  eq "a new file is written" "new rc=0 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^new rc=')"
  eq "with a line break at the end, and mode 644" "new mode=644 content=first|" "$(printf '%s\n' "$r" | grep '^new mode=')"
  eq "a file is replaced" "replace rc=0 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^replace rc=')"
  eq "by the new content" "replace content=second|" "$(printf '%s\n' "$r" | grep '^replace content=')"
  eq "a rename that fails: it fails, and leaves nothing" "mv-fails rc=1 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^mv-fails rc=')"
  eq "and the file is as it was" "mv-fails content=second|" "$(printf '%s\n' "$r" | grep '^mv-fails content=')"
  eq "a chmod that fails: it fails, and leaves nothing" "chmod-fails rc=1 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^chmod-fails rc=')"
  eq "a write that fails after it began: it fails, and leaves nothing" "tee-fails rc=1 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^tee-fails rc=')"
  eq "a directory in the place of the file: it fails, and leaves nothing" "directory rc=1 files=90-postern.conf,adir," "$(printf '%s\n' "$r" | grep '^directory rc=')"
  eq "a directory that cannot be made: it fails, and makes nothing" "mkdir-fails rc=1 files=" "$(printf '%s\n' "$r" | grep '^mkdir-fails rc=')"
  eq "a warning has one line" "one_line=first; second" "$(printf '%s\n' "$r" | grep '^one_line=')"
}

# port_list_union of install.sh, on its own.
t_port_list_union() {
  local r
  r=$(
    # shellcheck source=/dev/null
    source "$install_sh"
    set +e
    union() { # union EXPECTED LIST...: one line per case
      local want=$1 got
      shift
      if got=$(port_list_union "$@"); then
        if [ "$got" = "$want" ]; then echo "ok"; else echo "wrong: [$*] gave [$got], want [$want]"; fi
      else
        echo "wrong: [$*] failed, want [$want]"
      fi
    }
    refused() { # refused LIST
      if got=$(port_list_union "$1"); then echo "wrong: [$1] gave [$got], want a failure"; else echo "refused"; fi
      [ -z "$got" ] || echo "wrong: [$1] printed [$got] and failed"
    }
    union "" ""
    union "" " "
    union 20000-40999 "" 20000-40999
    union 8080,20000-40999 8080 20000-40999
    union 20000-50000 30000-50000 20000-40999
    union 1-2 2,1
    union 1-7,10 10,1-5,3-7
    union 1-3 1-3 2
    union 80 00080
    union 1-2 " 1 , 2 "
    union 0-65535 0-65535 20000-40999
    union 5,7 7,5
    for l in 5-3 65536 1-65536 a ',1' '1,' '1,,2' 1-2-3 -1 1- 123456; do refused "$l"; done
  )
  eq "every list is joined as it should be" 0 "$(printf '%s\n' "$r" | grep -c '^wrong')"
  printf '%s\n' "$r" | grep '^wrong' | sed 's/^/       /'
  eq "eleven lists that are not lists of ports are refused" 11 "$(printf '%s\n' "$r" | grep -c '^refused$')"
  eq "twelve unions are right" 12 "$(printf '%s\n' "$r" | grep -c '^ok$')"
}

t_compose_failure_is_reported() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  export FAKE_DOCKER_COMPOSE_FAIL=1
  run_install --bundle "$bundle" --binary "$tmproot/node"
  fails "a failing docker compose fails the script"
  has "with a message that says what is done and what to do" "$out" "The files are installed"
  present "the files are there" "$root/compose.yaml"
}

# bad_bundle DESCRIPTION MESSAGE: the bundle at $bundle must be refused with MESSAGE.
bad_bundle() {
  new_root
  run_install --bundle "$bundle" --binary /bin/true
  fails "$1 is refused"
  has "$1: the message" "$out" "$2"
  absent "$1: nothing was created" "$root"
  host_untouched "$1"
}

t_bad_bundles_are_refused() {
  local d

  bundle=$tmproot/not-a-tar
  echo "hello" > "$bundle"
  bad_bundle "a file that is not a tar archive" "not a tar archive"

  bundle=$tmproot/missing-file.tar
  d=$(bundle_dir "$ID_A" 43117)
  rm "$d/node-key.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle without the key" "has no node-key.pem"

  bundle=$tmproot/extra-file.tar
  d=$(bundle_dir "$ID_A" 43117)
  echo "x" > "$d/evil.sh"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle with an extra file" "unexpected entry"

  bundle=$tmproot/traversal.tar
  d=$(bundle_dir "$ID_A" 43117)
  (cd "$d" && tar --format=ustar --transform 's,^ca\.pem$,../ca.pem,' -cf "$bundle" -- *)
  bad_bundle "a bundle with a path that leaves the directory" "unexpected entry"

  bundle=$tmproot/duplicate.tar
  d=$(bundle_dir "$ID_A" 43117)
  tar_dir "$bundle" "$d"
  (cd "$d" && tar --format=ustar -rf "$bundle" ca.pem)
  bad_bundle "a bundle that lists a file twice" "twice"

  bundle=$tmproot/empty-file.tar
  d=$(bundle_dir "$ID_A" 43117)
  : > "$d/ca.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle with an empty file" "empty or larger"

  bundle=$tmproot/big-file.tar
  d=$(bundle_dir "$ID_A" 43117)
  head -c 70000 /dev/zero | tr '\0' 'A' > "$d/ca.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle with a file over 64 KiB" "empty or larger"

  bundle=$tmproot/huge-file.tar
  d=$(bundle_dir "$ID_A" 43117)
  head -c 8388608 /dev/zero | tr '\0' 'A' > "$d/node.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle with a file of 8 MiB" "empty or larger"

  bundle=$tmproot/symlink.tar
  d=$(bundle_dir "$ID_A" 43117)
  rm "$d/ca.pem"
  ln -s /etc/passwd "$d/ca.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle whose file is a symlink" "empty or larger"

  bundle=$tmproot/version2.tar
  d=$(bundle_dir "$ID_A" 43117)
  printf '{"version":2,"node_id":"%s","mgmt_port":43117}' "$ID_A" > "$d/bundle.json"
  tar_dir "$bundle" "$d"
  bad_bundle "a bundle of version 2" "unsupported bundle version"

  bundle=$tmproot/port0.tar
  d=$(bundle_dir "$ID_A" 0)
  tar_dir "$bundle" "$d"
  bad_bundle "management port 0" "out of range"

  bundle=$tmproot/port65536.tar
  d=$(bundle_dir "$ID_A" 65536)
  tar_dir "$bundle" "$d"
  bad_bundle "management port 65536" "out of range"

  bundle=$tmproot/port-text.tar
  d=$(bundle_dir "$ID_A" 43117)
  printf '{"version":1,"node_id":"%s","mgmt_port":"43117"}' "$ID_A" > "$d/bundle.json"
  tar_dir "$bundle" "$d"
  bad_bundle "a management port that is a string" "mgmt_port"

  bundle=$tmproot/port-float.tar
  d=$(bundle_dir "$ID_A" 43117)
  printf '{"version":1,"node_id":"%s","mgmt_port":4.5}' "$ID_A" > "$d/bundle.json"
  tar_dir "$bundle" "$d"
  bad_bundle "a management port that is not an integer" "mgmt_port"

  bundle=$tmproot/no-id.tar
  d=$(bundle_dir "$ID_A" 43117)
  printf '{"version":1,"mgmt_port":43117}' > "$d/bundle.json"
  tar_dir "$bundle" "$d"
  bad_bundle "metadata without a node id" "node_id"

  bundle=$tmproot/garbage-ca.tar
  d=$(bundle_dir "$ID_A" 43117)
  echo "not a certificate" > "$d/ca.pem"
  tar_dir "$bundle" "$d"
  bad_bundle "a CA file that is not a PEM certificate" "not a PEM certificate"
}

t_bundle_metadata_cannot_choose_modes_or_owners() {
  new_root
  local d
  d=$(bundle_dir "$ID_A" 43117)
  bundle=$tmproot/loose.tar
  (cd "$d" && tar --format=ustar --owner=12345 --group=12345 --mode=0777 -cf "$bundle" -- *)
  mkfakebin "$tmproot/node" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "succeeds" 0 "$rc"
  eq "the key is 0600 whatever the archive says" 600 "$(mode "$root/pki/node-key.pem")"
  eq "and belongs to the user running the script" "$(id -u)" "$(stat -c %u "$root/pki/node-key.pem")"
}

t_dot_slash_names_are_accepted() {
  new_root
  local d
  d=$(bundle_dir "$ID_A" 43117)
  bundle=$tmproot/dotslash.tar
  (cd "$d" && tar --format=ustar -cf "$bundle" ./bundle.json ./ca.pem ./node.pem ./node-key.pem)
  mkfakebin "$tmproot/node" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node"
  eq "a bundle packed with ./ names is accepted" 0 "$rc"
  eq "and installed" "$ID_A" "$(cat "$root/data/state/node-id")"
}

t_release_download() {
  new_root
  mkbundle "$ID_A" 43117
  local rel=$tmproot/releases$n asset sum arch
  mkdir -p "$rel/v1.2.3"
  mkfakebin "$rel/v1.2.3/postern-node-linux-amd64" v1.2.3 amd
  mkfakebin "$rel/v1.2.3/postern-node-linux-arm64" v1.2.3 arm
  sum=$rel/v1.2.3/SHA256SUMS
  (cd "$rel/v1.2.3" && sha256sum postern-node-linux-amd64 postern-node-linux-arm64 > SHA256SUMS)
  case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  asset=postern-node-linux-$arch

  run_install --bundle "$bundle" --version v1.2.3
  fails "without POSTERN_RELEASE_BASE a download is refused"
  has "and the message names the variable" "$out" "POSTERN_RELEASE_BASE"

  export POSTERN_RELEASE_BASE=file://$rel/
  export FAKE_CURL_LOG=$tmproot/curl$n.log
  : > "$FAKE_CURL_LOG"
  run_install --bundle "$bundle" --version v1.2.3
  eq "a release is downloaded and installed" 0 "$rc"
  eq "under the name of the version" postern-node-v1.2.3 "$(target "$root/bin/current")"
  same_file "with the downloaded content" "$rel/v1.2.3/$asset" "$root/bin/postern-node-v1.2.3"
  eq "the staging directory is gone" "" "$(ls -A "$root/bin" | grep '^\.' || true)"
  has "curl is told to take https and file URLs only" "$(cat "$FAKE_CURL_LOG")" "--proto =https,file "
  has "and to follow a redirect over https only" "$(cat "$FAKE_CURL_LOG")" "--proto-redir =https "
  unset FAKE_CURL_LOG

  printf '#!/bin/sh\necho tampered\n' > "$rel/v1.2.3/$asset"
  run_install --bundle "$bundle" --version v1.2.3
  eq "a release that is installed already is not downloaded again" 0 "$rc"

  new_root
  export POSTERN_RELEASE_BASE=file://$rel
  run_install --bundle "$bundle" --version v1.2.3
  fails "a binary that does not match SHA256SUMS is refused"
  has "and the message says so" "$out" "checksum mismatch"
  absent "and is not installed" "$root/bin/postern-node-v1.2.3"
  absent "and not linked" "$root/bin/current"

  mkfakebin "$rel/v1.2.3/$asset" v1.2.3 repaired
  grep -v " $asset\$" "$sum" > "$sum.new"
  mv "$sum.new" "$sum"
  run_install --bundle "$bundle" --version v1.2.3
  fails "a SHA256SUMS without the asset is refused"
  has "and the message says so" "$out" "no entry for $asset"

  rm "$sum"
  run_install --bundle "$bundle" --version v1.2.3
  fails "a missing SHA256SUMS is refused"
  has "and the message says so" "$out" "download failed"

  run_install --bundle "$bundle" --version v9.9.9
  fails "a missing release is refused"
}

# mksig PATH VERSION [ARCH] writes a minisign signature file of postern-node VERSION
# for linux/ARCH (the host's by default), as the release job signs one. The key
# and signature lines are base64 that nothing here verifies: the agent does that.
mksig() {
  local arch=${3:-}
  if [ -z "$arch" ]; then case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac; fi
  printf 'untrusted comment: signature from minisign secret key\nRUQzc2lnbmF0dXJl%s==\ntrusted comment: postern postern-node %s linux/%s\nZ2xvYmFsIHNpZ25hdHVyZQ==\n' \
    "${RANDOM}A" "$2" "$arch" > "$1"
}

# dot_files DIR prints the names of the dot files of DIR, one a line.
dot_files() (
  shopt -s nullglob
  local f
  for f in "$1"/.[!.]*; do printf '%s\n' "${f##*/}"; done
)

# The signature of the installed binary is kept beside it, as UpdateSelf keeps one,
# for an edge roll to that version: from beside a --binary, and from a release.
t_signature_is_kept() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node-sig" v0.1.0
  mksig "$tmproot/node-sig.minisig" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node-sig"
  eq "a binary with its signature beside it installs" 0 "$rc"
  same_file "and the signature is kept beside the binary" "$tmproot/node-sig.minisig" "$root/bin/.postern-node-v0.1.0.minisig"
  eq "readable by all" 644 "$(mode "$root/bin/.postern-node-v0.1.0.minisig")"
  eq "and nothing else is left over in bin/" .postern-node-v0.1.0.minisig "$(dot_files "$root/bin")"

  # A re-run keeps the signature again; one without a signature leaves it.
  mksig "$tmproot/node-sig.minisig" v0.1.0
  run_install --bundle "$bundle" --binary "$tmproot/node-sig"
  eq "a re-run succeeds" 0 "$rc"
  same_file "and keeps the signature again" "$tmproot/node-sig.minisig" "$root/bin/.postern-node-v0.1.0.minisig"
  cp "$tmproot/node-sig.minisig" "$tmproot/kept.minisig"
  rm "$tmproot/node-sig.minisig"
  run_install --bundle "$bundle" --binary "$tmproot/node-sig"
  eq "a re-run without a signature succeeds" 0 "$rc"
  same_file "and leaves the kept one" "$tmproot/kept.minisig" "$root/bin/.postern-node-v0.1.0.minisig"

  # A signature of another version, or another architecture, or not a signature.
  for bad_sig in "v0.2.0" "v0.1.0 other" "junk"; do
    new_root
    case $bad_sig in
      junk) printf 'not a signature\n' > "$tmproot/node-sig.minisig" ;;
      *" other") mksig "$tmproot/node-sig.minisig" v0.1.0 riscv64 ;;
      *) mksig "$tmproot/node-sig.minisig" "$bad_sig" ;;
    esac
    run_install --bundle "$bundle" --binary "$tmproot/node-sig"
    fails "a signature that is not the binary's is refused [$bad_sig]"
    has "[$bad_sig]: the message says so" "$out" "signature"
    absent "[$bad_sig]: the binary is not installed" "$root/bin/postern-node-v0.1.0"
    absent "[$bad_sig]: no signature is kept" "$root/bin/.postern-node-v0.1.0.minisig"
  done
  rm -f "$tmproot/node-sig.minisig"

  # From a release: <asset>.minisig beside the binary.
  new_root
  local rel=$tmproot/signed-releases$n asset arch
  case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  asset=postern-node-linux-$arch
  mkdir -p "$rel/v1.2.3" "$rel/v1.2.4"
  mkfakebin "$rel/v1.2.3/$asset" v1.2.3
  mksig "$rel/v1.2.3/$asset.minisig" v1.2.3
  mkfakebin "$rel/v1.2.4/$asset" v1.2.4
  (cd "$rel/v1.2.3" && sha256sum "$asset" > SHA256SUMS)
  (cd "$rel/v1.2.4" && sha256sum "$asset" > SHA256SUMS)
  export POSTERN_RELEASE_BASE=file://$rel
  run_install --bundle "$bundle" --version v1.2.3
  eq "a signed release installs" 0 "$rc"
  same_file "and its signature is kept" "$rel/v1.2.3/$asset.minisig" "$root/bin/.postern-node-v1.2.3.minisig"
  eq "and nothing else is left over in bin/" .postern-node-v1.2.3.minisig "$(dot_files "$root/bin")"

  # A re-run of an installed release whose signature is not kept fetches it.
  rm "$root/bin/.postern-node-v1.2.3.minisig"
  run_install --bundle "$bundle" --version v1.2.3
  eq "a re-run of the installed release succeeds" 0 "$rc"
  same_file "and keeps its signature again" "$rel/v1.2.3/$asset.minisig" "$root/bin/.postern-node-v1.2.3.minisig"

  # A release without a signature installs, with a warning that says what it means.
  run_install --bundle "$bundle" --version v1.2.4
  eq "a release without a signature installs" 0 "$rc"
  has "with a warning" "$(warnings)" "no signature"
  absent "and no signature is kept for it" "$root/bin/.postern-node-v1.2.4.minisig"

  # A release whose signature is of another version is refused.
  mksig "$rel/v1.2.4/$asset.minisig" v1.2.3
  rm -f "$root/bin/postern-node-v1.2.4"
  run_install --bundle "$bundle" --version v1.2.4
  fails "a release whose signature is of another version is refused"
  has "and the message says so" "$out" "signature"
}

# The release base is https:// (or file://, for a mirror on the host), and nothing
# else: the binary runs as root.
t_release_base_must_be_https_or_file() {
  local base
  new_root
  mkbundle "$ID_A" 43117
  export FAKE_CURL_LOG=$tmproot/curl$n.log
  : > "$FAKE_CURL_LOG"
  for base in \
    http://releases.example.com/dl HTTP://releases.example.com/dl http://127.0.0.1:8080/dl \
    ftp://releases.example.com/dl releases.example.com/dl //releases.example.com/dl /srv/releases \
    file:/srv/releases https:/releases.example.com https:// file:// "scp://releases.example.com/dl"; do
    export POSTERN_RELEASE_BASE=$base
    run_install --bundle "$bundle" --version v1.2.3
    fails "the base [$base] is refused"
    has "[$base]: the message names the variable" "$out" "POSTERN_RELEASE_BASE"
    lacks "[$base]: nothing was downloaded" "$out" "download failed"
    eq "[$base]: curl was never run" "" "$(cat "$FAKE_CURL_LOG")"
    absent "[$base]: no binary was installed" "$root/bin/postern-node-v1.2.3"
  done

  export POSTERN_RELEASE_BASE=http://releases.example.com/dl
  run_install --bundle "$bundle" --version v1.2.3
  has "plain http is called by its name" "$out" "plain http://"
  has "and the message says what to use" "$out" "https://"

  # A base may have a password in it: the refusal does not repeat it.
  export POSTERN_RELEASE_BASE=http://user:hunter2@releases.example.com/dl # gitleaks:allow (a fake credential)
  run_install --bundle "$bundle" --version v1.2.3
  fails "a base with a password in it, over http, is refused"
  lacks "and the password is not repeated" "$out" "hunter2"

  # A release that is installed already needs no download, and so no base.
  unset POSTERN_RELEASE_BASE
  mkfakebin "$tmproot/node-0.1.0" v1.2.3
  run_install --bundle "$bundle" --binary "$tmproot/node-0.1.0" --version v1.2.3
  export POSTERN_RELEASE_BASE=http://releases.example.com/dl
  run_install --bundle "$bundle" --version v1.2.3
  eq "an installed release is kept, whatever the base is" 0 "$rc"
}

# An https:// base works, which the other tests cannot show: they have no host with a
# certificate to download from. The fake curl is that host.
t_release_download_over_https() {
  new_root
  mkbundle "$ID_A" 43117
  local rel=$tmproot/https-releases$n arch log
  mkdir -p "$rel/v1.2.3"
  mkfakebin "$rel/v1.2.3/postern-node-linux-amd64" v1.2.3 amd
  mkfakebin "$rel/v1.2.3/postern-node-linux-arm64" v1.2.3 arm
  (cd "$rel/v1.2.3" && sha256sum postern-node-linux-amd64 postern-node-linux-arm64 > SHA256SUMS)
  case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  export FAKE_CURL_LOG=$tmproot/curl$n.log FAKE_CURL_ROOT=$rel FAKE_CURL_PREFIX=https://releases.example.com/dl/
  : > "$FAKE_CURL_LOG"
  export POSTERN_RELEASE_BASE=https://releases.example.com/dl/
  run_install --bundle "$bundle" --version v1.2.3
  eq "a release is downloaded from an https:// base" 0 "$rc"
  eq "and installed" postern-node-v1.2.3 "$(target "$root/bin/current")"
  same_file "with the content that was served" "$rel/v1.2.3/postern-node-linux-$arch" "$root/bin/postern-node-v1.2.3"
  log=$(cat "$FAKE_CURL_LOG")
  has "the binary is asked for under <base>/<version>/" "$log" "https://releases.example.com/dl/v1.2.3/postern-node-linux-$arch"
  has "and so is the list of checksums" "$log" "https://releases.example.com/dl/v1.2.3/SHA256SUMS"
  has "curl is told to take https and file URLs only" "$log" "--proto =https,file "
  has "and to follow a redirect over https only" "$log" "--proto-redir =https "
}

# A base may carry a user name and a password. A download that fails names the
# URL without them, and so does what curl says about it, which is passed on.
t_release_download_keeps_credentials_out() {
  new_root
  mkbundle "$ID_A" 43117
  local rel=$tmproot/private-releases$n
  mkdir -p "$rel"
  export FAKE_CURL_LOG=$tmproot/curl$n.log FAKE_CURL_ROOT=$rel
  export FAKE_CURL_PREFIX=https://user:hunter2@releases.example.com/dl/ # gitleaks:allow (a fake credential)
  : > "$FAKE_CURL_LOG"
  export POSTERN_RELEASE_BASE=https://user:hunter2@releases.example.com/dl # gitleaks:allow (a fake credential)
  run_install --bundle "$bundle" --version v9.9.9
  fails "a release that is not there is not installed"
  has "the download is reported as failed, with the URL" "$out" "download failed: https://releases.example.com/dl/v9.9.9/postern-node-linux-"
  has "and what curl said is passed on" "$out" "fake curl: not found: https://releases.example.com/dl/v9.9.9/postern-node-linux-"
  lacks "the password is never repeated" "$out" "hunter2"
  lacks "nor the user name" "$out" "user:"
  has "curl was given the URL with them" "$(cat "$FAKE_CURL_LOG")" "https://user:hunter2@releases.example.com/dl/v9.9.9/" # gitleaks:allow (a fake credential)
}

# fetch_with_path PATH URL runs fetch of install.sh, with PATH as the only places
# to look for curl, and prints what it said and "rc=<its status>".
fetch_with_path() {
  (
    # shellcheck source=/dev/null
    source "$install_sh"
    set +e
    # shellcheck disable=SC2030 # the PATH of this subshell is the only one that changes
    PATH=$1
    (fetch "$2" "$tmproot/dest") 2>&1
    echo "rc=$?"
  )
}

# download_with_path PATH runs download_release of install.sh for v1.2.3 from an
# https:// base, with PATH as the only places to look for programs, and prints what
# it said and "rc=<its status>".
download_with_path() {
  (
    # shellcheck source=/dev/null
    source "$install_sh"
    set +e
    POSTERN_RELEASE_BASE=https://releases.example.com/dl
    # shellcheck disable=SC2030 # the PATH of this subshell is the only one that changes
    PATH=$1
    (download_release v1.2.3 "$tmproot/dest") 2>&1
    echo "rc=$?"
  )
}

# A release is downloaded with curl and with nothing else: wget cannot be kept from
# following a redirect from https to http. curl is told to take https and file URLs
# only, and refuses plain http on its own.
t_fetch_takes_curl_only() {
  local wget_only=$tmproot/wget-only curl_only=$tmproot/curl-only nothing=$tmproot/no-tools dir msg
  new_root # and so no fake release host of an earlier test: the real curl runs below
  mkdir -p "$wget_only" "$curl_only" "$nothing"
  # Tools that only write down how they were called.
  cat > "$wget_only/wget" << 'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$TOOL_LOG"
exit 0
EOF
  cp "$wget_only/wget" "$curl_only/curl"
  chmod 755 "$wget_only/wget" "$curl_only/curl"
  export TOOL_LOG=$tmproot/tool.log

  for dir in "$wget_only" "$nothing"; do
    : > "$TOOL_LOG"
    msg=$(download_with_path "$dir")
    has "without curl [${dir##*/}]: a release is not downloaded" "$msg" "need curl"
    has "[${dir##*/}]: the message says what to do instead" "$msg" "--binary"
    lacks "[${dir##*/}]: and it is a failure" "$msg" "rc=0"
    eq "[${dir##*/}]: wget is never run" "" "$(cat "$TOOL_LOG")"
  done

  : > "$TOOL_LOG"
  msg=$(fetch_with_path "$curl_only" "https://releases.example.com/x")
  has "curl is run for an https:// URL" "$msg" "rc=0"
  has "with https and file as the only protocols" "$(cat "$TOOL_LOG")" "--proto =https,file --proto-redir =https "
  has "and with the URL last" "$(cat "$TOOL_LOG")" "--output $tmproot/dest https://releases.example.com/x"
  unset TOOL_LOG

  if [ -z "$real_curl" ]; then
    note "skipped the real curl: there is none"
    return
  fi
  # The real curl says no to plain http before it connects to anything: status 1,
  # a protocol that is not taken. Without --proto it would try the connection, and
  # fail with 7 (nothing listens on port 9).
  export FAKE_CURL_LOG=$tmproot/curl-fetch.log
  : > "$FAKE_CURL_LOG"
  # shellcheck disable=SC2031 # this is the PATH of the test, not the one of the helper
  msg=$(fetch_with_path "$fakebin:$PATH" "http://127.0.0.1:9/x")
  eq "the real curl refuses an http:// URL itself (status 1)" "exit 1" "$(grep '^exit ' "$FAKE_CURL_LOG")"
  has "and says that the protocol is not taken" "$msg" 'Protocol "http" not supported'
  has "and the download is reported as failed" "$msg" "download failed: http://127.0.0.1:9/x"

  # A URL with a password in it, which curl tries and cannot connect to.
  : > "$FAKE_CURL_LOG"
  # shellcheck disable=SC2031
  msg=$(fetch_with_path "$fakebin:$PATH" "https://user:hunter2@127.0.0.1:9/x") # gitleaks:allow (a fake credential)
  eq "the real curl tries a URL with a password and cannot connect (status 7)" "exit 7" "$(grep '^exit ' "$FAKE_CURL_LOG")"
  has "the download is reported as failed, with the URL" "$msg" "download failed: https://127.0.0.1:9/x"
  lacks "without the password" "$msg" "hunter2"
  lacks "or the user name" "$msg" "user:"
  unset FAKE_CURL_LOG
}

# bundle_checks_with_tar DESCRIPTION DIR runs install.sh with DIR/tar as its tar,
# which writes its arguments to DIR/calls: a bundle with a relative name that has a
# colon in it is read and installed, and a file that is not a tar archive is
# refused for what it is.
bundle_checks_with_tar() {
  local what=$1 dir=$2 d
  new_root
  tar_bin_dir=$dir
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  cp "$bundle" "$tmproot/host:bundle.tar"
  pushd "$tmproot" > /dev/null || return
  run_install --bundle "host:bundle.tar" --binary "$tmproot/node"
  popd > /dev/null || return
  eq "$what: a bundle with a colon in its name is read and installed" 0 "$rc"
  eq "$what: the node id is stored" "$ID_A" "$(cat "$root/data/state/node-id" 2> /dev/null)"
  d=$tmproot/unpacked-$n
  mkdir -p "$d"
  "$real_tar" -xf "$bundle" -C "$d"
  same_file "$what: the key is installed unchanged" "$d/node-key.pem" "$root/pki/node-key.pem"
  has "$what: install.sh used this tar, with a name that is local to every tar" "$(cat "$dir/calls" 2> /dev/null)" "-tf ./host:bundle.tar"

  new_root
  tar_bin_dir=$dir
  bundle=$tmproot/not-a-tar
  echo "hello" > "$bundle"
  run_install --bundle "$bundle" --binary /bin/true
  fails "$what: a file that is not a tar archive is refused"
  has "$what: for what it is" "$out" "not a tar archive"
  tar_bin_dir=
}

# Hosts without GNU tar have busybox tar (Alpine, for one). It knows its own short
# options and a few long ones, and refuses any other, GNU tar's --force-local among
# them, with its usage; and it reads every name as a local file. The bundle checks
# must pass with it. Two such tars: a stand-in that refuses what busybox tar does
# not know and runs the real tar otherwise, and, when the Docker daemon has the
# runner image, busybox tar itself.
t_bundle_checks_with_busybox_tar() {
  local dir=$tmproot/strict-tar
  mkdir -p "$dir"
  cat > "$dir/tar" << EOF
#!/bin/sh
# The options of busybox tar 1.37, as tar --help in the runner image lists them.
printf '%s\n' "\$*" >> "$dir/calls"
for a in "\$@"; do
  case \$a in
    --) break ;;
    --exclude | --exclude=* | --overwrite | --strip-components | --strip-components=* | --no-recursion | --numeric-owner | --no-same-permissions | --lzma) ;;
    --*)
      echo "tar: unrecognized option: \${a#--}" >&2
      echo "Usage: tar c|x|t [-ZzJjahmvokO] [-f TARFILE] [-C DIR] [-T FILE] [-X FILE] [LONGOPT]... [FILE]..." >&2
      exit 1
      ;;
    -*[!cxtZzJjahmvokOfCTX]*)
      echo "tar: invalid option -- '\${a#-}'" >&2
      exit 1
      ;;
  esac
done
exec "$real_tar" "\$@"
EOF
  chmod 755 "$dir/tar"
  bundle_checks_with_tar "a tar with the options of busybox tar only" "$dir"

  if [ -z "$real_docker" ] || ! "$real_docker" image inspect "$runner_image" > /dev/null 2>&1; then
    note "skipped busybox tar of the runner image: no Docker, or no runner image (docker pull $runner_image)"
    return
  fi
  dir=$tmproot/busybox-tar
  mkdir -p "$dir"
  cat > "$dir/tar" << EOF
#!/bin/sh
# busybox tar of the runner image, on the files of the test, which are mounted at
# the same path.
printf '%s\n' "\$*" >> "$dir/calls"
exec "$real_docker" run --rm --network none -v "$tmproot:$tmproot:ro" -w "\$PWD" "$runner_image" tar "\$@"
EOF
  chmod 755 "$dir/tar"
  bundle_checks_with_tar "busybox tar of the runner image" "$dir"
}

# The members of an archive are copied out to the disk up to the limit and no
# further, whatever their size, and the name of the archive is a local file.
t_read_member_stops_at_the_cap() {
  local d=$tmproot/members work=$tmproot/members-work r
  mkdir -p "$d" "$work"
  head -c 100 /dev/zero | tr '\0' 'a' > "$d/small"
  head -c 65536 /dev/zero | tr '\0' 'a' > "$d/exact"
  head -c 65537 /dev/zero | tr '\0' 'a' > "$d/over"
  head -c 10485760 /dev/zero | tr '\0' 'a' > "$d/huge"
  (cd "$d" && tar --format=ustar -cf "$tmproot/members.tar" -- small exact over huge)
  echo "not a tar archive" > "$tmproot/not-a-tar"
  r=$(
    # shellcheck source=/dev/null
    source "$install_sh"
    set +e
    for m in small exact over huge; do
      read_member "$tmproot/members.tar" "$m" "$work/$m" 2> /dev/null
      echo "$m rc=$? size=$(wc -c < "$work/$m") mode=$(stat -c %a "$work/$m")"
    done
    read_member "$tmproot/members.tar" nope "$work/nope" 2> /dev/null
    echo "missing-member rc=$?"
    read_member "$tmproot/not-a-tar" small "$work/not-a-tar" 2> /dev/null
    echo "not-an-archive rc=$?"
    read_member "$tmproot/members.tar" small "$work/no-such-dir/file" 2> /dev/null
    echo "unwritable rc=$?"
  )
  has "a member under the limit is copied whole" "$r" "small rc=0 size=100 mode=600"
  has "one of exactly 64 KiB is copied whole" "$r" "exact rc=0 size=65536 mode=600"
  has "one byte more is copied, so that it is seen to be too big" "$r" "over rc=0 size=65537 mode=600"
  has "a member of 10 MiB stops at 64 KiB and a byte" "$r" "huge rc=0 size=65537 mode=600"
  lacks "a member that is not there is not a success" "$r" "missing-member rc=0"
  lacks "an archive that is not one is not a success" "$r" "not-an-archive rc=0"
  lacks "a file that cannot be written is not a success" "$r" "unwritable rc=0"
}

t_bundle_name_with_a_colon_is_a_local_file() {
  new_root
  mkbundle "$ID_A" 43117
  mkfakebin "$tmproot/node" v0.1.0
  cp "$bundle" "$tmproot/host:bundle.tar"
  # GNU tar takes a name with a colon in it for a file on another machine, unless
  # it has a slash before the colon: install.sh puts ./ before a relative name.
  pushd "$tmproot" > /dev/null || return
  run_install --bundle "host:bundle.tar" --binary "$tmproot/node"
  popd > /dev/null || return
  eq "a bundle whose name has a colon in it is read as a local file" 0 "$rc"
  eq "and installed" "$ID_A" "$(cat "$root/data/state/node-id")"
}

t_unit_functions() {
  local r
  r=$(
    # shellcheck source=install.sh
    source "$install_sh"
    set +e
    for id in "$ID_A" "$ID_B" 00000000000000000000000000; do valid_node_id "$id" && echo "id-ok" || echo "id-bad:$id"; done
    for id in "" 01ARZ3NDEKTSV4RRFFQ69G5FAv "$ID_A"$'\n' "${ID_A}0" "${ID_A%?}" "${ID_A%?}/"; do valid_node_id "$id" && echo "id-wrongly-ok:$id" || echo "id-refused"; done
    for v in v1.2.3 1.2.3-rc.1+build5 dev a; do valid_version "$v" && echo "ver-ok" || echo "ver-bad:$v"; done
    for v in "" ../x a/b -x .x "a b" 'a;b' "$(printf 'a%.0s' $(seq 1 65))"; do valid_version "$v" && echo "ver-wrongly-ok:$v" || echo "ver-refused"; done
    json='{"version":1,"node_id":"X1","mgmt_port":43117}'
    echo "node_id=$(json_field "$json" node_id string)"
    echo "mgmt_port=$(json_field "$json" mgmt_port integer)"
    echo "version=$(json_field "$json" version integer)"
    pretty=$'{\n  "version": 1,\n  "node_id": "X2",\n  "mgmt_port": 4000\n}'
    echo "pretty node_id=$(json_field "$pretty" node_id string)"
    echo "pretty mgmt_port=$(json_field "$pretty" mgmt_port integer)"
    json_field '{"node_id":"a","node_id":"b"}' node_id string > /dev/null && echo "dup-wrongly-ok" || echo "dup-refused"
    json_field '{"mgmt_port":"7"}' mgmt_port integer > /dev/null && echo "str-as-int-wrongly-ok" || echo "str-as-int-refused"
    json_field '{"node_id":7}' node_id string > /dev/null && echo "int-as-str-wrongly-ok" || echo "int-as-str-refused"
    json_field '{"mgmt_port":4.5}' mgmt_port integer > /dev/null && echo "float-wrongly-ok" || echo "float-refused"
    # URLs with made-up credentials in them.
    echo "url1=$(without_userinfo 'https://user:pw@releases.example.com/dl')" # gitleaks:allow
    echo "url2=$(without_userinfo 'HTTPS://user@releases.example.com/dl?v=1')"
    echo "url3=$(without_userinfo 'file://user:pw@/srv/releases')" # gitleaks:allow
    echo "url4=$(without_userinfo 'https://a@b:pw@releases.example.com/x')" # gitleaks:allow
    echo "url5=$(without_userinfo 'https://releases.example.com/a@b and mail@example.com')"
    echo "url6=$(without_userinfo 'https://releases.example.com/dl')"
    without_userinfo $'curl: https://u:pw@one.example.com/x, https://two.example.com/y\nand ftp://u@three.example.com' # gitleaks:allow
  )
  eq "valid node ids are accepted" "id-ok id-ok id-ok" "$(printf '%s\n' "$r" | grep '^id-ok$\|^id-bad' | tr '\n' ' ' | sed 's/ $//')"
  eq "six malformed node ids are refused" 6 "$(printf '%s\n' "$r" | grep -c '^id-refused$')"
  eq "valid versions are accepted" 4 "$(printf '%s\n' "$r" | grep -c '^ver-ok$')"
  eq "eight malformed versions are refused" 8 "$(printf '%s\n' "$r" | grep -c '^ver-refused$')"
  lacks "nothing malformed slipped through" "$r" "wrongly"
  has "json: compact string" "$r" "node_id=X1"
  has "json: compact integer" "$r" "mgmt_port=43117"
  has "json: version" "$r" "version=1"
  has "json: pretty string" "$r" "pretty node_id=X2"
  has "json: pretty integer" "$r" "pretty mgmt_port=4000"
  has "json: duplicates are refused" "$r" "dup-refused"
  has "json: a string is not an integer" "$r" "str-as-int-refused"
  has "json: an integer is not a string" "$r" "int-as-str-refused"
  has "json: a float is not an integer" "$r" "float-refused"
  has "userinfo: a user and a password are taken out" "$r" "url1=https://releases.example.com/dl"
  has "userinfo: a user alone, any case of the scheme" "$r" "url2=HTTPS://releases.example.com/dl?v=1"
  has "userinfo: a file:// URL" "$r" "url3=file:///srv/releases"
  has "userinfo: up to the last @ before the host" "$r" "url4=https://releases.example.com/x"
  has "userinfo: an @ after the host stays" "$r" "url5=https://releases.example.com/a@b and mail@example.com"
  has "userinfo: a URL without one is unchanged" "$r" "url6=https://releases.example.com/dl"
  has "userinfo: every URL of a text" "$r" "curl: https://one.example.com/x, https://two.example.com/y"
  has "userinfo: on every line" "$r" "and ftp://three.example.com"
  lacks "userinfo: no password is left" "$r" "pw@"
}

# ---- run -------------------------------------------------------------------------

for t in \
  t_tcp_migrate_req \
  t_fresh_install \
  t_rerun_is_idempotent \
  t_new_binary_keeps_the_old_one_as_previous \
  t_binary_options \
  t_same_version_other_content_is_refused \
  t_other_node_state_is_moved_aside \
  t_state_of_unknown_origin_is_moved_aside \
  t_empty_state_is_not_moved \
  t_invalid_node_ids_are_refused \
  t_refusals_leave_the_host_alone \
  t_missing_docker_prints_instructions \
  t_reserved_ports \
  t_sysctl_dir_cannot_be_written \
  t_write_sysctl_file \
  t_port_list_union \
  t_roll_edge \
  t_compose_failure_is_reported \
  t_bad_bundles_are_refused \
  t_bundle_metadata_cannot_choose_modes_or_owners \
  t_dot_slash_names_are_accepted \
  t_release_download \
  t_signature_is_kept \
  t_release_base_must_be_https_or_file \
  t_release_download_over_https \
  t_release_download_keeps_credentials_out \
  t_fetch_takes_curl_only \
  t_read_member_stops_at_the_cap \
  t_bundle_name_with_a_colon_is_a_local_file \
  t_bundle_checks_with_busybox_tar \
  t_unit_functions; do
  echo "$t"
  "$t"
done

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then exit 1; fi
