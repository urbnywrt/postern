#!/bin/sh
# Tests for launcher.sh. POSIX sh, so the same file runs under dash and under
# the busybox ash of the runner image.
#
# From the repository root:
#
#   bash scripts/wsl 'sh deploy/node/launcher_test.sh'
#
# Inside the runner image, which proves that launcher.sh works with busybox:
#
#   docker run --rm -v "$PWD":/src:ro \
#     alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
#     sh /src/deploy/node/launcher_test.sh
#
# POSTERN_TEST_SHELL=<shell> runs the launcher as "<shell> launcher.sh" instead
# of through its #! line, for example POSTERN_TEST_SHELL=bash.
#
# Every test gets a fresh POSTERN_HOME in a temporary directory, with fake
# "postern-node" binaries whose behaviour a control file selects:
#
#   healthy        write the healthy marker and exit 0
#   healthy-crash  write the healthy marker and exit 1 (dies after it was up)
#   crash          exit 1 without a marker (the default)
#   exit<N>        exit with status N, no marker
#
# Each fake appends one line to $POSTERN_HOME/trace when it starts.

set -u

here=$(cd "$(dirname "$0")" && pwd) || exit 1
launcher_src=$here/launcher.sh

tmproot=$(mktemp -d "${TMPDIR:-/tmp}/postern-launcher-test.XXXXXX") || exit 1
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

# has DESCRIPTION HAYSTACK NEEDLE: NEEDLE is a substring of HAYSTACK
has() {
  case $2 in
    *"$3"*) ok "$1" ;;
    *) bad "$1" "no [$3] in [$2]" ;;
  esac
}

# absent DESCRIPTION PATH: nothing at PATH, not even a dangling symlink
absent() {
  if [ -e "$2" ] || [ -L "$2" ]; then
    bad "$1" "$2 exists"
  else
    ok "$1"
  fi
}

# ---- fixtures ------------------------------------------------------------------

# new_home creates a POSTERN_HOME with the launcher in bin/, as install.sh lays it
# out. data/run/launcher is not created: the launcher has to.
new_home() {
  home=$(mktemp -d "$tmproot/home.XXXXXX")
  state=$home/data/run/launcher
  mkdir -p "$home/bin" "$home/ctl"
  cp "$launcher_src" "$home/bin/launcher.sh"
  chmod 755 "$home/bin/launcher.sh"
}

# mkbin NAME creates bin/NAME, a fake node binary.
mkbin() {
  cat > "$home/bin/$1" <<'EOF'
#!/bin/sh
home=$POSTERN_HOME
marker=$home/data/run/launcher/healthy
if [ -e "$marker" ]; then seen=yes; else seen=no; fi
printf '@NAME@ ppid=%s args=%s healthy_at_start=%s umask=%s\n' \
  "$PPID" "$*" "$seen" "$(umask)" >> "$home/trace"
mode=crash
if [ -f "$home/ctl/@NAME@" ]; then mode=$(cat "$home/ctl/@NAME@"); fi
case $mode in
  healthy) : > "$marker"; exit 0 ;;
  healthy-crash) : > "$marker"; exit 1 ;;
  exit[0-9]*) exit "${mode#exit}" ;;
  *) exit 1 ;;
esac
EOF
  sed "s/@NAME@/$1/g" "$home/bin/$1" > "$home/bin/$1.new"
  mv "$home/bin/$1.new" "$home/bin/$1"
  chmod 755 "$home/bin/$1"
}

# setmode NAME MODE selects what the fake NAME does the next time it starts.
setmode() {
  printf '%s\n' "$2" > "$home/ctl/$1"
}

# link NAME TARGET makes bin/NAME a symlink to the bare file name TARGET.
link() {
  rm -f "$home/bin/$1"
  ln -s "$2" "$home/bin/$1"
}

# launch ARGS... runs the launcher the way the container does. It must not run in
# a command substitution: the fakes compare their parent pid with this shell's.
launch() {
  if [ -n "${POSTERN_TEST_SHELL:-}" ]; then
    POSTERN_HOME=$home "$POSTERN_TEST_SHELL" "$home/bin/launcher.sh" "$@" 2> "$home/stderr"
  else
    POSTERN_HOME=$home "$home/bin/launcher.sh" "$@" 2> "$home/stderr"
  fi
  rc=$?
}

# trace_count NAME: how many times the fake NAME has started
trace_count() {
  if [ -f "$home/trace" ]; then
    grep -c "^$1 " "$home/trace" || true
  else
    echo 0
  fi
}

counter() {
  cat "$state/crashes" 2> /dev/null
}

target() {
  readlink "$home/bin/$1" 2> /dev/null
}

stderr_text() {
  cat "$home/stderr"
}

# ---- tests ---------------------------------------------------------------------

test_passes_arguments_and_exit_status() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  setmode postern-node-v1 exit42
  launch agent --flag value
  eq "the exit status of the binary is the exit status of the launcher" 42 "$rc"
  has "the binary gets the arguments" "$(cat "$home/trace")" "args=agent --flag value"
}

test_replaces_itself_with_the_binary() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  launch agent
  ppid=$(sed -n 's/.*ppid=\([0-9]*\).*/\1/p' "$home/trace")
  eq "exec: no shell is left between whoever started the launcher and the binary" "$$" "$ppid"
}

test_creates_its_state_directory() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  launch agent
  eq "the state directory is root only" "drwx------" "$(ls -ld "$state" | cut -c1-10)"
  eq "the first start counts no failure" 0 "$(counter)"
  if [ -f "$state/started" ]; then ok "the start is recorded"; else bad "the start is recorded"; fi
  absent "the healthy marker is cleared before the start" "$state/healthy"
}

test_clears_a_stale_healthy_marker() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  mkdir -p "$state"
  : > "$state/healthy"
  launch agent
  has "the binary does not see the marker of an earlier process" "$(cat "$home/trace")" "healthy_at_start=no"
}

test_does_not_change_the_umask() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  umask 022
  launch agent
  eq "the binary runs with the umask the launcher got" "umask=$(umask)" "$(sed -n 's/.*\(umask=.*\)$/\1/p' "$home/trace")"
}

test_rolls_back_after_three_unhealthy_starts() {
  new_home
  mkbin postern-node-v1
  mkbin postern-node-v2
  setmode postern-node-v1 healthy
  setmode postern-node-v2 crash
  link current postern-node-v2
  link previous postern-node-v1

  launch agent
  launch agent
  launch agent
  eq "three failing starts ran the current version" 3 "$(trace_count postern-node-v2)"
  eq "no rollback yet" postern-node-v2 "$(target current)"
  eq "two failures were counted when the third start was judged" 2 "$(counter)"

  launch agent
  eq "the fourth start ran the previous version" 1 "$(trace_count postern-node-v1)"
  eq "the failing version was not started a fourth time" 3 "$(trace_count postern-node-v2)"
  eq "current now points to the old version, by its bare name" postern-node-v1 "$(target current)"
  absent "previous is gone, so the failed version is never picked again" "$home/bin/previous"
  eq "the counter was reset" 0 "$(counter)"
  has "the launcher says what it did" "$(stderr_text)" "rolled back"
  has "the log names both versions" "$(stderr_text)" "postern-node-v2"
  has "the rollback is recorded for the agent" "$(cat "$state/rollback")" "postern-node-v2 postern-node-v1"
}

test_no_rollback_when_the_start_was_healthy() {
  new_home
  mkbin postern-node-v1
  mkbin postern-node-v2
  setmode postern-node-v2 healthy-crash
  link current postern-node-v2
  link previous postern-node-v1

  i=0
  while [ "$i" -lt 6 ]; do
    launch agent
    i=$((i + 1))
  done
  eq "every start ran the current version" 6 "$(trace_count postern-node-v2)"
  eq "the previous version never ran" 0 "$(trace_count postern-node-v1)"
  eq "current is unchanged" postern-node-v2 "$(target current)"
  eq "previous is unchanged" postern-node-v1 "$(target previous)"
  eq "no failures counted" 0 "$(counter)"
}

test_no_rollback_without_a_previous_version() {
  new_home
  mkbin postern-node-v2
  setmode postern-node-v2 crash
  link current postern-node-v2

  i=0
  while [ "$i" -lt 6 ]; do
    launch agent
    i=$((i + 1))
  done
  eq "every start ran the current version" 6 "$(trace_count postern-node-v2)"
  eq "current is unchanged" postern-node-v2 "$(target current)"
  eq "the failures are still counted" 5 "$(counter)"
  has "the launcher says why it does not roll back" "$(stderr_text)" "no bin/previous"
  absent "nothing is recorded as a rollback" "$state/rollback"
}

test_counter_is_reset_by_a_healthy_start() {
  new_home
  mkbin postern-node-v1
  mkbin postern-node-v2
  setmode postern-node-v1 healthy
  link current postern-node-v2
  link previous postern-node-v1

  setmode postern-node-v2 crash
  launch agent
  launch agent
  setmode postern-node-v2 healthy
  launch agent
  setmode postern-node-v2 crash
  launch agent
  launch agent
  launch agent
  eq "failures before and after the healthy start never add up" 2 "$(counter)"
  eq "so there was no rollback" postern-node-v2 "$(target current)"
  eq "and the previous version never ran" 0 "$(trace_count postern-node-v1)"

  launch agent
  eq "three failures in a row after the healthy start roll back" postern-node-v1 "$(target current)"
  eq "and run the previous version" 1 "$(trace_count postern-node-v1)"
}

test_counter_starts_over_when_current_changes() {
  new_home
  mkbin postern-node-v2
  mkbin postern-node-v3
  setmode postern-node-v2 crash
  setmode postern-node-v3 crash
  link current postern-node-v2

  launch agent
  launch agent
  launch agent
  eq "v2 has failed twice by the time its third start is judged" 2 "$(counter)"

  # An update while v2 is crash-looping: v3 becomes current, v2 previous.
  link previous postern-node-v2
  link current postern-node-v3
  launch agent
  eq "the failures of v2 are not held against v3" 0 "$(counter)"
  eq "v3 is not rolled back after its first start" postern-node-v3 "$(target current)"
  eq "v3 ran" 1 "$(trace_count postern-node-v3)"
  launch agent
  launch agent
  eq "v3 gets its own two failures counted" 2 "$(counter)"
  eq "and is still current" postern-node-v3 "$(target current)"
  launch agent
  eq "after three failures of its own v3 is rolled back" postern-node-v2 "$(target current)"
}

test_does_not_roll_back_to_a_missing_previous() {
  new_home
  mkbin postern-node-v2
  setmode postern-node-v2 crash
  link current postern-node-v2
  link previous postern-node-v0-gone

  i=0
  while [ "$i" -lt 5 ]; do
    launch agent
    i=$((i + 1))
  done
  eq "current is unchanged" postern-node-v2 "$(target current)"
  eq "every start ran the current version" 5 "$(trace_count postern-node-v2)"
  has "the launcher says the previous version is unusable" "$(stderr_text)" "not an executable file"
  absent "nothing is recorded as a rollback" "$state/rollback"
}

test_recovers_from_a_missing_current_binary() {
  new_home
  mkbin postern-node-v1
  setmode postern-node-v1 healthy
  link current postern-node-v2 # a half-done update: the file is not there
  link previous postern-node-v1

  launch agent
  eq "a missing binary is reported as command not found" 127 "$rc"
  has "and said so" "$(stderr_text)" "missing or not executable"
  launch agent
  launch agent
  eq "nothing ran meanwhile" 0 "$(trace_count postern-node-v1)"
  launch agent
  eq "the fourth start runs the previous version" 1 "$(trace_count postern-node-v1)"
  eq "current points to it" postern-node-v1 "$(target current)"
}

test_recovers_from_a_binary_that_is_not_executable() {
  new_home
  mkbin postern-node-v1
  mkbin postern-node-v2
  setmode postern-node-v1 healthy
  chmod 644 "$home/bin/postern-node-v2"
  link current postern-node-v2
  link previous postern-node-v1

  launch agent
  eq "a binary without the execute bit is reported as command not found" 127 "$rc"
  launch agent
  launch agent
  launch agent
  eq "the fourth start runs the previous version" 1 "$(trace_count postern-node-v1)"
  eq "current points to it" postern-node-v1 "$(target current)"
}

test_ignores_a_corrupt_counter() {
  new_home
  mkbin postern-node-v2
  setmode postern-node-v2 crash
  link current postern-node-v2
  mkdir -p "$state"
  printf '1700000000 postern-node-v2\n' > "$state/started"

  printf 'garbage\n' > "$state/crashes"
  launch agent
  eq "a counter that is not a number counts as zero" 1 "$(counter)"

  printf '08\n' > "$state/crashes"
  launch agent
  eq "a counter with a leading zero is not read as octal" 9 "$(counter)"

  : > "$state/crashes"
  launch agent
  eq "an empty counter counts as zero" 1 "$(counter)"

  printf '5\n' > "$state/crashes"
  : > "$state/started"
  launch agent
  eq "a start record without a binary name is no evidence against this binary" 0 "$(counter)"

  eq "the binary started every time" 4 "$(trace_count postern-node-v2)"
}

test_still_starts_when_it_cannot_keep_its_books() {
  new_home
  mkbin postern-node-v1
  link current postern-node-v1
  setmode postern-node-v1 exit7
  mkdir -p "$home/data/run"
  : > "$home/data/run/launcher" # a file where the state directory should be
  launch agent
  eq "the binary ran and its status came through" 7 "$rc"
  eq "the binary ran once" 1 "$(trace_count postern-node-v1)"
  has "the launcher warned" "$(stderr_text)" "warning"
}

# ---- run -----------------------------------------------------------------------

if [ ! -f "$launcher_src" ]; then
  echo "launcher_test.sh: $launcher_src does not exist" >&2
  exit 1
fi

for t in \
  test_passes_arguments_and_exit_status \
  test_replaces_itself_with_the_binary \
  test_creates_its_state_directory \
  test_clears_a_stale_healthy_marker \
  test_does_not_change_the_umask \
  test_rolls_back_after_three_unhealthy_starts \
  test_no_rollback_when_the_start_was_healthy \
  test_no_rollback_without_a_previous_version \
  test_counter_is_reset_by_a_healthy_start \
  test_counter_starts_over_when_current_changes \
  test_does_not_roll_back_to_a_missing_previous \
  test_recovers_from_a_missing_current_binary \
  test_recovers_from_a_binary_that_is_not_executable \
  test_ignores_a_corrupt_counter \
  test_still_starts_when_it_cannot_keep_its_books; do
  echo "$t"
  "$t"
done

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
