#!/bin/sh
# Tests for launcher.sh. POSIX sh, so the same file runs under dash and under
# the busybox ash of the image.
#
# From the repository root:
#
#   bash scripts/wsl 'sh deploy/panel/launcher_test.sh'
#
# Inside the runner image, which proves that launcher.sh works with busybox:
#
#   docker run --rm -v "$PWD":/src:ro \
#     alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
#     sh /src/deploy/panel/launcher_test.sh
#
# POSTERN_TEST_SHELL=<shell> runs the launcher as "<shell> launcher.sh" instead
# of through its #! line, for example POSTERN_TEST_SHELL=bash.
#
# Every test gets a fresh POSTERN_DATA in a temporary directory, with fake panel
# binaries whose behaviour a control file selects, and a fake binary of the image
# (POSTERN_PANEL_BIN):
#
#   healthy        write the healthy marker and exit 0
#   healthy-crash  write the healthy marker and exit 1 (dies after it was up)
#   restart        write the healthy marker and exit 75 (installed an update)
#   crash          exit 1 without a marker (the default)
#   exit<N>        exit with status N, no marker
#
# A fake writes the marker where the launcher says, in POSTERN_HEALTHY_FILE, as
# the real panel does. Each fake appends one line to $POSTERN_DATA/trace when it
# starts.

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

# new_home creates a POSTERN_DATA with nothing in it but the places of the tests:
# an empty data volume, as the image finds it at the first start. bin/ and
# run/launcher are not created: the launcher has to, when it needs them.
new_home() {
  home=$(mktemp -d "$tmproot/home.XXXXXX")
  state=$home/run/launcher
  image=$home/image/postern-panel
  mkdir -p "$home/ctl" "$home/image" "$home/launcher"
  cp "$launcher_src" "$home/launcher/launcher.sh"
  chmod 755 "$home/launcher/launcher.sh"
  fake "$image" image
}

# need_bin makes the bin directory of the volume, where the versions are put.
need_bin() {
  mkdir -p "$home/bin"
}

# fake PATH NAME creates a fake panel binary that calls itself NAME.
fake() {
  cat > "$1" <<'EOF'
#!/bin/sh
home=$POSTERN_DATA
marker=${POSTERN_HEALTHY_FILE:-}
if [ -n "$marker" ] && [ -e "$marker" ]; then seen=yes; else seen=no; fi
printf '@NAME@ ppid=%s args=%s healthy_at_start=%s umask=%s marker=%s data=%s\n' \
  "$PPID" "$*" "$seen" "$(umask)" "$marker" "$home" >> "$home/trace"
mode=crash
if [ -f "$home/ctl/@NAME@" ]; then mode=$(cat "$home/ctl/@NAME@"); fi
case $mode in
  healthy) [ -z "$marker" ] || : > "$marker"; exit 0 ;;
  healthy-crash) [ -z "$marker" ] || : > "$marker"; exit 1 ;;
  restart) [ -z "$marker" ] || : > "$marker"; exit 75 ;;
  exit[0-9]*) exit "${mode#exit}" ;;
  *) exit 1 ;;
esac
EOF
  sed "s/@NAME@/$2/g" "$1" > "$1.new"
  mv "$1.new" "$1"
  chmod 755 "$1"
}

# mkbin NAME creates bin/NAME, a fake panel binary.
mkbin() {
  need_bin
  fake "$home/bin/$1" "$1"
}

# setmode NAME MODE selects what the fake NAME does the next time it starts.
setmode() {
  printf '%s\n' "$2" > "$home/ctl/$1"
}

# link NAME TARGET makes bin/NAME a symlink to TARGET: a bare file name, or a path.
link() {
  need_bin
  rm -f "$home/bin/$1"
  ln -s "$2" "$home/bin/$1"
}

# launch ARGS... runs the launcher the way the container does. It must not run in
# a command substitution: the fakes compare their parent pid with this shell's.
launch() {
  if [ -n "${POSTERN_TEST_SHELL:-}" ]; then
    POSTERN_DATA=$home POSTERN_PANEL_BIN=$image "$POSTERN_TEST_SHELL" "$home/launcher/launcher.sh" "$@" 2> "$home/stderr"
  else
    POSTERN_DATA=$home POSTERN_PANEL_BIN=$image "$home/launcher/launcher.sh" "$@" 2> "$home/stderr"
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
  mkbin postern-panel-v1
  link current postern-panel-v1
  setmode postern-panel-v1 exit42
  launch serve --flag value
  eq "the exit status of the binary is the exit status of the launcher" 42 "$rc"
  has "the binary gets the arguments" "$(cat "$home/trace")" "args=serve --flag value"
}

test_replaces_itself_with_the_binary() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  launch serve
  ppid=$(sed -n 's/.*ppid=\([0-9]*\).*/\1/p' "$home/trace")
  eq "exec: no shell is left between whoever started the launcher and the binary" "$$" "$ppid"
}

test_creates_its_state_directory() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  launch serve
  eq "the state directory is private to the user" "drwx------" "$(stat -c %A "$state")"
  eq "the first start counts no failure" 0 "$(counter)"
  if [ -f "$state/started" ]; then ok "the start is recorded"; else bad "the start is recorded"; fi
  absent "the healthy marker is cleared before the start" "$state/healthy"
}

test_hands_the_marker_path_to_the_binary() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  setmode postern-panel-v1 healthy
  launch serve
  has "the binary is told where to write the marker" "$(cat "$home/trace")" "marker=$state/healthy"
  has "the binary has the data directory too" "$(cat "$home/trace")" "data=$home"
  if [ -f "$state/healthy" ]; then ok "and writes it there"; else bad "and writes it there"; fi
}

test_clears_a_stale_healthy_marker() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  mkdir -p "$state"
  : > "$state/healthy"
  launch serve
  has "the binary does not see the marker of an earlier process" "$(cat "$home/trace")" "healthy_at_start=no"
}

test_does_not_change_the_umask() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  umask 022
  launch serve
  eq "the binary runs with the umask the launcher got" "umask=$(umask)" "$(sed -n 's/.*\(umask=[0-9]*\).*/\1/p' "$home/trace")"
}

test_rolls_back_after_three_unhealthy_starts() {
  new_home
  mkbin postern-panel-v1
  mkbin postern-panel-v2
  setmode postern-panel-v1 healthy
  setmode postern-panel-v2 crash
  link current postern-panel-v2
  link previous postern-panel-v1

  launch serve
  launch serve
  launch serve
  eq "three failing starts ran the current version" 3 "$(trace_count postern-panel-v2)"
  eq "no rollback yet" postern-panel-v2 "$(target current)"
  eq "two failures were counted when the third start was judged" 2 "$(counter)"

  launch serve
  eq "the fourth start ran the previous version" 1 "$(trace_count postern-panel-v1)"
  eq "the failing version was not started a fourth time" 3 "$(trace_count postern-panel-v2)"
  eq "current now points to the old version, by its bare name" postern-panel-v1 "$(target current)"
  absent "previous is gone, so the failed version is never picked again" "$home/bin/previous"
  eq "the counter was reset" 0 "$(counter)"
  has "the launcher says what it did" "$(stderr_text)" "rolled back"
  has "the log names both versions" "$(stderr_text)" "postern-panel-v2"
  has "the rollback is recorded" "$(cat "$state/rollback")" "postern-panel-v2 postern-panel-v1"
}

test_no_rollback_when_the_start_was_healthy() {
  new_home
  mkbin postern-panel-v1
  mkbin postern-panel-v2
  setmode postern-panel-v2 healthy-crash
  link current postern-panel-v2
  link previous postern-panel-v1

  i=0
  while [ "$i" -lt 6 ]; do
    launch serve
    i=$((i + 1))
  done
  eq "every start ran the current version" 6 "$(trace_count postern-panel-v2)"
  eq "the previous version never ran" 0 "$(trace_count postern-panel-v1)"
  eq "current is unchanged" postern-panel-v2 "$(target current)"
  eq "previous is unchanged" postern-panel-v1 "$(target previous)"
  eq "no failures counted" 0 "$(counter)"
}

test_no_rollback_without_a_previous_version() {
  new_home
  mkbin postern-panel-v2
  setmode postern-panel-v2 crash
  link current postern-panel-v2

  i=0
  while [ "$i" -lt 6 ]; do
    launch serve
    i=$((i + 1))
  done
  eq "every start ran the current version" 6 "$(trace_count postern-panel-v2)"
  eq "current is unchanged" postern-panel-v2 "$(target current)"
  eq "the failures are still counted" 5 "$(counter)"
  has "the launcher says why it does not roll back" "$(stderr_text)" "no bin/previous"
  absent "nothing is recorded as a rollback" "$state/rollback"
}

test_counter_is_reset_by_a_healthy_start() {
  new_home
  mkbin postern-panel-v1
  mkbin postern-panel-v2
  setmode postern-panel-v1 healthy
  link current postern-panel-v2
  link previous postern-panel-v1

  setmode postern-panel-v2 crash
  launch serve
  launch serve
  setmode postern-panel-v2 healthy
  launch serve
  setmode postern-panel-v2 crash
  launch serve
  launch serve
  launch serve
  eq "failures before and after the healthy start never add up" 2 "$(counter)"
  eq "so there was no rollback" postern-panel-v2 "$(target current)"
  eq "and the previous version never ran" 0 "$(trace_count postern-panel-v1)"

  launch serve
  eq "three failures in a row after the healthy start roll back" postern-panel-v1 "$(target current)"
  eq "and run the previous version" 1 "$(trace_count postern-panel-v1)"
}

test_counter_starts_over_when_current_changes() {
  new_home
  mkbin postern-panel-v2
  mkbin postern-panel-v3
  setmode postern-panel-v2 crash
  setmode postern-panel-v3 crash
  link current postern-panel-v2

  launch serve
  launch serve
  launch serve
  eq "v2 has failed twice by the time its third start is judged" 2 "$(counter)"

  # An update while v2 is crash-looping: v3 becomes current, v2 previous.
  link previous postern-panel-v2
  link current postern-panel-v3
  launch serve
  eq "the failures of v2 are not held against v3" 0 "$(counter)"
  eq "v3 is not rolled back after its first start" postern-panel-v3 "$(target current)"
  eq "v3 ran" 1 "$(trace_count postern-panel-v3)"
  launch serve
  launch serve
  eq "v3 gets its own two failures counted" 2 "$(counter)"
  eq "and is still current" postern-panel-v3 "$(target current)"
  launch serve
  eq "after three failures of its own v3 is rolled back" postern-panel-v2 "$(target current)"
}

test_does_not_roll_back_to_a_missing_previous() {
  new_home
  mkbin postern-panel-v2
  setmode postern-panel-v2 crash
  link current postern-panel-v2
  link previous postern-panel-v0-gone

  i=0
  while [ "$i" -lt 5 ]; do
    launch serve
    i=$((i + 1))
  done
  eq "current is unchanged" postern-panel-v2 "$(target current)"
  eq "every start ran the current version" 5 "$(trace_count postern-panel-v2)"
  has "the launcher says the previous version is unusable" "$(stderr_text)" "not an executable file"
  absent "nothing is recorded as a rollback" "$state/rollback"
}

test_recovers_from_a_missing_current_binary() {
  new_home
  mkbin postern-panel-v1
  setmode postern-panel-v1 healthy
  link current postern-panel-v2 # a half-done update: the file is not there
  link previous postern-panel-v1

  launch serve
  eq "a missing binary is reported as command not found" 127 "$rc"
  has "and said so" "$(stderr_text)" "missing or not executable"
  launch serve
  launch serve
  eq "nothing ran meanwhile" 0 "$(trace_count postern-panel-v1)"
  launch serve
  eq "the fourth start runs the previous version" 1 "$(trace_count postern-panel-v1)"
  eq "current points to it" postern-panel-v1 "$(target current)"
}

test_recovers_from_a_binary_that_is_not_executable() {
  new_home
  mkbin postern-panel-v1
  mkbin postern-panel-v2
  setmode postern-panel-v1 healthy
  chmod 644 "$home/bin/postern-panel-v2"
  link current postern-panel-v2
  link previous postern-panel-v1

  launch serve
  eq "a binary without the execute bit is reported as command not found" 127 "$rc"
  launch serve
  launch serve
  launch serve
  eq "the fourth start runs the previous version" 1 "$(trace_count postern-panel-v1)"
  eq "current points to it" postern-panel-v1 "$(target current)"
}

test_ignores_a_corrupt_counter() {
  new_home
  mkbin postern-panel-v2
  setmode postern-panel-v2 crash
  link current postern-panel-v2
  mkdir -p "$state"
  printf '1700000000 postern-panel-v2\n' > "$state/started"

  printf 'garbage\n' > "$state/crashes"
  launch serve
  eq "a counter that is not a number counts as zero" 1 "$(counter)"

  printf '08\n' > "$state/crashes"
  launch serve
  eq "a counter with a leading zero is not read as octal" 9 "$(counter)"

  : > "$state/crashes"
  launch serve
  eq "an empty counter counts as zero" 1 "$(counter)"

  printf '5\n' > "$state/crashes"
  : > "$state/started"
  launch serve
  eq "a start record without a binary name is no evidence against this binary" 0 "$(counter)"

  eq "the binary started every time" 4 "$(trace_count postern-panel-v2)"
}

test_still_starts_when_it_cannot_keep_its_books() {
  new_home
  mkbin postern-panel-v1
  link current postern-panel-v1
  setmode postern-panel-v1 exit7
  : > "$home/run" # a file where the run directory should be
  launch serve
  eq "the binary ran and its status came through" 7 "$rc"
  eq "the binary ran once" 1 "$(trace_count postern-panel-v1)"
  has "the launcher warned" "$(stderr_text)" "warning"
}

# The differences from the launcher of the node.

test_runs_the_image_binary_without_a_current() {
  new_home
  setmode image exit5
  launch serve --flag value
  eq "the exit status of the binary of the image comes through" 5 "$rc"
  has "the binary of the image gets the arguments" "$(cat "$home/trace")" "image ppid="
  has "and the arguments" "$(cat "$home/trace")" "args=serve --flag value"
  has "and the data directory" "$(cat "$home/trace")" "data=$home"
}

test_the_image_binary_is_run_by_exec_and_gets_a_marker() {
  new_home
  setmode image healthy
  launch serve
  ppid=$(sed -n 's/.*ppid=\([0-9]*\).*/\1/p' "$home/trace")
  eq "exec: the binary of the image is a child of whoever started the launcher" "$$" "$ppid"
  absent "no bin directory is made" "$home/bin"
  # The marker tells the panel that it runs under its launcher, which is what
  # offers the first self-update (bug B1 of the real-server pass).
  has "the binary of the image is told where to write the marker" "$(cat "$home/trace")" "marker=$state/healthy"
  if [ -f "$state/healthy" ]; then ok "and writes it there"; else bad "and writes it there"; fi
  has "the start is recorded against the binary of the image, by its path" "$(cat "$state/started" 2> /dev/null)" " $image"
  eq "the state directory is private to the user" "drwx------" "$(stat -c %A "$state" 2> /dev/null)"
  launch serve
  has "the next start clears the marker of the one before" "$(sed -n 2p "$home/trace")" "healthy_at_start=no"
  eq "a healthy image start counts no failure" 0 "$(counter)"
}

test_an_unhealthy_image_binary_is_counted_and_never_rolled_back() {
  new_home
  setmode image crash
  i=0
  while [ "$i" -lt 5 ]; do
    launch serve
    i=$((i + 1))
  done
  eq "every start ran the binary of the image" 5 "$(trace_count image)"
  eq "its failures are counted" 4 "$(counter)"
  has "the launcher says there is nothing to roll back to" "$(stderr_text)" "nothing to roll back to"
  absent "no bin directory is made" "$home/bin"
  absent "nothing is recorded as a rollback" "$state/rollback"
}

# The first update from the image: the image ran (and kept its books), then the
# updater points current at the new version and previous at the image by its path.
test_the_first_update_from_the_image_keeps_the_rollback_contract() {
  new_home
  setmode image crash
  launch serve
  launch serve
  eq "the image failed once by the time its second start was judged" 1 "$(counter)"
  mkbin postern-panel-v2
  setmode postern-panel-v2 crash
  link current postern-panel-v2
  link previous "$image"
  launch serve
  eq "the failures of the image are not held against the update" 0 "$(counter)"
  eq "the update ran" 1 "$(trace_count postern-panel-v2)"
  has "and was told where to write the marker" "$(grep '^postern-panel-v2 ' "$home/trace")" "marker=$state/healthy"
  setmode image healthy
  launch serve
  launch serve
  launch serve
  eq "three unhealthy starts of the update roll back to the image" "$image" "$(target current)"
  eq "the image ran again" 3 "$(trace_count image)"
}

test_current_wins_over_the_image() {
  new_home
  mkbin postern-panel-v1
  setmode postern-panel-v1 healthy
  link current postern-panel-v1
  launch serve
  eq "bin/current ran" 1 "$(trace_count postern-panel-v1)"
  eq "the image did not" 0 "$(trace_count image)"
}

test_a_dangling_current_is_not_the_image() {
  new_home
  link current postern-panel-gone
  launch serve
  eq "a bin/current that points nowhere is an error, not a reason to run the image" 127 "$rc"
  eq "the image did not run" 0 "$(trace_count image)"
  has "and the launcher says so" "$(stderr_text)" "missing or not executable"
}

test_removing_current_goes_back_to_the_image() {
  new_home
  mkbin postern-panel-v1
  setmode postern-panel-v1 healthy
  link current postern-panel-v1
  launch serve
  rm -f "$home/bin/current"
  setmode image healthy
  launch serve
  eq "without bin/current the image runs again" 1 "$(trace_count image)"
  eq "and the version in the volume does not" 1 "$(trace_count postern-panel-v1)"
}

# The way back to the image: the updater makes bin/previous a link to the binary of
# the image, with its path.
test_rolls_back_to_the_binary_of_the_image() {
  new_home
  mkbin postern-panel-v2
  setmode postern-panel-v2 crash
  setmode image healthy
  link current postern-panel-v2
  link previous "$image"

  launch serve
  launch serve
  launch serve
  eq "three failing starts ran the current version" 3 "$(trace_count postern-panel-v2)"
  launch serve
  eq "the fourth start ran the binary of the image" 1 "$(trace_count image)"
  eq "current points to it, by its path" "$image" "$(target current)"
  has "the rollback is recorded" "$(cat "$state/rollback")" "postern-panel-v2 $image"
  launch serve
  eq "and it goes on running it" 2 "$(trace_count image)"
  eq "healthy, so no counter" 0 "$(counter)"
}

# A panel that installed an update writes its marker when it serves and exits
# with 75; Docker starts the launcher again, which runs the new bin/current and
# counts no crash for either start.
test_an_update_exit_75_is_not_a_crash() {
  new_home
  mkbin postern-panel-v1
  mkbin postern-panel-v2
  setmode postern-panel-v1 restart
  setmode postern-panel-v2 healthy
  link current postern-panel-v1

  launch serve
  eq "the panel exits with 75" 75 "$rc"
  # What the update does: v1 becomes previous, v2 current.
  link previous postern-panel-v1
  link current postern-panel-v2
  launch serve
  eq "the next start runs the new version" 1 "$(trace_count postern-panel-v2)"
  eq "the exit with 75 was not counted as a crash" 0 "$(counter)"
  eq "no rollback" postern-panel-v2 "$(target current)"
  absent "no rollback record" "$state/rollback"

  # A version that exits with 75 again and again (each time healthy) is
  # restarted without ever being rolled back.
  setmode postern-panel-v2 restart
  launch serve
  launch serve
  launch serve
  launch serve
  eq "restarted each time" 5 "$(trace_count postern-panel-v2)"
  eq "never counted" 0 "$(counter)"
  eq "never rolled back" postern-panel-v2 "$(target current)"
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
  test_hands_the_marker_path_to_the_binary \
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
  test_still_starts_when_it_cannot_keep_its_books \
  test_runs_the_image_binary_without_a_current \
  test_the_image_binary_is_run_by_exec_and_gets_a_marker   test_an_unhealthy_image_binary_is_counted_and_never_rolled_back   test_the_first_update_from_the_image_keeps_the_rollback_contract \
  test_current_wins_over_the_image \
  test_a_dangling_current_is_not_the_image \
  test_removing_current_goes_back_to_the_image \
  test_rolls_back_to_the_binary_of_the_image \
  test_an_update_exit_75_is_not_a_crash; do
  echo "$t"
  "$t"
done

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
