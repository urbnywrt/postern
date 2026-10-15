#!/bin/sh
# Tests for entrypoint.sh. POSIX sh. They have to run as root, since what they
# check is that root changes the owner of directories, and that it gives root up.
# Without root they say so and succeed.
#
# From the repository root, in the image that the script runs in, which proves that
# it works with busybox:
#
#   docker run --rm -v "$PWD":/src:ro \
#     alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
#     sh /src/deploy/panel/entrypoint_test.sh
#
# The script is run with a fake su-exec (it records its arguments and runs the
# command as the user that it is, which is root), a chown that records its
# arguments and then does the work, a fake launcher and a fake panel binary. The
# owners are the real ones: the tests look at them with stat.
#
# One case plants a link to /etc, to see that root does not follow it. If the
# entrypoint were wrong, that would change the owner of the real /etc, so the
# case is tried only inside a container (/.dockerenv exists), where /etc is the
# container's own; anywhere else it is skipped, with a note.

set -u

here=$(cd "$(dirname "$0")" && pwd) || exit 1
entrypoint_src=$here/entrypoint.sh

if [ "$(id -u)" != 0 ]; then
  echo "entrypoint_test.sh: skipped, it has to run as root (see the top of the file)"
  exit 0
fi

tmproot=$(mktemp -d "${TMPDIR:-/tmp}/postern-entrypoint-test.XXXXXX") || exit 1
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

eq() {
  if [ "$2" = "$3" ]; then
    ok "$1"
  else
    bad "$1" "expected [$2], got [$3]"
  fi
}

has() {
  case $2 in
    *"$3"*) ok "$1" ;;
    *) bad "$1" "no [$3] in [$2]" ;;
  esac
}

lacks() {
  case $2 in
    *"$3"*) bad "$1" "[$3] is in [$2]" ;;
    *) ok "$1" ;;
  esac
}

# skip says that a check was not made, and why. It is not a check: it does not
# count as one, and does not fail.
skip() {
  printf '  skip %s\n' "$1"
}

# ---- fixtures ------------------------------------------------------------------

# new_env makes a world for one test: the data and key directories, the shims,
# and the fake launcher and panel. Nothing is owned by the panel user yet.
new_env() {
  world=$(mktemp -d "$tmproot/world.XXXXXX")
  data=$world/data
  keys=$world/keys
  calls=$world/calls
  : > "$calls"
  mkdir -p "$data" "$keys" "$world/shims"
  chown 0:0 "$data" "$keys"

  cat > "$world/shims/su-exec" <<'EOF'
#!/bin/sh
printf 'su-exec %s\n' "$*" >> "$WORLD/calls"
shift
exec "$@"
EOF
  cat > "$world/shims/chown" <<'EOF'
#!/bin/sh
printf 'chown %s\n' "$*" >> "$WORLD/calls"
if [ -n "${CHOWN_FAILS:-}" ]; then exit 1; fi
exec /bin/chown "$@"
EOF
  cat > "$world/launcher" <<'EOF'
#!/bin/sh
printf 'launcher %s\n' "$*" >> "$WORLD/calls"
exit "${LAUNCHER_EXIT:-0}"
EOF
  cat > "$world/panel" <<'EOF'
#!/bin/sh
printf 'panel %s\n' "$*" >> "$WORLD/calls"
exit "${PANEL_EXIT:-0}"
EOF
  chmod 755 "$world/shims/su-exec" "$world/shims/chown" "$world/launcher" "$world/panel"
}

# enter ARGS... runs the entrypoint in the world, as root, with the shims first in
# PATH. stderr goes to $world/stderr.
enter() {
  WORLD=$world POSTERN_DATA=$data POSTERN_KEYS=$keys POSTERN_LAUNCHER=$world/launcher POSTERN_PANEL_BIN=$world/panel \
    LAUNCHER_EXIT=${LAUNCHER_EXIT:-0} PANEL_EXIT=${PANEL_EXIT:-0} CHOWN_FAILS=${CHOWN_FAILS:-} \
    PATH="$world/shims:$PATH" sh "$entrypoint_src" "$@" 2> "$world/stderr"
  rc=$?
}

owner() {
  stat -c '%u:%g' "$1"
}

calls_text() {
  cat "$calls"
}

stderr_text() {
  cat "$world/stderr"
}

chown_calls() {
  grep -c '^chown ' "$calls" || true
}

# ---- tests ---------------------------------------------------------------------

test_takes_the_volumes_for_the_panel_user() {
  new_env
  echo secret > "$keys/master.key"
  chown 0:0 "$keys/master.key"
  enter serve
  eq "the data directory belongs to the panel user" 65532:65532 "$(owner "$data")"
  eq "the key directory belongs to the panel user" 65532:65532 "$(owner "$keys")"
  eq "so does the key in it" 65532:65532 "$(owner "$keys/master.key")"
  has "it says what it did" "$(stderr_text)" "changing the owner of $data"
  has "for both" "$(stderr_text)" "changing the owner of $keys"
}

test_drops_root_before_the_launcher() {
  new_env
  enter serve --some-flag
  eq "serve goes through the launcher, as the panel user" "su-exec 65532:65532 $world/launcher serve --some-flag" \
    "$(grep -v '^chown ' "$calls" | sed -n 1p)"
  eq "and the launcher is what runs, with the arguments" "launcher serve --some-flag" \
    "$(grep -v '^chown ' "$calls" | sed -n 2p)"
  eq "the chown came first" chown "$(sed -n 1p "$calls" | cut -d' ' -f1)"
  eq "nothing else ran" 2 "$(grep -vc '^chown ' "$calls")"
}

test_other_commands_skip_the_launcher() {
  new_env
  enter version
  eq "version runs the panel binary, as the panel user" "su-exec 65532:65532 $world/panel version" \
    "$(grep -v '^chown ' "$calls" | sed -n 1p)"
  eq "and the binary runs" "panel version" "$(grep -v '^chown ' "$calls" | sed -n 2p)"
  lacks "without the launcher" "$(calls_text)" "launcher"
  : > "$calls"
  enter
  eq "no arguments is the binary with no arguments" "su-exec 65532:65532 $world/panel" "$(sed -n 1p "$calls")"
}

test_passes_the_exit_status() {
  new_env
  LAUNCHER_EXIT=42 enter serve
  eq "the exit status of the launcher is the status of the container" 42 "$rc"
  PANEL_EXIT=3 enter version
  eq "and that of the binary" 3 "$rc"
}

test_does_not_walk_a_volume_that_is_right() {
  new_env
  chown 65532:65532 "$data" "$keys"
  mkdir "$data/sub"
  : > "$data/sub/file"
  chown -R 65532:65532 "$data"
  enter serve
  eq "no chown was run" 0 "$(chown_calls)"
  eq "and nothing was said" "" "$(stderr_text)"
  eq "the command still ran as the panel user" 1 "$(grep -c '^su-exec 65532:65532 ' "$calls")"
}

test_takes_only_the_volume_that_needs_it() {
  new_env
  chown 65532:65532 "$data"
  enter serve
  eq "one chown" 1 "$(chown_calls)"
  has "of the key directory" "$(calls_text)" "chown -hR 65532:65532 $keys"
  lacks "and not of the data directory" "$(calls_text)" "chown -hR 65532:65532 $data"
}

# The directory is right and one file in it is not: that is a restored backup, and
# it is what "only when needed" must not miss.
test_finds_a_file_in_a_volume_that_is_otherwise_right() {
  new_env
  chown 65532:65532 "$data" "$keys"
  mkdir -p "$data/backups/deep"
  : > "$data/backups/deep/old.bak"
  chown 65532:65532 "$data/backups" "$data/backups/deep"
  # root:root, by the other user's own owner
  chown 0:0 "$data/backups/deep/old.bak"
  enter serve
  eq "the file was found" 65532:65532 "$(owner "$data/backups/deep/old.bak")"
  eq "one chown, of the data directory" 1 "$(chown_calls)"
}

test_a_wrong_group_alone_is_enough() {
  new_env
  chown 65532:65532 "$data" "$keys"
  chown 65532:0 "$keys"
  enter serve
  eq "the group was set" 65532:65532 "$(owner "$keys")"
}

test_a_wrong_user_alone_is_enough() {
  new_env
  chown 65532:65532 "$data" "$keys"
  chown 0:65532 "$data"
  enter serve
  eq "the user was set" 65532:65532 "$(owner "$data")"
}

test_makes_missing_directories() {
  new_env
  rm -rf "$data" "$keys"
  enter serve
  eq "the data directory exists and is the panel's" 65532:65532 "$(owner "$data")"
  eq "so is the key directory" 65532:65532 "$(owner "$keys")"
}

# A link that is planted in a volume must not make root change the owner of what
# it points to. The link to /etc is only planted in a container: a mistake of the
# entrypoint would change the owner of the real /etc of whatever this runs on.
test_does_not_follow_links_out_of_a_volume() {
  new_env
  mkdir "$world/outside"
  echo precious > "$world/outside/file"
  chown 0:0 "$world/outside" "$world/outside/file"
  ln -s "$world/outside/file" "$data/link-to-file"
  ln -s "$world/outside" "$data/link-to-dir"
  etc_link_planted=
  if [ -f /.dockerenv ]; then
    ln -s /etc "$keys/link-to-etc"
    etc_link_planted=1
  else
    skip "the link to /etc is not planted: this is not a container (there is no /.dockerenv), and a mistake would change the owner of the real /etc"
  fi
  enter serve
  eq "the file that a link points to is not touched" 0:0 "$(owner "$world/outside/file")"
  eq "nor the directory" 0:0 "$(owner "$world/outside")"
  if [ -n "$etc_link_planted" ]; then
    eq "nor /etc" 0:0 "$(owner /etc)"
  fi
  eq "the links are the panel's" 65532:65532 "$(stat -c '%u:%g' "$data/link-to-file")"
  has "chown was told not to follow" "$(calls_text)" "chown -hR "
}

test_a_chown_that_fails_is_a_warning() {
  new_env
  CHOWN_FAILS=1 enter serve
  eq "the panel is started all the same" 0 "$rc"
  has "the launcher ran" "$(calls_text)" "launcher serve"
  has "the entrypoint warns" "$(stderr_text)" "warning: could not change the owner"
}

test_a_directory_that_cannot_be_made_is_a_warning() {
  new_env
  rm -rf "$data"
  : > "$data" # a file where the directory should be
  enter serve
  eq "the panel is started all the same" 0 "$rc"
  has "the entrypoint warns" "$(stderr_text)" "warning: cannot create $data"
  eq "the key directory was still taken" 65532:65532 "$(owner "$keys")"
}

# Not root: nothing to change and nobody to become.
test_as_another_user_it_only_runs_the_command() {
  new_env
  cat > "$world/shims/id" <<'EOF'
#!/bin/sh
echo 1000
EOF
  chmod 755 "$world/shims/id"
  enter serve --flag
  eq "no chown" 0 "$(chown_calls)"
  lacks "no su-exec" "$(calls_text)" "su-exec"
  eq "the launcher runs" "launcher serve --flag" "$(calls_text)"
  eq "nothing was changed" 0:0 "$(owner "$data")"
  enter version
  eq "and the binary too" "panel version" "$(sed -n 2p "$calls")"
}

test_honours_the_directories_of_the_environment() {
  new_env
  other=$world/elsewhere
  mkdir -p "$other"
  chown 0:0 "$other"
  WORLD=$world POSTERN_DATA=$other POSTERN_KEYS=$keys POSTERN_LAUNCHER=$world/launcher POSTERN_PANEL_BIN=$world/panel \
    PATH="$world/shims:$PATH" sh "$entrypoint_src" serve 2> "$world/stderr"
  eq "the data directory of the environment is taken" 65532:65532 "$(owner "$other")"
  eq "and the key directory of the environment" 65532:65532 "$(owner "$keys")"
}

# ---- run -----------------------------------------------------------------------

if [ ! -f "$entrypoint_src" ]; then
  echo "entrypoint_test.sh: $entrypoint_src does not exist" >&2
  exit 1
fi

for t in \
  test_takes_the_volumes_for_the_panel_user \
  test_drops_root_before_the_launcher \
  test_other_commands_skip_the_launcher \
  test_passes_the_exit_status \
  test_does_not_walk_a_volume_that_is_right \
  test_takes_only_the_volume_that_needs_it \
  test_finds_a_file_in_a_volume_that_is_otherwise_right \
  test_a_wrong_group_alone_is_enough   test_a_wrong_user_alone_is_enough \
  test_makes_missing_directories \
  test_does_not_follow_links_out_of_a_volume \
  test_a_chown_that_fails_is_a_warning \
  test_a_directory_that_cannot_be_made_is_a_warning \
  test_as_another_user_it_only_runs_the_command \
  test_honours_the_directories_of_the_environment; do
  echo "$t"
  "$t"
done

echo
echo "$checks checks, $failed failed"
if [ "$failed" -ne 0 ]; then
  exit 1
fi
