#!/bin/sh
# Postern panel launcher: starts the panel in its container. POSIX sh; it runs
# under the busybox ash of the image, as the unprivileged user (entrypoint.sh has
# dropped root before it gets here).
#
#   launcher.sh <args...>      exec  $POSTERN_DATA/bin/current <args...>
#
# It is the launcher of the node (deploy/node/launcher.sh), with the paths of the
# panel and two differences, both below. The panel binary is the one of the image
# until something else is put into the data volume: bin/postern-panel-<version>
# files, bin/current, a relative symlink to the version to run, and bin/previous,
# when there is one, the version that ran before. The launcher picks the binary and
# then replaces itself with it (exec), so no shell is left in between: the binary is
# the main process of the container and gets Docker's signals directly.
#
# Rollback (spec 7). At every start the launcher judges the start before it: if
# that process did not write the healthy marker, the counter of unhealthy starts
# goes up by one; if it did, the counter goes back to zero. When the counter
# reaches 3 and bin/previous is a usable executable, the launcher points
# bin/current at it (one atomic rename), removes bin/previous so that the failed
# version is never picked again, resets the counter, logs what it did to stderr
# and leaves a "rollback" record. Without a usable bin/previous nothing is rolled
# back: the launcher logs why and starts bin/current again. A bin/current that is
# missing or not executable counts as an unhealthy start too, so a half-finished
# update is rolled back like a crashing one. bin/previous may point at the binary
# of the image (an absolute link), which is the version to go back to when the
# first update fails.
#
# State directory: $POSTERN_DATA/run/launcher/
#
#   healthy   MARKER CONTRACT. Written by the BINARY, never by this script, which
#             only deletes it before each start. The launcher gives the binary
#             the path in the environment variable POSTERN_HEALTHY_FILE, and
#             "postern-panel serve" creates the file (the content does not
#             matter; it holds the version) once, and only when the database is
#             open, the master key and the CA are loaded, and the server is
#             listening. It must not do it after a fixed delay of being alive: a
#             process that is up but cannot work is exactly what the rollback is
#             for. A start that never writes it is an unhealthy start.
#   started   Written by the launcher before the exec: "<unix time> <binary>", where
#             <binary> is the name bin/current points to. Failures are counted
#             against that binary: when bin/current points elsewhere at the next
#             start (an update, a manual switch), the counter starts over.
#   crashes   The counter: how many starts in a row, counted when the latest
#             start began, did not write the marker. Internal to the launcher.
#   rollback  Written by the launcher after a rollback: "<unix time> <from> <to>".
#
# Bookkeeping never keeps the binary from starting: when a file cannot be written
# the launcher warns on stderr and goes on.
#
# The differences from the node launcher:
#
#   1. Without bin/current (not even a dangling link) there is nothing to choose
#      from and nothing to roll back to: the launcher runs the binary of the image,
#      /usr/local/bin/postern-panel (POSTERN_PANEL_BIN overrides the path, for
#      tests). This is the state of a panel that has not been updated, and the way
#      back to the image: remove bin/current. The launcher keeps its books for this
#      start too ("started" names the image binary by its path) and hands over the
#      marker path, so the panel knows it runs under its launcher and offers its
#      first update, and that update starts its own count of unhealthy starts.
#      It never makes bin/: there is no rollback from the image binary.
#   2. The marker path is handed over in POSTERN_HEALTHY_FILE, as said above.
#
# A newer image wins over an older self-updated binary, but the launcher does not
# compare versions: the panel does, at its start, before it serves
# (selfupdate.Recover). A panel that runs from bin/ and finds that the image
# binary reports a newer version removes bin/current (and bin/previous when it
# points at the image binary; the version files stay), leaves run/image-newer for
# the image binary to record, and exits 75. This launcher then finds no
# bin/current and runs the image binary, as in difference 1.
#
# Do not run one-off commands through the launcher (it counts as a start and
# clears the healthy marker of the running panel). entrypoint.sh runs everything
# but "serve" without it.

set -u

POSTERN_DATA=${POSTERN_DATA:-/data}
export POSTERN_DATA

bin_dir=$POSTERN_DATA/bin
state_dir=$POSTERN_DATA/run/launcher
current=$bin_dir/current
previous=$bin_dir/previous
image_bin=${POSTERN_PANEL_BIN:-/usr/local/bin/postern-panel}
max_unhealthy=3

log() {
  printf 'postern-launcher: %s\n' "$*" >&2
}

# write_file PATH TEXT replaces PATH with TEXT atomically (a temporary file and a
# rename). A failure is a warning, not an error.
write_file() {
  wf_tmp=$1.tmp
  if printf '%s\n' "$2" > "$wf_tmp" 2> /dev/null && mv -f "$wf_tmp" "$1" 2> /dev/null; then
    return 0
  fi
  rm -f "$wf_tmp" 2> /dev/null
  log "warning: cannot write $1"
  return 1
}

# read_counter FILE prints the number in FILE: 0 when the file is missing, empty or
# not a plain number. Leading zeros are dropped so that the shell never reads the
# value as octal, and an absurdly long number is cut down to something arithmetic
# can handle.
read_counter() {
  rc_n=0
  if [ -f "$1" ]; then
    { IFS= read -r rc_n < "$1"; } 2> /dev/null || :
  fi
  case $rc_n in
    '' | *[!0-9]*) rc_n=0 ;;
  esac
  rc_n=${rc_n#"${rc_n%%[!0]*}"}
  [ "${#rc_n}" -le 6 ] || rc_n=999999
  printf '%s\n' "${rc_n:-0}"
}

# link_target NAME prints where bin/NAME points, or nothing.
link_target() {
  readlink "$bin_dir/$1" 2> /dev/null || :
}

# rollback points bin/current at bin/previous. It returns 0 only when it did.
rollback() {
  if [ ! -L "$previous" ]; then
    log "$crashes unhealthy starts in a row, but there is no bin/previous to roll back to; starting bin/current again"
    return 1
  fi
  rb_to=$(link_target previous)
  if [ ! -f "$previous" ] || [ ! -x "$previous" ]; then
    log "$crashes unhealthy starts in a row, but bin/previous ($rb_to) is not an executable file; starting bin/current again"
    return 1
  fi
  rb_from=$(link_target current)
  if [ "$rb_from" = "$rb_to" ]; then
    log "$crashes unhealthy starts in a row, but bin/previous is the version bin/current already points to ($rb_to); starting it again"
    return 1
  fi
  rm -f "$bin_dir/.current.new"
  if ln -s "$rb_to" "$bin_dir/.current.new" && mv -f "$bin_dir/.current.new" "$current"; then
    rm -f "$previous"
    log "rolled back: bin/current now points to ${rb_to} instead of ${rb_from:-nothing} after $crashes unhealthy starts in a row"
    write_file "$state_dir/rollback" "$(date +%s) ${rb_from:-unknown} $rb_to" || :
    return 0
  fi
  rm -f "$bin_dir/.current.new"
  log "cannot point bin/current at $rb_to; starting bin/current again"
  return 1
}

# Nothing was installed over the image: run the binary of the image (below).
from_image=
if [ ! -e "$current" ] && [ ! -L "$current" ]; then
  from_image=yes
fi

if mkdir -p "$state_dir" 2> /dev/null; then
  chmod 700 "$state_dir" 2> /dev/null || :
else
  log "warning: cannot create $state_dir; the rollback counter does not work for this start"
fi

# The binary the previous start ran, as recorded in "started".
started_name=
if [ -f "$state_dir/started" ]; then
  { IFS=' ' read -r _ started_name < "$state_dir/started"; } 2> /dev/null || :
fi
if [ -n "$from_image" ]; then
  cur_name=$image_bin
else
  cur_name=$(link_target current)
  cur_name=${cur_name:-bin/current}
fi

# Judge the previous start. A failure counts against the binary that failed: when
# bin/current points elsewhere than it did at that start (an update, a switch by
# hand), the old failures say nothing about the new binary and the count starts
# over.
crashes=$(read_counter "$state_dir/crashes")
if [ -e "$state_dir/healthy" ]; then
  crashes=0
elif [ -e "$state_dir/started" ]; then
  if [ "$started_name" = "$cur_name" ]; then
    crashes=$((crashes + 1))
    log "the previous start of $cur_name did not report healthy ($crashes in a row)"
  else
    crashes=0
    log "bin/current changed from ${started_name:-an unknown binary} to $cur_name since the last start; counting unhealthy starts from zero"
  fi
fi

if [ -n "$from_image" ]; then
  if [ "$crashes" -ge "$max_unhealthy" ]; then
    log "$crashes unhealthy starts in a row of the binary of the image; there is nothing to roll back to, starting it again"
  fi
elif [ "$crashes" -ge "$max_unhealthy" ] && rollback; then
  crashes=0
  cur_name=$(link_target current)
fi

# Record this start. The marker is cleared last: if the launcher is stopped in
# between, the next start still sees the marker of the process that wrote it.
write_file "$state_dir/crashes" "$crashes" || :
write_file "$state_dir/started" "$(date +%s) $cur_name" || :
rm -f "$state_dir/healthy"

if [ -z "$from_image" ] && { [ ! -f "$current" ] || [ ! -x "$current" ]; }; then
  log "error: $current is missing or not executable"
  exit 127
fi

# Where the binary writes the marker when it is healthy.
POSTERN_HEALTHY_FILE=$state_dir/healthy
export POSTERN_HEALTHY_FILE

log "starting $cur_name (unhealthy starts in a row: $crashes)"
if [ -n "$from_image" ]; then
  exec "$image_bin" "$@"
fi
exec "$current" "$@"
