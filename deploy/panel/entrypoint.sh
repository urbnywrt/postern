#!/bin/sh
# Postern panel entrypoint: the first process of the container. POSIX sh; it runs
# under the busybox ash of the image.
#
#   entrypoint.sh serve [...]   the panel, through launcher.sh
#   entrypoint.sh <command>     postern-panel <command>, without the launcher
#                               (version, and what comes later)
#
# The container starts as root for one reason: the volumes. A directory that is
# bind-mounted from the host (./data and ./keys in compose.yaml) belongs to whoever
# made it there, usually root, and the panel runs as 65532:65532 and could not write
# to it. So this script makes 65532:65532 the owner of the data directory and of the
# key directory, when they or anything in them belong to somebody else, and then
# drops root for good with su-exec before it runs anything of the panel. Nothing
# but this script ever runs as root, and it only runs chown and su-exec.
#
# The ownership is only changed when it has to be: a volume that is right is not
# walked again by chown, and a volume that is read-only, or on a file system that
# does not allow it, is left as it is, with a warning, since the panel may still be
# able to use it. Symbolic links are never followed (chown -h), so a link that was
# planted in a volume cannot make this script change the owner of a file outside
# it.
#
# A container that is started as another user (docker run --user, "user:" in the
# compose file) is not root, cannot change owners and does not try: the command
# runs as that user. Then the volumes have to be writable for it already.
#
# The paths are those of the image (POSTERN_DATA and POSTERN_KEYS, /data and
# /keys). POSTERN_LAUNCHER and POSTERN_PANEL_BIN are for the tests, which run the
# script without the image.

set -eu

uid=65532
gid=65532
data=${POSTERN_DATA:-/data}
keys=${POSTERN_KEYS:-/keys}
launcher=${POSTERN_LAUNCHER:-/usr/local/bin/launcher.sh}
panel=${POSTERN_PANEL_BIN:-/usr/local/bin/postern-panel}

log() {
  printf 'postern-entrypoint: %s\n' "$*" >&2
}

# own DIR makes DIR, and what is in it, belong to uid:gid, if something does not.
own() {
  if ! mkdir -p "$1" 2> /dev/null; then
    log "warning: cannot create $1"
    return 0
  fi
  if [ -n "$(find "$1" \( ! -user "$uid" -o ! -group "$gid" \) -print -quit 2> /dev/null)" ]; then
    log "changing the owner of $1 and what is in it to $uid:$gid"
    if ! chown -hR "$uid:$gid" "$1"; then
      log "warning: could not change the owner of everything in $1; the panel may not be able to use all of it"
    fi
  fi
}

# run COMMAND... replaces this script with COMMAND, as the unprivileged user.
run() {
  if [ "$(id -u)" = 0 ]; then
    exec su-exec "$uid:$gid" "$@"
  fi
  exec "$@"
}

if [ "$(id -u)" = 0 ]; then
  own "$data"
  own "$keys"
fi

case ${1:-} in
  serve) run "$launcher" "$@" ;;
  *) run "$panel" "$@" ;;
esac
