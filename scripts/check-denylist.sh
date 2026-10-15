#!/usr/bin/env bash
# Keep private strings (real hosts, addresses, names) out of the repository.
#
#   scripts/check-denylist.sh --staged           lines added in the index (git diff --cached)
#   scripts/check-denylist.sh --message <file>   a commit message file
#   scripts/check-denylist.sh [--] <path>...     files; directories are scanned recursively
#
# The deny-list is a private text file that lives OUTSIDE the repository: one
# pattern per line, blank lines and lines starting with '#' are ignored.
# Patterns are fixed strings, matched case-insensitively. The first existing
# file of these is used:
#
#   1. $POSTERN_DENYLIST
#   2. <repo-root>/../.postern-denylist
#   3. $HOME/.config/postern/denylist.txt
#
# Without a deny-list the script prints a one-line notice and succeeds.
#
# Every hit is reported on stderr as
#
#   denylist: <file>:<line>: matched pattern #<n>
#
# where <n> is the 1-based position of the pattern among the active (neither
# blank nor comment) lines of the deny-list. The pattern itself is never printed.
#
# Exit status: 0 nothing found, 1 at least one hit, 2 usage or I/O error.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(dirname "$script_dir")

usage() {
  cat >&2 <<'USAGE'
usage: check-denylist.sh --staged
       check-denylist.sh --message <file>
       check-denylist.sh [--] <path>...
USAGE
}

die() {
  echo "denylist: $*" >&2
  exit 2
}

mode=
msgfile=
case "${1-}" in
  '')
    usage
    exit 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  --staged)
    [ "$#" -eq 1 ] || {
      usage
      exit 2
    }
    mode=staged
    ;;
  --message)
    [ "$#" -eq 2 ] || {
      usage
      exit 2
    }
    mode=message
    msgfile=$2
    ;;
  --)
    shift
    [ "$#" -gt 0 ] || {
      usage
      exit 2
    }
    mode=paths
    ;;
  -*)
    echo "denylist: unknown option: $1" >&2
    usage
    exit 2
    ;;
  *)
    mode=paths
    ;;
esac

denylist=
for candidate in \
  "${POSTERN_DENYLIST:-}" \
  "$repo_root/../.postern-denylist" \
  "${HOME:-/nonexistent}/.config/postern/denylist.txt"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    denylist=$candidate
    break
  fi
done
if [ -z "$denylist" ]; then
  echo "denylist: no deny-list found (set POSTERN_DENYLIST); nothing checked" >&2
  exit 0
fi
[ -r "$denylist" ] || die "cannot read the deny-list file"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The matcher. It is awk so that the index of the matching pattern is known
# without ever echoing the pattern. Paths reach it through the environment (not
# -v, which would interpret backslashes in Windows-style paths).
cat >"$tmp/scan.awk" <<'AWK'
# mode "diff":  scan the added lines of the unified diff given as file operand.
# mode "paths": scan every file listed (one path per line) in $POSTERN_AWK_LIST.

function check(text, where, lineno,    low, i) {
    low = tolower(text)
    for (i = 1; i <= npat; i++) {
        if (index(low, pat[i]) > 0) {
            printf "denylist: %s:%d: matched pattern #%d\n", where, lineno, i
            hits++
        }
    }
}

# "+++ b/dir/file<TAB>" -> "dir/file" (git appends a TAB after names with blanks)
function diffname(line,    name, tab) {
    name = substr(line, 5)
    tab = index(name, "\t")
    if (tab > 0) name = substr(name, 1, tab - 1)
    if (substr(name, 1, 1) == "\"") name = substr(name, 2, length(name) - 2)
    if (substr(name, 1, 2) == "b/") name = substr(name, 3)
    return name
}

# "@@ -a,b +c,d @@ ..." -> c
function hunkstart(line) {
    if (match(line, /\+[0-9]+/)) return substr(line, RSTART + 1, RLENGTH - 1) + 0
    return 1
}

function scanfile(path,    text, n, rc) {
    n = 0
    while ((rc = (getline text < path)) > 0) check(text, path, ++n)
    if (rc < 0) {
        printf "denylist: cannot read %s\n", path
        unreadable++
    }
    close(path)
}

function status() {
    if (hits > 0) return 1
    if (unreadable > 0) return 2
    return 0
}

BEGIN {
    bom = "\357\273\277"
    deny = ENVIRON["POSTERN_AWK_DENY"]
    while ((getline line < deny) > 0) {
        if (++nline == 1 && index(line, bom) == 1) line = substr(line, length(bom) + 1)
        sub(/\r$/, "", line)
        sub(/^[ \t]+/, "", line)
        sub(/[ \t]+$/, "", line)
        if (line == "" || substr(line, 1, 1) == "#") continue
        pat[++npat] = tolower(line)
    }
    close(deny)
    if (npat == 0) {
        print "denylist: the deny-list has no patterns; nothing checked"
        exit 0
    }
    if (mode == "paths") {
        list = ENVIRON["POSTERN_AWK_LIST"]
        while ((getline path < list) > 0) scanfile(path)
        close(list)
        exit status()
    }
}

mode == "diff" {
    # Header lines ("diff ...", "--- a/x", "+++ b/x") only precede a hunk, so an
    # added line that looks like "+++ ..." inside a hunk is still content.
    if (substr($0, 1, 5) == "diff ") { inhdr = 1; next }
    if (substr($0, 1, 2) == "@@") { inhdr = 0; newline = hunkstart($0); next }
    if (inhdr) {
        if (substr($0, 1, 4) == "+++ ") file = diffname($0)
        next
    }
    if (substr($0, 1, 1) == "+") check(substr($0, 2), file, newline++)
}

END { exit status() }
AWK

scan_diff() {
  POSTERN_AWK_DENY=$denylist awk -v mode=diff -f "$tmp/scan.awk" "$1" >&2
}

scan_paths() {
  POSTERN_AWK_DENY=$denylist POSTERN_AWK_LIST=$1 awk -v mode=paths -f "$tmp/scan.awk" >&2
}

rc=0
case "$mode" in
  staged)
    git -c core.quotepath=off diff --cached -U0 --no-color --no-ext-diff --no-textconv \
      --src-prefix=a/ --dst-prefix=b/ >"$tmp/diff" || die "git diff --cached failed"
    scan_diff "$tmp/diff" || rc=$?
    ;;
  message)
    [ -f "$msgfile" ] && [ -r "$msgfile" ] || die "cannot read commit message file: $msgfile"
    printf '%s\n' "$msgfile" >"$tmp/list"
    scan_paths "$tmp/list" || rc=$?
    ;;
  paths)
    : >"$tmp/list"
    for path in "$@"; do
      if [ -d "$path" ]; then
        find "$path" -name .git -prune -o -type f -print | LC_ALL=C sort >>"$tmp/list"
      elif [ -f "$path" ]; then
        printf '%s\n' "$path" >>"$tmp/list"
      else
        die "no such file or directory: $path"
      fi
    done
    scan_paths "$tmp/list" || rc=$?
    ;;
esac

case "$rc" in
  0) exit 0 ;;
  1) exit 1 ;;
  *) exit 2 ;;
esac
