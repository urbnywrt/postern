#!/usr/bin/env bash
# Self-test for scripts/check-denylist.sh and the hooks in .githooks/.
#
# Everything runs in a temporary directory with a throw-away deny-list that
# holds documentation values only; the real (private) deny-list is never read.
#
#   bash scripts/test-hooks.sh      # prints "hooks: OK" on success
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check=$root/scripts/check-denylist.sh

# Do not inherit repository context when run from inside a git hook.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX

tmp=$(mktemp -d)
trap 'cd "$root" && rm -rf "$tmp"' EXIT

secret=198.51.100.77 # the "private" host of the throw-away deny-list
out=

fail() {
  printf 'hooks: FAIL: %s\n' "$*" >&2
  exit 1
}

# expect <exit status> <label> <command...>
# Runs the command and leaves its combined output in $out.
expect() {
  local want=$1 label=$2 rc=0
  shift 2
  out=$("$@" 2>&1) || rc=$?
  [ "$rc" -eq "$want" ] || fail "$label: exit status $rc, want $want. Output: $out"
}

# reported <text>: $out must contain <text> and must not leak a deny-list pattern.
reported() {
  local lower
  case $out in
    *"$1"*) ;;
    *) fail "report lacks '$1'. Output: $out" ;;
  esac
  lower=$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')
  case $lower in
    *198.51.100.77* | *staging.internal.example*) fail "output leaks a deny-list pattern. Output: $out" ;;
  esac
}

# --- fixtures ----------------------------------------------------------------

denylist=$tmp/denylist.txt
{
  echo '# throw-away deny-list: documentation values only'
  echo
  echo "$secret"
  echo '  Staging.Internal.Example  ' # blanks and mixed case are normalised
} >"$denylist"

export POSTERN_DENYLIST=$denylist
export HOME=$tmp/home # no ~/.config deny-list and no global git config
mkdir -p "$HOME"

repo=$tmp/repo
mkdir "$repo"
git -C "$repo" init -q
cd "$repo"
git config user.name "Hook Test"
git config user.email "hook-test@example.test"
git config commit.gpgsign false
git config core.autocrlf false
mkdir "$tmp/no-hooks"
git config core.hooksPath "$tmp/no-hooks" # these checks must not trigger any hook

# --- check-denylist.sh --staged ----------------------------------------------

printf 'hello\nworld\n' >clean.txt
printf 'ok\nhost=%s\n' "$secret" >dirty.txt
git add clean.txt
expect 0 "--staged, clean file" "$check" --staged

git add dirty.txt
expect 1 "--staged, listed address" "$check" --staged
reported "denylist: dirty.txt:2: matched pattern #1"
git reset -q

printf 'x\nSTAGING.internal.EXAMPLE\n' >mixed.txt
git add mixed.txt
expect 1 "--staged, mixed-case match" "$check" --staged
reported "denylist: mixed.txt:2: matched pattern #2"
git reset -q

printf '%s\n' "$secret" >"with space.txt"
printf '++ %s\n' "$secret" >plusplus.txt # the diff shows this line as "+++ ..."
git add "with space.txt" plusplus.txt
expect 1 "--staged, odd file name and '+++' content" "$check" --staged
reported "denylist: with space.txt:1: matched pattern #1"
reported "denylist: plusplus.txt:1: matched pattern #1"
git reset -q
rm "with space.txt" plusplus.txt mixed.txt

# Only added lines count: pre-existing matches are not reported again.
git add dirty.txt
git commit -q -m "test: seed"
printf 'changed\nhost=%s\n' "$secret" >dirty.txt
git add dirty.txt
expect 0 "--staged, match only on an untouched line" "$check" --staged

printf 'changed\nhost=%s\nthird\nfourth\nother=%s\n' "$secret" "$secret" >dirty.txt # distinct text keeps git's alignment unambiguous
git add dirty.txt
expect 1 "--staged, match added in a later hunk" "$check" --staged
reported "denylist: dirty.txt:5: matched pattern #1"
case $out in
  *"dirty.txt:2:"*) fail "an untouched line was reported. Output: $out" ;;
esac

printf 'changed\n' >dirty.txt # removing a listed string is always fine
git add dirty.txt
expect 0 "--staged, listed string removed" "$check" --staged
git reset -q

# --- check-denylist.sh --message ---------------------------------------------

printf 'feat: add thing\n' >msg-clean.txt
printf 'fix: reach %s\n\nbody\n' "$secret" >msg-dirty.txt
expect 0 "--message, clean" "$check" --message msg-clean.txt
expect 1 "--message, listed address" "$check" --message msg-dirty.txt
reported "denylist: msg-dirty.txt:1: matched pattern #1"
expect 2 "--message, missing file" "$check" --message does-not-exist.txt

# --- check-denylist.sh <paths...> ---------------------------------------------

printf 'a\n%s\n' "$secret" >p-dirty.txt
expect 0 "paths, clean file" "$check" clean.txt
expect 1 "paths, listed address" "$check" p-dirty.txt
reported "denylist: p-dirty.txt:2: matched pattern #1"
mkdir -p tree/sub
cp p-dirty.txt tree/sub/nested.txt
expect 1 "paths, directory is scanned recursively" "$check" tree
reported "denylist: tree/sub/nested.txt:2: matched pattern #1"
expect 2 "paths, missing file" "$check" nope.txt
expect 2 "no arguments" "$check"
expect 2 "unknown option" "$check" --bogus

# A deny-list written on Windows (UTF-8 BOM, CRLF) must work too.
printf '\357\273\277# windows list\r\n\r\n%s\r\n' "$secret" >"$tmp/windows-denylist.txt"
expect 1 "BOM and CRLF deny-list" env POSTERN_DENYLIST="$tmp/windows-denylist.txt" "$check" p-dirty.txt

# --- deny-list lookup order ----------------------------------------------------
# Run a copy of the script from a fake checkout so that <repo-root>/.. is inside $tmp.

fake=$tmp/lookup/postern
mkdir -p "$fake/scripts" "$HOME/.config/postern"
cp "$check" "$fake/scripts/check-denylist.sh"
lcheck=$fake/scripts/check-denylist.sh
cd "$tmp/lookup"

echo token-env >list-env.txt
echo token-root >.postern-denylist
echo token-home >"$HOME/.config/postern/denylist.txt"
echo token-env >hit-env.txt
echo token-root >hit-root.txt
echo token-home >hit-home.txt

use_env=(env POSTERN_DENYLIST="$tmp/lookup/list-env.txt")
no_env=(env -u POSTERN_DENYLIST)

expect 1 "lookup: \$POSTERN_DENYLIST is used" "${use_env[@]}" "$lcheck" hit-env.txt
expect 0 "lookup: \$POSTERN_DENYLIST shadows the others" "${use_env[@]}" "$lcheck" hit-root.txt
expect 1 "lookup: a missing \$POSTERN_DENYLIST is skipped" env POSTERN_DENYLIST="$tmp/missing.txt" "$lcheck" hit-root.txt
expect 1 "lookup: <repo-root>/../.postern-denylist is next" "${no_env[@]}" "$lcheck" hit-root.txt
expect 0 "lookup: <repo-root>/../.postern-denylist shadows ~/.config" "${no_env[@]}" "$lcheck" hit-home.txt
rm .postern-denylist
expect 1 "lookup: ~/.config/postern/denylist.txt is the last resort" "${no_env[@]}" "$lcheck" hit-home.txt
rm "$HOME/.config/postern/denylist.txt"
expect 0 "lookup: no deny-list is not an error" "${no_env[@]}" "$lcheck" hit-home.txt
case $out in
  *"no deny-list"*) ;;
  *) fail "no-list notice missing. Output: $out" ;;
esac
[ "$(printf '%s\n' "$out" | awk 'END { print NR }')" -eq 1 ] || fail "no-list notice must be one line. Output: $out"

# --- the hooks themselves, driven by git commit ----------------------------------
# A stub gitleaks (first on PATH) keeps this independent of what is installed.

stubs=$tmp/stubs
calls=$tmp/gitleaks.calls
mkdir "$stubs"
cat >"$stubs/gitleaks" <<STUB
#!/bin/sh
echo "\$*" >>"$calls"
exit "\${STUB_GITLEAKS_EXIT:-0}"
STUB
chmod +x "$stubs/gitleaks"
export PATH="$stubs:$PATH"

e2e=$tmp/e2e
mkdir "$e2e"
git -C "$e2e" init -q
cd "$e2e"
git config user.name "Hook Test"
git config user.email "hook-test@example.test"
git config commit.gpgsign false
git config core.autocrlf false
git config core.hooksPath "$root/.githooks"

printf 'clean\n' >a.txt
git add a.txt
expect 0 "hooks: clean commit" git commit -q -m "chore: add a"
[ "$(cat "$calls")" = "protect --staged --redact" ] || fail "pre-commit did not run 'gitleaks protect --staged --redact'. Calls: $(cat "$calls")"

printf 'host=%s\n' "$secret" >b.txt
git add b.txt
: >"$calls"
expect 1 "hooks: listed address in staged content" git commit -q -m "chore: add b"
reported "denylist: b.txt:1: matched pattern #1"
[ ! -s "$calls" ] || fail "gitleaks ran although the deny-list check had already failed"
git reset -q
rm b.txt

printf 'also clean\n' >c.txt
git add c.txt
expect 1 "hooks: listed address in the commit message" git commit -q -m "fix: reach $secret"
reported "COMMIT_EDITMSG:1: matched pattern #1"

expect 1 "hooks: gitleaks failure blocks the commit" env STUB_GITLEAKS_EXIT=1 git commit -q -m "chore: add c"
expect 0 "hooks: clean commit after the failures" git commit -q -m "chore: add c"

echo "hooks: OK"
