#!/usr/bin/env bash
# Tests for the job of the stable list: that the secrets of signing reach only
# the job that signs (.github/workflows/stable.yml, and no end-to-end job of
# ci.yml), the caches, the pins and the timeouts of the workflows, and what
# scripts/stable.sh does without the key and without a
# command. The dry run against a fake API is TestStableScriptDryRun of
# scripts/release.
#
#   bash scripts/wsl 'bash scripts/stable_test.sh'

set -u

root=$(cd "$(dirname "$0")/.." && pwd) || exit 1
stable_yml=$root/.github/workflows/stable.yml
ci_yml=$root/.github/workflows/ci.yml
release_yml=$root/.github/workflows/release.yml

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

# job FILE NAME prints the lines of the job NAME of the workflow FILE: from its
# key (two spaces in, under jobs:) to the next job.
job() {
  awk -v name="$2" '
    /^jobs:/ { in_jobs = 1; next }
    in_jobs && /^[^ #]/ { in_jobs = 0 }
    in_jobs && /^  [A-Za-z0-9_-]+:/ { cur = $1; sub(":", "", cur) }
    in_jobs && cur == name { print }
  ' "$1"
}

# secrets FILE NAME prints the secrets that the job names, sorted, one a line.
secrets() {
  job "$1" "$2" | grep -o 'secrets\.[A-Za-z0-9_]*' | sort -u | sed 's/^secrets\.//'
}

t_only_the_job_that_signs_has_the_key() {
  local j
  for j in candidates e2e; do
    [ -n "$(job "$stable_yml" "$j")" ] || bad "stable.yml has a job $j"
    eq "the job $j names no secret" "" "$(secrets "$stable_yml" "$j")"
    eq "the job $j runs in no environment" "" "$(job "$stable_yml" "$j" | grep -c '^    environment:' | grep -v '^0$')"
  done
  eq "the job stable-sign names the stable key, its password and the token of Gitea" \
    "GITEA_TOKEN POSTERN_STABLE_KEY POSTERN_STABLE_KEY_PASSWORD" "$(secrets "$stable_yml" stable-sign | tr '\n' ' ' | sed 's/ $//')"
  eq "the job stable-sign runs in the environment stable" "    environment: stable" "$(job "$stable_yml" stable-sign | grep '^    environment:')"
  eq "the job stable-sign alone may write" "1" "$(grep -c 'contents: write' "$stable_yml")"
  eq "no other job of stable.yml" "candidates e2e stable-sign" \
    "$(awk '/^jobs:/{j=1;next} j&&/^[^ #]/{j=0} j&&/^  [A-Za-z0-9_-]+:/{sub(":","",$1);print $1}' "$stable_yml" | tr '\n' ' ' | sed 's/ $//')"
  eq "the end-to-end job of CI names no secret" "" "$(secrets "$ci_yml" e2e)"
  eq "no workflow but stable.yml names the stable key" "$stable_yml" \
    "$(grep -l 'POSTERN_STABLE_KEY' "$root"/.github/workflows/*.yml)"
}

# The jobs that hold a key restore no Go cache that another job saved (a job
# that runs npm could have written into it), and run only actions pinned to a
# commit (S5-12).
t_the_jobs_with_a_key_take_no_cache() {
  local file j file_job
  for file_job in "$release_yml:sign" "$release_yml:image" "$release_yml:publish" "$stable_yml:stable-sign"; do
    file=${file_job%:*} j=${file_job##*:}
    [ -n "$(job "$file" "$j")" ] || bad "$(basename "$file") has a job $j"
    eq "the job $j uses only actions pinned to a commit" "" "$(job "$file" "$j" | grep -E '^ *(- )?uses:' | grep -vE 'uses: [^@]+@[0-9a-f]{40} # v[0-9.]+$')"
    eq "setup-go in the job $j saves and restores no cache" "$(job "$file" "$j" | grep -c 'actions/setup-go@')" "$(job "$file" "$j" | grep -c '^ *cache: false$')"
  done
  for j in sign stable-sign; do
    file=$release_yml
    [ "$j" = sign ] || file=$stable_yml
    eq "the job $j has setup-go" 1 "$(job "$file" "$j" | grep -c 'actions/setup-go@')"
  done
  local s
  for s in release.sh stable.sh; do
    eq "$s builds its tool with a cache of its own" 1 "$(grep -c 'GOCACHE="\$[a-z]*/gocache" GOMODCACHE="\$[a-z]*/gomod"' "$root/scripts/$s")"
  done
}

# Every job has a timeout of its own, below the default of six hours, and CI
# runs once for a pull request, and cancels the run that a newer one replaces.
t_every_job_has_a_timeout() {
  local file j jobs
  for file in "$ci_yml" "$release_yml" "$stable_yml"; do
    jobs=$(awk '/^jobs:/{j=1;next} j&&/^[^ #]/{j=0} j&&/^  [A-Za-z0-9_-]+:/{sub(":","",$1);print $1}' "$file")
    for j in $jobs; do
      eq "$(basename "$file") job $j has a timeout" 1 "$(job "$file" "$j" | grep -cE '^    timeout-minutes: [0-9]+$')"
    done
  done
  eq "CI runs on a push to main and dev only" "    branches: [main, dev]" "$(grep -A1 '^  push:' "$ci_yml" | tail -n 1)"
  eq "CI cancels a run that a newer one replaces" "  cancel-in-progress: true" "$(grep -A2 '^concurrency:' "$ci_yml" | tail -n 1)"
}

t_without_the_key_nothing_is_signed() {
  local dir out rc
  dir=$(mktemp -d)
  out=$(env -u POSTERN_STABLE_KEY -u POSTERN_STABLE_KEY_PASSWORD GITHUB_STEP_SUMMARY= bash "$root/scripts/stable.sh" sign "$dir" telemt@3.5.15 2>&1)
  rc=$?
  eq "sign without POSTERN_STABLE_KEY: exit 0" 0 "$rc"
  case $out in
    *"POSTERN_STABLE_KEY is not set"*) ok "and it says why" ;;
    *) bad "and it says why" "$out" ;;
  esac
  eq "and writes nothing" "" "$(ls -A "$dir")"
  rm -rf "$dir"
}

t_a_wrong_command_line_is_refused() {
  local rc
  bash "$root/scripts/stable.sh" > /dev/null 2>&1
  rc=$?
  eq "no command: exit 1" 1 "$rc"
  bash "$root/scripts/stable.sh" e2e nginx 1.0 > /dev/null 2>&1
  rc=$?
  eq "an end-to-end run of a component that none runs: exit 1" 1 "$rc"
}

t_only_the_job_that_signs_has_the_key
t_the_jobs_with_a_key_take_no_cache
t_every_job_has_a_timeout
t_without_the_key_nothing_is_signed
t_a_wrong_command_line_is_refused

printf '\n%d checks, %d failed\n' "$checks" "$failed"
[ "$failed" -eq 0 ]
