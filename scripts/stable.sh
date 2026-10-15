#!/usr/bin/env bash
# The job of the stable list of engines (.github/workflows/stable.yml,
# docs/releasing.md): which upstream releases of the engines and providers the
# end-to-end tests passed on, in engines-stable.json, signed with the stable key.
#
#   bash scripts/stable.sh candidates <dir>            the job candidates: no secret
#   bash scripts/stable.sh e2e <component> <version>   one candidate through its end-to-end tests: no secret
#   bash scripts/stable.sh sign <dir> [<c>@<v>...]     the job stable-sign: the key, no candidate code
#   bash scripts/stable.sh publish <dir>               the list onto the release engines-stable
#   bash scripts/stable.sh --dry-run <dir>             candidates, and the list that they would give
#
# candidates fetches the list that is out (POSTERN_STABLE_LIST_URL, a 404 is
# none yet) into <dir>/current.json and runs the tool's candidates
# (scripts/release): for each component the newest upstream release newer than
# its newest stable version whose files pass the checksum rules and the
# static-ELF check, in <dir>/candidates.json. In a job it writes the matrix of
# the candidates to GITHUB_OUTPUT (matrix, any) and the releases it skipped to
# the job summary.
#
# e2e runs the end-to-end tests of the component (scripts/e2e.sh) with the
# override POSTERN_E2E_<COMPONENT>_VERSION, so that they run on the candidate:
# telemt the first test and TestVersions, mtg TestVersions, xray the egress
# test. (psiphon-core publishes no releases and has no candidates.)
#
# sign takes <dir>/candidates.json and the candidates that passed (<c>@<v>),
# and the versions to drop (POSTERN_STABLE_DROP, words <c>@<v>, from a manual
# run): the tool's stable-add makes <dir>/engines-stable.json of the list that
# is out, and stable-sign dates and signs it with the key of
# POSTERN_STABLE_KEY (the text of the key file) and POSTERN_STABLE_KEY_PASSWORD.
# Without the key (a fork, a repository without the environment) it says so and
# does nothing; with nothing to add or drop it signs nothing either.
#
# publish puts <dir>/engines-stable.json and its .minisig on the release with
# the tag engines-stable, made when it is missing: on GitHub with gh release
# upload --clobber (GH_TOKEN); on Gitea with its API (GITEA_TOKEN), deleting the
# attachment of each name first, since Gitea keeps two of one name otherwise.
#
# --dry-run is candidates and a list of all the candidates, as if they all
# passed, in <dir>/engines-stable.json; nothing is signed, uploaded or tested.
#
# Environment:
#   POSTERN_GITHUB_API           the API that candidates reads (https://api.github.com)
#   GITHUB_TOKEN                 a token for it, optional
#   POSTERN_STABLE_LIST_URL      the list that is out; by default the asset of the
#                                release engines-stable of GITHUB_REPOSITORY (urbnywrt/postern)
#                                on GITHUB_SERVER_URL (https://github.com)
#   POSTERN_STABLE_DROP          sign: <c>@<v> to drop, apart by spaces
#   POSTERN_STABLE_KEY           sign: the text of the secret stable key file
#   POSTERN_STABLE_KEY_PASSWORD  sign: its password
#
# Nothing of the key or of its password is printed: both are taken out of the
# environment first, and only the tool that signs gets the password; the key is
# a file of a private temporary directory only while it is used.

# Tracing (bash -x) would print the key.
set +x
set -euo pipefail

stable_key=${POSTERN_STABLE_KEY:-}
stable_password=${POSTERN_STABLE_KEY_PASSWORD:-}
unset POSTERN_STABLE_KEY POSTERN_STABLE_KEY_PASSWORD

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

log() { printf 'stable.sh: %s\n' "$*" >&2; }
die() {
  log "$*"
  exit 1
}
usage() {
  die "usage: bash scripts/stable.sh candidates <dir> | e2e <component> <version> | sign <dir> [<c>@<v>...] | publish <dir> | --dry-run <dir>"
}

tool() { go run ./scripts/release "$@"; }

server=${GITHUB_SERVER_URL:-https://github.com}
repository=${GITHUB_REPOSITORY:-urbnywrt/postern}
list_url=${POSTERN_STABLE_LIST_URL:-$server/$repository/releases/download/engines-stable/engines-stable.json}

# summary appends a line to the job summary, when there is one.
summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# fetch_list <file>: the list that is out, or no file when there is none yet.
fetch_list() {
  local out=$1 status
  case $list_url in
    https://* | http://127.0.0.1:* | http://localhost:*) ;;
    *) die "POSTERN_STABLE_LIST_URL is not https://: $list_url" ;;
  esac
  rm -f "$out"
  status=$(curl --silent --show-error --location --max-time 120 --retry 3 \
    --output "$out.part" --write-out '%{http_code}' "$list_url") || die "cannot fetch the stable list from $list_url"
  case $status in
    200) mv "$out.part" "$out" ;;
    404)
      rm -f "$out.part"
      log "no stable list is out yet ($list_url)"
      ;;
    *)
      rm -f "$out.part"
      die "fetching the stable list from $list_url: HTTP $status"
      ;;
  esac
}

# candidates <dir>
candidates() {
  local dir=$1 stable=() matrix="" line component version
  mkdir -p "$dir"
  fetch_list "$dir/current.json"
  if [ -f "$dir/current.json" ]; then
    stable=(--stable "$dir/current.json")
  fi
  tool candidates "${stable[@]}" --out "$dir/candidates.json" | tee "$dir/candidates.txt"
  while IFS= read -r line; do
    case $line in
      "candidate "*)
        read -r _ component version <<< "$line"
        matrix+="${matrix:+,}{\"component\":\"$component\",\"version\":\"$version\"}"
        ;;
      "skipped "*)
        summary "- ${line#skipped }: not tried"
        ;;
    esac
  done < "$dir/candidates.txt"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'matrix=[%s]\n' "$matrix" >> "$GITHUB_OUTPUT"
    if [ -n "$matrix" ]; then echo "any=true"; else echo "any=false"; fi >> "$GITHUB_OUTPUT"
  fi
  if [ -z "$matrix" ]; then
    log "no candidate: every component is at its newest usable release"
  fi
}

# e2e <component> <version>
e2e() {
  local component=$1 version=$2 run
  case $component in
    telemt)
      export POSTERN_E2E_TELEMT_VERSION=$version
      run='^(TestPanelToNodeFakeTLS|TestVersions)$'
      ;;
    mtg)
      export POSTERN_E2E_MTG_VERSION=$version
      run='^TestVersions$'
      ;;
    xray)
      export POSTERN_E2E_XRAY_VERSION=$version
      run='^TestEgressChainFailover$'
      ;;
    *) die "no end-to-end test runs $component" ;;
  esac
  log "the end-to-end tests of $component on $version: $run"
  if bash scripts/e2e.sh -test.run "$run"; then
    summary "- $component $version: passed the end-to-end tests"
  else
    summary "- $component $version: **failed** the end-to-end tests, and is not added"
    return 1
  fi
}

# sign <dir> [<c>@<v>...]
sign() {
  local dir=$1 tmp drops=()
  shift
  if [ -z "$stable_key" ]; then
    log "POSTERN_STABLE_KEY is not set (a fork, or a repository without the environment of the stable key): nothing is signed"
    summary "- no stable key: nothing was signed"
    return 0
  fi
  # shellcheck disable=SC2206 # words <c>@<v>
  drops=(${POSTERN_STABLE_DROP:-})
  if [ "$#" -eq 0 ] && [ "${#drops[@]}" -eq 0 ]; then
    log "no candidate passed and nothing is dropped: the list stays as it is"
    return 0
  fi
  fetch_list "$dir/current.json"
  local list=()
  if [ -f "$dir/current.json" ]; then
    list=(--list "$dir/current.json")
  fi
  local drop_flags=() d
  for d in "${drops[@]}"; do
    drop_flags+=(--drop "$d")
  done
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # The tool that holds the key is built with caches of its own: a cache that
  # the runner restored could hold a trojaned package, written there by a job
  # that ran npm (S5-12). -modcacherw lets the cleanup remove the modules.
  env -u GOOS -u GOARCH CGO_ENABLED=0 GOCACHE="$tmp/gocache" GOMODCACHE="$tmp/gomod" GOFLAGS="-mod=readonly -modcacherw" \
    go build -trimpath -o "$tmp/release-tool" ./scripts/release
  "$tmp/release-tool" stable-add "${list[@]}" --from "$dir/candidates.json" "${drop_flags[@]}" --out "$dir/engines-stable.json" "$@"
  (umask 077 && printf '%s\n' "$stable_key" > "$tmp/stable.key")
  POSTERN_MINISIGN_PASSWORD=$stable_password "$tmp/release-tool" stable-sign --key "$tmp/stable.key" "$dir/engines-stable.json" > /dev/null
  rm -f "$tmp/stable.key"
  summary "- signed engines-stable.json: $*${drops[*]:+; dropped ${drops[*]}}"
}

# publish <dir>
publish() {
  local dir=$1 file
  for file in "$dir/engines-stable.json" "$dir/engines-stable.json.minisig"; do
    [ -f "$file" ] || die "$file is missing: nothing to publish"
  done
  if [ "$server" = https://github.com ]; then
    if ! gh release view engines-stable > /dev/null 2>&1; then
      gh release create engines-stable --title "Stable engines" --latest=false \
        --notes "The engine versions that passed the end-to-end tests, signed with the stable key (docs/releasing.md)."
    fi
    gh release upload engines-stable --clobber "$dir/engines-stable.json" "$dir/engines-stable.json.minisig"
    return
  fi
  publish_gitea "$dir"
}

# publish_gitea <dir>: the API of Gitea, with the token in a file of headers.
publish_gitea() {
  local dir=$1 tmp api_base id name ids
  [ -n "${GITEA_TOKEN:-}" ] || die "GITEA_TOKEN is not set"
  api_base=$server/api/v1/repos/$repository
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  (umask 077 && printf 'Authorization: token %s\n' "$GITEA_TOKEN" > "$tmp/headers")
  api() {
    local method=$1 path=$2 status
    shift 2
    status=$(curl --silent --show-error --output "$tmp/answer" --write-out '%{http_code}' \
      --request "$method" --header @"$tmp/headers" "$@" "$api_base$path")
    case $status in
      2??) return 0 ;;
      404) return 4 ;;
    esac
    echo "$method $path: HTTP $status" >&2
    cat "$tmp/answer" >&2
    return 1
  }
  local rc=0
  api GET /releases/tags/engines-stable || rc=$?
  case $rc in
    0) ;;
    4)
      api POST /releases --header 'Content-Type: application/json' --data-binary \
        '{"tag_name":"engines-stable","target_commitish":"'"${GITHUB_SHA:-main}"'","name":"Stable engines","body":"The engine versions that passed the end-to-end tests, signed with the stable key (docs/releasing.md).","draft":false,"prerelease":false}'
      ;;
    *) die "the release engines-stable cannot be read" ;;
  esac
  # node reads the JSON, as the release workflow does: jq is not on every runner.
  id=$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).id))' "$tmp/answer")
  for file in "$dir/engines-stable.json" "$dir/engines-stable.json.minisig"; do
    name=$(basename "$file")
    ids=$(node -e '
      const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      process.stdout.write((r.assets || []).filter(a => a.name === process.argv[2]).map(a => a.id).join(" "));
    ' "$tmp/answer" "$name")
    local old
    for old in $ids; do
      api DELETE "/releases/$id/assets/$old"
    done
    api POST "/releases/$id/assets?name=$name" --form "attachment=@$file"
    echo "uploaded $name"
  done
}

# dry_run <dir>
dry_run() {
  local dir=$1 passed=() line component version list=()
  candidates "$dir"
  while IFS= read -r line; do
    case $line in
      "candidate "*)
        read -r _ component version <<< "$line"
        passed+=("$component@$version")
        ;;
    esac
  done < "$dir/candidates.txt"
  if [ -f "$dir/current.json" ]; then
    list=(--list "$dir/current.json")
  fi
  tool stable-add "${list[@]}" --from "$dir/candidates.json" --out "$dir/engines-stable.json" "${passed[@]}"
  log "dry run: $dir/engines-stable.json is the list that the candidates would give if they all passed; nothing was tested, signed or uploaded"
}

[ "$#" -ge 1 ] || usage
command=$1
shift
case $command in
  candidates)
    [ "$#" -eq 1 ] || usage
    candidates "$1"
    ;;
  e2e)
    [ "$#" -eq 2 ] || usage
    e2e "$1" "$2"
    ;;
  sign)
    [ "$#" -ge 1 ] || usage
    sign "$@"
    ;;
  publish)
    [ "$#" -eq 1 ] || usage
    publish "$1"
    ;;
  --dry-run)
    [ "$#" -eq 1 ] || usage
    dry_run "$1"
    ;;
  *) usage ;;
esac
