# Releasing Postern

A release of Postern is a git tag `v<major>.<minor>.<patch>` (`v0.5.0`), or a prerelease with a
`-` in it (`v0.5.0-rc.1`). Pushing the tag starts `.github/workflows/release.yml`, which tests
the tag, builds the release in one job and signs it in another with `scripts/release.sh`, pushes
the panel image and the node image, and publishes the release with its notes (see [The jobs](#the-jobs)). This page
is for whoever makes releases: the keys, the tag, Gitea, and what to do when a key has to change.

**The key steps (making, keeping, rotating and replacing the keys) are done by the owner of the
keys, with the maintainer who coordinates the release, and by nobody who only implements changes.
No production key is ever made by a script on its own, kept in the repository or printed; the
tests and CI make throwaway keys of their own when they run, which nothing trusts.**

## What a release is

| File | What it is |
|---|---|
| `postern-node-linux-amd64`, `postern-node-linux-arm64` | The node binary (agent and edge), static, for the two architectures that nodes run on. |
| `postern-panel-linux-amd64`, `postern-panel-linux-arm64` | The panel binary, with the web UI in it. |
| `psiphon-core-linux-amd64`, `psiphon-core-linux-arm64` | Psiphon's client (GPL-3.0), built from a pinned upstream commit, static, with the SHA-256s that the panel pins ([third-party/psiphon-tunnel-core.md](third-party/psiphon-tunnel-core.md)). |
| `<file>.minisig` for each binary | Its signature by the release key. |
| `SHA256SUMS`, `SHA256SUMS.minisig` | The SHA-256 of the six binaries, in the format of `sha256sum`, and its signature. |
| `postern-<tag>-bundle.tar` | The binaries of Postern, `SHA256SUMS` and the signatures, in one plain tar file, for a panel that takes a release as an upload. psiphon-core is not in it (size); the upload takes `psiphon-core-linux-<arch>` with its `.minisig` too, in the bundle or in a tar of its own (see below). |

A signature is a [minisign](https://jedisct1.github.io/minisign/) signature (prehashed) with a
**trusted comment** that names what it signs, and that the signature covers:
`postern <component> <version>`, and ` linux/<arch>` after it for a binary:

```text
postern postern-node v0.5.0 linux/amd64
postern sha256sums v0.5.0
```

A binary takes a signature only when the comment is that of the file that it wants, so a
signature cannot be moved to another file, version or architecture (`internal/release`).

There are two key pairs, and so two sets of public keys compiled into every binary
(`internal/release/keys.go`):

- the **release key** signs `postern-node`, `postern-panel` and `sha256sums`;
- the **stable key** signs `engines-stable`, the signed list of the engine versions that passed the
  end-to-end tests (the asset `engines-stable.json` of the release `engines-stable`).

A binary refuses a signature by a key of the other set, so the key that a job keeps for one
purpose cannot sign for the other. In `release.yml` only the job that signs has a key, the release
key; the stable key is kept in the protected environment of the job that signs the list, and
nowhere else.

`install.sh --version <tag>` on a node downloads `postern-node-linux-<arch>` and `SHA256SUMS` from
`POSTERN_RELEASE_BASE/<tag>/` (`deploy/node/README.md`): for a release on GitHub or Gitea, that base
is `https://<host>/<OWNER>/postern/releases/download`.

## The keys

### Making them

Both key pairs are made on the maintainer's own machine, outside of any repository, with the tool
of the repository. `keygen` refuses a directory that is in a git working tree (where `git add -A`
or a copy of the tree would take the key), never overwrites a key, writes the secret key with mode
0600, encrypted with the password in `POSTERN_MINISIGN_PASSWORD`, and prints the public key:

```sh
read -rs POSTERN_MINISIGN_PASSWORD   # the password of the release key; it is not shown
export POSTERN_MINISIGN_PASSWORD
go run ./scripts/release keygen --out ~/.config/postern/release
# RWQ...            <- the public release key

read -rs POSTERN_MINISIGN_PASSWORD   # another password, for the stable key
go run ./scripts/release keygen --out ~/.config/postern/engines-stable
# RWQ...            <- the public stable key
unset POSTERN_MINISIGN_PASSWORD
```

Each directory then holds `postern-release.key`. Keep a copy of both files and both passwords
offline, apart from each other: a key that is lost cannot sign the next release, and the fleet then
has to be reinstalled as after a compromise (below). `go run ./scripts/release pubkey --key <file>`
prints the public key of a key file again.

The keys are minisign keys: the minisign program reads them too (`minisign -S -s <file>`), and
`aead.dev/minisign` encrypts them as minisign does (scrypt with 1 GiB of memory, a few seconds for
each use).

### Putting the public keys into the binaries

The public keys are the two `RW...` lines. They go into `internal/release/keys.go`, in a commit of
their own:

```go
productionReleaseKeys = "RWQ...the release key..."
productionStableKeys = "RWQ...the stable key..."
```

A list may hold several keys, one to a line or apart by commas (see [Rotating a key](#rotating-a-key)).
Check what a build trusts with

```sh
go run ./scripts/release keys
# release  <key id>  RWQ...
# stable   <key id>  RWQ...
```

The binaries of the first release after that commit are the first that trust the keys. A node or a
panel that runs an older build has no production key, so it verifies no release, and gets to that
one by hand: `install.sh` with the node kit of the new panel image, or an image pull. Until a set
has production keys, a build may add test keys to it (see [Test releases](#test-releases)); once it
has them, the test keys of a build are ignored for that set, and the binary says so in its warnings
(`test-release-keys-ignored`).

### The secrets of CI

| Secret | Where | What |
|---|---|---|
| `POSTERN_RELEASE_KEY` | the environment `release` (GitHub); repository secrets (Gitea) | the text of `~/.config/postern/release/postern-release.key` |
| `POSTERN_RELEASE_KEY_PASSWORD` | the same | its password |
| `POSTERN_STABLE_KEY`, `POSTERN_STABLE_KEY_PASSWORD` | the protected environment of the job of the stable list only | the same for the stable key |

On GitHub, make the environment `release` (Settings, Environments) and put the two secrets there,
not among the secrets of the repository: then only a job that names the environment, the job
that signs, gets them. **Limit the environment to tags**: under "Deployment branches and tags",
"Selected branches and tags" with the one tag rule `v*`, and no branch. A tag `v*` starts a run of
the workflow whoever pushed it, and the rule keeps a job of any other ref (a branch whose copy of
the workflow names the environment) from the key. Required reviewers on the environment make each
signature wait for an approval, which is worth having. With the GitHub CLI:
`gh secret set POSTERN_RELEASE_KEY --env release < ~/.config/postern/release/postern-release.key`
and `gh secret set POSTERN_RELEASE_KEY_PASSWORD --env release` (it asks for the value).

On Gitea: the settings of the repository, Actions, Secrets. **Gitea has no protected
environments**: it takes `environment: release` and ignores it, so the key is a secret of the
repository, and any workflow of the repository that names the secret gets it, with no approval.
There the key is kept from npm and from the build by the jobs alone (the job that builds has no
secret), not by an environment; keep the rights to push tags and workflows to the people who may
release. Neither the key nor its password is ever printed by the workflow or by `scripts/release.sh`.

## Tagging a release

1. Make sure `dev` (or the branch of the release) is green, and that the commits since the last
   release are conventional commits: the notes are made of their subjects.
2. Tag the commit and push the tag:

   ```sh
   git tag -a v0.5.0 -m v0.5.0
   git push origin v0.5.0
   ```

3. Watch the workflow (and approve the job that signs, when the environment asks for it). The job
   that signs refuses a release (no `-`) that is not signed by one of the production release keys
   of the tag. The panel image for amd64 and arm64 is pushed as `<POSTERN_IMAGE>:v0.5.0`, and as
   `<POSTERN_IMAGE>:latest` when the tag is the newest release (never for a prerelease, nor for a
   fix of an older line); then the node image, the same way, as `<POSTERN_NODE_IMAGE>:v0.5.0` (and
   `:latest`); then the release is published with every file of the signed build.

### The jobs

| Job | Has | Does |
|---|---|---|
| `test` | nothing | the Go and web tests |
| `build` | no secret, `contents: read` | `scripts/release.sh build <tag> unsigned`: exports the tag, builds the UI (npm), the four binaries (the panel's with `POSTERN_NODE_IMAGE` as their default node image, `-X .../internal/version.NodeImage`) and psiphon-core for both architectures (`scripts/psiphon-core.sh`: the pinned source archive, `go mod verify`, the toolchain of its go.mod), and writes `MANIFEST`, their SHA-256. Uploads the artifact `unsigned-dist`; its outputs are the SHA-256 of `MANIFEST` and the node image that the panel binaries carry. |
| `sign` | the release key (environment `release`), `contents: read` | `scripts/release.sh sign <tag> unsigned dist`: builds the tool from the tag (`go.sum` checks its modules), and before it signs anything checks, in this order, that the artifact holds the six binaries and `MANIFEST` and nothing else (no other file, link or directory), that `MANIFEST` has the SHA-256 that `build` gave, that the binaries have the sums of `MANIFEST`, and that each is a static Go program of its command (`cmd/node`, `cmd/panel`) and architecture, built for linux without cgo and with `-trimpath`, with a string variable that is the tag and one that is the commit; psiphon-core a static Go build of the ConsoleClient with the SHA-256 that the panel pins. A packed (UPX) binary is refused. Nothing of the artifact runs there, and neither npm nor a build of the binaries does. Then it signs, writes and signs `SHA256SUMS`, verifies every signature, makes the bundle, and uploads `signed-dist`. |
| `image` | `packages: write` | builds the panel image of `signed-dist` (`--build-arg PREBUILT=dist -f deploy/panel/Dockerfile`) and pushes it, then the node image (`-f deploy/node/Dockerfile`) under the name that `build` gives as its output (the one the panel binaries carry, not `vars` read again) and pushes it; without `POSTERN_IMAGE` no panel image, without `POSTERN_NODE_IMAGE` no node image (the job says which it leaves out) |
| `publish` | `contents: write`, no key | the notes, and the release with every file of `signed-dist` |

What the job that signs checks proves that it signs the files that the job that built made, as
they were made: an artifact changed or swapped on the way is refused. It does not prove that the
build was honest: a job that builds, or a package of npm that runs in it, could make another binary
and its `MANIFEST` alike. Only builds that can be repeated, checked by a second build that comes to
the same bytes, would show that; they are not part of this workflow.

Both images are pushed before the release is published, so a release is out only with its images:
when either cannot be built, nothing is published, and the run of the workflow can be repeated.
An image may then be in the registry for a release that a later step did not publish; the next run
of the tag pushes it again.

The notes are the subjects of the commits since the tag before, grouped into features, fixes,
performance, security and the rest (`go run ./scripts/release changelog --from <tag> --to <tag>`):
for a release, the commits since the release before (its prereleases are left out); for a
prerelease, since the tag before. Merges and the bodies of commits are left out.

The variables and secrets that the workflow reads:

| Name | Kind | What |
|---|---|---|
| `POSTERN_IMAGE` | variable | The image to push, without a tag: `ghcr.io/<OWNER>/postern-panel`, `git.example.com/<OWNER>/postern-panel`. Without it no panel image is pushed. |
| `POSTERN_NODE_IMAGE` | variable | The node image to push, without a tag: `ghcr.io/<OWNER>/postern-node`. The build job puts it into the panel binaries as their default node image, which the panel tags with its version in the command that installs a node (`<POSTERN_NODE_IMAGE>:v0.5.0`); the environment variable `POSTERN_NODE_IMAGE` of a panel overrides it. Without it no node image is pushed, and a panel of the release shows that command only when it is given an image. `scripts/release.sh` refuses a value that is not a name without a tag. |
| `POSTERN_REGISTRY_USER`, `POSTERN_REGISTRY_PASSWORD` | secrets | The account of the registry, one pair for both images: the panel image and the node image are pushed with the same credentials, so both must be in registries that this account (or the job token) can write to. Without them the job's own token is used, which works for GHCR on GitHub (the job has `packages: write`). |
| `POSTERN_EXTRA_PUBLIC_KEYS` | variable | Test keys for prereleases (below). It is passed to the build of a prerelease only. |

A tag whose release failed half way: delete the release (on Gitea, the draft that it left) and run
the workflow of the tag again. A release that was published is never changed; a fix is a new tag.

### Test releases

A prerelease may be signed with a throwaway key, and may trust test keys: the comma-separated
public keys of `POSTERN_EXTRA_PUBLIC_KEYS` are compiled into its binaries
(`-X github.com/urbnywrt/postern/internal/release.extraPublicKeys=<keys>`), for test servers whose
nodes and panel are then updated with releases signed by those keys. `scripts/release.sh` refuses
them for a release, and the binaries ignore them for a set that has production keys.

```sh
go run ./scripts/release keygen --unencrypted --out /tmp/postern-test-key   # prints the public key
git tag v0.5.0-test.1
POSTERN_RELEASE_KEY="$(cat /tmp/postern-test-key/postern-release.key)" \
POSTERN_EXTRA_PUBLIC_KEYS=<the public key> bash scripts/release.sh v0.5.0-test.1
```

### Building a release on a workstation

`scripts/release.sh` has three modes. The workflow runs `build <tag> <outdir>` (no key) and
`sign <tag> <indir> <outdir>` (the key, and `POSTERN_MANIFEST_SHA256` from the build) in two jobs.
`scripts/release.sh <tag>` runs both in one go and puts the release in `dist/` of the repository:
**that mode is for a workstation and test keys, never for CI or the key of the releases**, since
the key is then in the shell that runs npm. Every mode exports the tag with `git archive` into a
temporary directory and works there, so the working tree is never changed. `build` and the mode
for a workstation need git, Go 1.27 and Node 24 with npm; `sign` needs git and Go. Where Node 24 is
not installed, run it in a container that has both, for example one built from

```dockerfile
FROM node:24-trixie-slim AS node
FROM golang:1.27-trixie
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
```

```sh
docker build -t postern-release-env - < Dockerfile.release-env
# as yourself, so that dist/ is yours; the caches of Go and npm stay in the container
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src \
  -e POSTERN_RELEASE_KEY -e POSTERN_RELEASE_KEY_PASSWORD \
  postern-release-env bash scripts/release.sh v0.5.0-test.1
```

The image of a release is built of `dist/`, and builds nothing itself:

```sh
docker build --build-arg PREBUILT=dist -f deploy/panel/Dockerfile -t postern-panel:v0.5.0-test.1 .
docker build --build-arg PREBUILT=dist -f deploy/node/Dockerfile -t postern-node:v0.5.0-test.1 .
```

The panel of such a build has a default node image only when the build had `POSTERN_NODE_IMAGE`
(`-e POSTERN_NODE_IMAGE=ghcr.io/<OWNER>/postern-node` above).

The integration test does all of that on a copy of the working tree, with a key that it makes,
in the two modes of the workflow (and checks that `sign` refuses files that the build did not
make) and in the mode for a workstation:
`go test -tags integration -count=1 -timeout 30m -run '^TestReleaseScript$' -v ./scripts/release/`
in such a container, with the Docker socket mounted for the part that builds the image. The Panel
image job of CI runs it on every push.

## Gitea

The workflow runs on Gitea Actions as it is. What it needs there:

- **No protected environment.** Gitea ignores `environment: release`: the release key is a secret
  of the repository, there is no approval before a signature, and the key is kept from the build by
  the jobs only (see [The secrets of CI](#the-secrets-of-ci)).
- **Artifacts.** The jobs hand the build and the release on with `actions/upload-artifact@v4` and
  `actions/download-artifact@v4`, which need Gitea 1.24 or later; on an older instance, change both
  to `@v3`.
- **Which forge.** The publish job takes GitHub's way (`gh`) when `github.server_url` is
  `https://github.com`, and Gitea's API otherwise. GitHub Enterprise Server is therefore taken for
  Gitea, and its publish step fails; such an instance would need the condition changed.
- **The token of the job.** Releases and their attachments are made with the API
  (`POST /api/v1/repos/<OWNER>/<REPO>/releases`, then `POST .../releases/<id>/assets?name=<file>`
  with the file in the multipart field `attachment`, then `PATCH .../releases/<id>` to publish the
  draft) and `Authorization: token` with the automatic `GITEA_TOKEN`. The publish job, which has no
  key, asks for `contents: write`, which on Gitea covers the code and the releases
  ([token permissions](https://docs.gitea.com/usage/actions/token-permissions)); Gitea's own scope
  `releases` would be narrower, but GitHub refuses a workflow that names it. A maximum token
  permission below `write` for releases makes the publish step fail with 403.
- **Attachments of the size of the bundle**, about 70 MB. The API takes release attachments only
  with `[attachment] ENABLED = true` (the default). Gitea 28 limits them with
  `[repository.release] FILE_MAX_SIZE` (in MB, 2048 by default) and `ALLOWED_TYPES` (empty by
  default: every type, files without an extension too); older versions do not limit their size. A
  reverse proxy in front of the instance has to let such a request through as well (nginx:
  `client_max_body_size`, 1 MB by default).
- **A runner with Docker** in the job, privileged, for the image: the step registers QEMU
  (`tonistiigi/binfmt`, pinned by digest) for the other architecture and builds with a buildx
  builder of its own. Without `POSTERN_IMAGE` the step does nothing; with it and without Docker
  it fails. The registry of the instance takes the job's token when the instance allows
  `packages` for it; else set `POSTERN_REGISTRY_USER` and `POSTERN_REGISTRY_PASSWORD` (a token that
  may write packages).
- **Go and Node** come from `actions/setup-go` and `actions/setup-node`, which the runner fetches
  from GitHub, as in the CI workflow.

### A private Gitea

A panel that cannot download the releases of a private instance either has a token for it (the
release source in the settings of the panel) or gets them by hand: download
`postern-<tag>-bundle.tar` from the release and upload it in the panel (Versions page, or
`POST /api/releases/upload`). The panel verifies every file of the bundle with the keys that it
trusts, and keeps the release only when all of them verify.

psiphon-core reaches a panel that is no published release (a dev build, an air-gapped panel)
the same way: put `psiphon-core-linux-amd64` and/or `psiphon-core-linux-arm64` of a release,
each with its `.minisig`, into the bundle or into a tar of their own, and upload it. Each one is
verified like the binaries of Postern (a release key, the trusted comment
`postern psiphon-core <tag> linux/<arch>`, a static ELF) and has to have the SHA-256 that the
panel pins for psiphon-core (built in or from the stable list); a bundle with one that is not
pinned is refused whole. The panel keeps it in its release catalog with its signature, prepares
it from there (no download) and delivers it to the nodes like any other provider binary.

## The stable list

The panels' channel `stable` is the engine and provider versions built into the panel and those
of the signed list `engines-stable.json`, the asset of the release `engines-stable` (with
`engines-stable.json.minisig`). The workflow `.github/workflows/stable.yml` keeps the list: every
Monday, and when it is started by hand (Actions, "Stable engines", Run workflow). It runs only
where the end-to-end tests run (GitHub, or a Gitea with the variable `POSTERN_E2E` = `1`:
[the end-to-end test in CI](testing/e2e.md)), in three jobs:

1. **candidates** (no secret): `scripts/stable.sh candidates` fetches the list that is out and
   runs `go run ./scripts/release candidates`: for each of telemt, mtg and Xray, the
   newest upstream release that is no prerelease, is newer than the newest stable version, and
   whose files for amd64 and arm64 pass the checks of the panel (the SHA-256 that the checksum
   rules expect, the binary out of its archive, a static program of its architecture). The newer
   releases that fail a check are in the job summary. The candidates, with their SHA-256, are the
   artifact `stable-candidates`.
2. **e2e** (no secret), one job per candidate, one at a time: `scripts/stable.sh e2e` runs the
   end-to-end tests with the candidate's version (`POSTERN_E2E_TELEMT_VERSION`,
   `POSTERN_E2E_MTG_VERSION`, `POSTERN_E2E_XRAY_VERSION`: the
   test's release host serves that upstream release, its bytes and checksum from upstream, and
   the tests run on it). telemt goes through `TestPanelToNodeFakeTLS` and `TestVersions`, mtg
   through `TestVersions`, Xray through `TestEgressChainFailover`. (psiphon-core is built by each
   release of Postern from the commit of `scripts/psiphon-core.env`: it has no candidates; a new
   commit is a new version, pinned by hand in `builtin.json`, or in the list with `tag`, the
   release of Postern that holds its files.) A test that would be skipped fails
   when an override is set: a candidate passes only when its tests ran. A failure is in the job
   summary, and that candidate is left out.
3. **stable-sign**, in the environment `stable`, which alone holds `POSTERN_STABLE_KEY` and
   `POSTERN_STABLE_KEY_PASSWORD`: `scripts/stable.sh sign` adds the candidates that passed to the
   list that is out (`stable-add`: sorted, a version that is there already kept as it is, and
   refused when its SHA-256 differs), dates it now and signs it (`stable-sign`, the trusted comment
   `postern engines-stable <generated_at>`), and `scripts/stable.sh publish` replaces the two
   assets of the release `engines-stable`, made when it is missing: `gh release upload --clobber`
   on GitHub; on Gitea the attachment of each name is deleted and the new one uploaded, since Gitea
   keeps two attachments of one name otherwise. No code of a candidate runs in this job: it takes
   the SHA-256 of the candidates job and the names of the passes, and builds its tool from the
   repository.

A version leaves the list only by hand: run the workflow with **drop** set to
`<component>@<version>` (several apart by spaces). The panels then take its stable flag away; a
built-in version stays stable.

Without the secrets (a fork, a repository without the environment) the job that signs says so and
does nothing. **Set the environment up** on GitHub as for `release`: Settings, Environments, a new
environment `stable` with the two secrets, limited to the default branch (the schedule runs there)
and, worth having, required reviewers. On Gitea there is no protected environment: the stable key is
a secret of the repository (see [The secrets of CI](#the-secrets-of-ci)).

`bash scripts/stable.sh --dry-run <dir>` shows on a workstation what the job would find: the
candidates against `POSTERN_GITHUB_API`, and in `<dir>/engines-stable.json` the list that they
would give if they all passed. It tests, signs and uploads nothing.

## Rotating a key

A binary verifies a release with the keys of its own build, so a new key has to be in the binaries
that run before anything is signed with it.

**The release key.**

1. Release N adds the new public key to `productionReleaseKeys` (both keys in the list), and is
   signed with the **old** key: every binary can verify it.
2. Once the fleet runs N or later, set the secrets of the environment `release` (on Gitea, of the
   repository) to the new key. Release N+1 is signed with the **new** key, which N trusts.
3. Release N+2 removes the old key from the list.

A node or a panel that is still below N when N+1 is out has to go to N first: it cannot verify N+1.

**The stable key**, the same with lists: release N adds the new key to `productionStableKeys` (the
lists are still signed with the old one); once the panels run N, the job of the stable list signs
with the new key (its protected environment gets the new secrets); release N+2 removes the old key.

## When a key is compromised

Whoever has the key can sign binaries that every node and panel would install. So:

1. Remove the secrets of that key from CI at once (the environment `release`; on Gitea, the
   repository), and stop the jobs that use it.
2. Make a new key pair, as above, and put **only** the new public key into the set in
   `internal/release/keys.go`.
3. Tag and publish a release signed with the new key.
4. The binaries in the field do not trust the new key and cannot verify that release, and must not:
   the old key cannot be told apart from the attacker's. So they are replaced by hand. **Panels:** pull
   the new image (`docker compose pull && docker compose up -d`; a panel that updated itself from
   `/data/bin` first goes back to the image: remove `/data/bin/current`). **Nodes:** run
   `install.sh` again with the node kit of the new panel image (`deploy/node/README.md`), which
   installs the new binary and its launcher.
5. Say so in the notes of the release, with the time from which the old key is not to be trusted.

For the stable key it is the same, and less urgent: a list signed with it can only name engine
versions as stable, whose checksums still have to match. Steps 1 to 3 replace it; panels that do
not run the new release refuse the new lists until they do.

## Updates that need more than the binary

Self-update replaces only the binary (`postern-node` of a node, `postern-panel` of a panel).

- **Going back with a panel** is by hand, and only to the binary of the image: remove
  `/data/bin/current` in the data volume and restart the container (`deploy/panel/README.md`). The
  panel never installs an older version itself.
- **A release that needs `install.sh` again.** `launcher.sh`, `compose.yaml` and the settings of the
  host change only when `install.sh` runs. The release that sets `net.ipv4.tcp_migrate_req = 1`,
  so that an edge roll does not drop the connections in the accept queue of the old edge (see
  [Rolling the edge](../deploy/node/README.md#rolling-the-edge)), is such a release: run
  `install.sh` again on each existing node after updating it. Its notes say so.

## A note on the build and the key

The UI is built with npm (`npm ci --ignore-scripts`, from `web/package-lock.json`), whose packages
are code that the build runs. In the workflow that happens in the job that builds, which has no
secret; the job that signs runs no npm, builds no binary and runs none, only the tool of the tag,
and takes the files of the build only after the checks of [The jobs](#the-jobs). In the job that
signs, the key and its password leave the environment before anything runs, the key is a file only
while it is read and while it signs, and only the tool gets the password. The mode of
`scripts/release.sh` for a workstation builds and signs in one shell, and so is for test keys.
