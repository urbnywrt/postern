# Postern Node Install by One Docker Command — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A node is installed with one `docker run` (or the same as a `compose.yaml`) that the panel shows: an image `ghcr.io/<OWNER>/postern-node:<version>` and a one-time join token. On first start the container generates the node's key, joins the panel over HTTPS with a CSR, lays out `/opt/postern`, seeds its binary and launcher, applies the host sysctls through a one-shot privileged helper, and execs the existing launcher. The kit + bundle path stays as the fallback.

**Architecture:** The panel gets a token table, CSR signing in `pki`, a public Connect procedure `JoinService.Join` (rate-limited by client address like the login) and `NodeService.CreateJoinToken`, which also renders the command for a given panel URL and the configured node image (`POSTERN_NODE_IMAGE`, default compiled in by the release). The node binary gets a `bootstrap` subcommand that is the image's entrypoint and does what `install.sh` did, then `exec`s `bin/launcher.sh agent`; the agent itself is unchanged except for messages. The release workflow builds and pushes the node image next to the panel image. The UI and the SSH install switch to the command; e2e covers the docker path.

**Tech Stack:** Go 1.27 (`crypto/x509` CSR, connect-go client already in the module), Docker Engine API via `internal/dockerapi`, Dockerfile + buildx in `release.yml`, React 19 + Mantine 8 + TanStack Query, buf for protos.

**Spec:** `docs/design/2026-10-08-node-docker-join.md` (binding), on top of `docs/design/2026-10-04-postern-design.md` §5.2 and §7. Facts about the code at the start of this plan: `.superpowers/sdd/node-docker/facts.md` (git-ignored; read the sections a task names).

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply verbatim (module, Go in WSL through `bash scripts/wsl '<command>'`, `scripts/race.sh`, commits from Windows Git Bash with author `urbnywrt <14278436+urbnywrt@users.noreply.github.com>` and **no trailer of any kind**, never `--no-verify`, documentation addresses only, `log/slog`, never log secrets/keys/tokens, runner image `alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`, layout under `/opt/postern`, container labels and names).
- Every proto field, enum number and SQL migration: the next free number on the branch (`internal/panel/store/migrations` is at `0017`; the next is `0018`). Regenerate Go with `bash scripts/gen.sh` (in WSL) and TS with `npm run gen` in `web/`; generated output is committed.
- UI strings go into `web/src/i18n/ru.json` and `en.json` (same keys; the parity test must pass). Russian copy is plain and short.
- **Names (exact):**
  - env of the node container: `POSTERN_JOIN` = `<panel base URL>#<token>`; `POSTERN_HOME` (default `/opt/postern`).
  - env of the panel: `POSTERN_NODE_IMAGE`; Go var `github.com/urbnywrt/postern/internal/version.NodeImage` (ldflag default); repo variable of the release workflow `POSTERN_NODE_IMAGE` (an image name without a tag, e.g. `ghcr.io/<OWNER>/postern-node`).
  - proto: service `postern.panel.v1.JoinService`, rpc `Join`; `NodeService.CreateJoinToken`; field `GetNodeInstallResponse.node_image`.
  - SQL table `node_join_tokens`; audit actions `node.join_token` and `node.join`.
  - node subcommand `postern-node bootstrap`; image paths `/usr/local/lib/postern/postern-node`, `/usr/local/lib/postern/postern-node.minisig` (present in release images only), `/usr/local/lib/postern/launcher.sh`; `ENTRYPOINT ["/usr/local/lib/postern/postern-node"]`, `CMD ["bootstrap"]`; image labels `postern.managed=true`, `postern.role=agent`, `postern.id=agent`; `ENV POSTERN_HOME=/opt/postern`.
  - node files: `data/state/join-token.sha256` (hex SHA-256 of the token last joined with, 0600), `data/run/join/` (0700; the pending key `key.pem` 0600 and `token.sha256` while a join is in flight).
- **Token:** 32 random bytes, base64url without padding (43 characters); the panel stores only its SHA-256; one live token per node (a new one replaces the old); lifetime 24 h; consumed by a successful join; a repeated join with the same token **and the same CSR public key** before expiry returns the same certificate (lost-response retry).
- **Panel URL** in `POSTERN_JOIN` and in `CreateJoinTokenRequest.panel_url`: `https://host[:port]` (no path other than `/`, no query, no fragment, no userinfo); `http://` only when the host is loopback (`127.0.0.0/8`, `::1`, `localhost`). Panel and node both enforce it. The node never uses `HTTP(S)_PROXY` for the join (ruling S5-16).
- **Join limits:** `Join` is a public procedure with the 64 KiB message cap; failures (unknown/expired/used token, bad CSR) are limited per client address with the login's limiter (5 failures in 15 min, then the doubling lock); CSR at most 8 KiB DER, public key ECDSA P-256 only, signature checked.
- **Certificate from a CSR:** the same fields as `pki.CA.IssueServer` for that node (CN = lower-case node id, SAN `<lower id>.internal`, serverAuth only, NotBefore now−1 h, 10 years capped at the CA); the CSR's subject and extensions are ignored. On join the node row gets `cert_pem` and `cert_fingerprint` of the new certificate and `key_enc` = NULL.
- **The command** (rendered by Go only; the UI and the SSH install never build it themselves):

  ```sh
  docker run -d --name postern-agent --restart unless-stopped \
    --network host --pid host --read-only --tmpfs /tmp \
    --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /opt/postern:/opt/postern \
    -v /etc/os-release:/host/etc/os-release:ro \
    -e POSTERN_JOIN='<panel URL>#<token>' \
    <image>
  ```

  and the compose file:

  ```yaml
  name: postern
  services:
    postern-agent:
      image: <image>
      container_name: postern-agent
      restart: unless-stopped
      network_mode: host
      pid: host
      read_only: true
      tmpfs:
        - /tmp
      environment:
        POSTERN_JOIN: "<panel URL>#<token>"
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
        - /opt/postern:/opt/postern
        - /etc/os-release:/host/etc/os-release:ro
      logging:
        driver: json-file
        options:
          max-size: 10m
          max-file: "3"
  ```

- **Image reference resolution** (panel): value = env `POSTERN_NODE_IMAGE` if set, else `version.NodeImage`. Empty → no command (`node_image` empty, `CreateJoinToken` answers `FailedPrecondition` with a message naming `POSTERN_NODE_IMAGE`). A value with a tag or a digest is used as is; without one, `:` + `version.Version` is appended, unless the version is `dev`, which gives no command. The value is validated at startup (Docker reference syntax: lower-case registry/path components, optional `:tag` `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`, optional `@sha256:<64 hex>`); an invalid value refuses to start with a clear message.
- The kit + bundle path, `install.sh`, `launcher.sh`, `deploy/node/compose.yaml` and the kit inside the panel image stay as they are (the release integration test pins the kit's file list).
- Nothing in this plan writes a real address, domain, owner name or token into the repository; docs write `ghcr.io/<OWNER>/postern-node` and `https://panel.example.com`.

## Ordering

Strictly sequential on lane `lane/node-docker` (worktree `C:\Users\URBNY-PC\Documents\Code\mtproto\postern-wt-nodedocker`): 1a → 1b → 2 → 3 → 4 → 5 → 6. Each task ends with its own commits; the next starts from the reviewed head.

---

### Task 1a: Panel: join tokens, CSR signing and `JoinService.Join`

**Files:**
- Create: `internal/panel/store/migrations/0018_join_tokens.sql`, `internal/panel/store/jointokens.go` (+ `_test.go`), `proto/postern/panel/v1/join.proto`, `internal/panel/nodes/join.go` (+ `_test.go`).
- Modify: `internal/pki/pki.go` (+ test), `internal/panel/auth/{ratelimit.go,session.go,service.go}` (exports only), `internal/panel/server/api.go`, `internal/panel/auth/session.go` (`publicProcedures`), `internal/panel/server/{server_test.go,limits_test.go}`, `internal/panel/nodes/connmgr.go`, `internal/panel/nodes/service.go` (create with empty `mgmt_host`; delete cascades), `internal/panel/nodes/bundle_handler.go` (message for a joined node), `gen/go/...`, `web/src/gen/...`.

**Interfaces:**
- Produces: `pki.(*CA).SignServerCSR(csrDER []byte, cn string, dnsNames []string) (certPEM []byte, err error)`; `store` methods to put a token for a node (replacing any), find a token by hash, mark it used by a public-key hash, and apply a join to a node in one transaction (cert, fingerprint, `key_enc` NULL, `mgmt_host` when it was empty); `nodes.Service.MintJoinToken(ctx, nodeID string) (token string, expires time.Time, err error)` (no RPC yet: Task 1b adds it); the Connect handler of `JoinService`; exported from `auth`: the limiter (constructor + begin/fail/succeed/release) and `auth.CallerIP(ctx) (netip.Addr, bool)` (the address the middleware resolved, trusted proxies honoured).
- Consumes: `pki.CA`, `nodes.Manager.Notify`, the auth middleware's `callInfo`.

**Requirements:**
- [ ] `join.proto`: `JoinRequest{string token; bytes csr; string arch; string version}`, `JoinResponse{string node_id; uint32 mgmt_port; bytes ca_pem; bytes cert_pem}`; service `JoinService { rpc Join(JoinRequest) returns (JoinResponse); }`. Mounted under `/api` with the `public` options; listed in `publicProcedures` and in the tests that enumerate procedures and limits.
- [ ] Migration `0018`: `node_join_tokens(node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT 0, used_key BLOB NOT NULL DEFAULT x'') STRICT` (times Unix seconds; `used_key` = SHA-256 of the PKIX DER public key). Follow the existing migration style.
- [ ] `SignServerCSR`: parse DER (≤ 8 KiB), `CheckSignature`, ECDSA P-256 public key only, then the same template and signing as `issue` for a server cert (factor the shared template so `IssueServer` and `SignServerCSR` cannot drift). Tests: fields equal those of `IssueServer` for the same id; wrong curve, RSA, bad signature, oversize, garbage are refused.
- [ ] `Join` handler (`internal/panel/nodes/join.go`), in this order: begin a limiter attempt keyed `join-ip:<ipKey>` (refuse with `ResourceExhausted` + `Retry-After` as the login does); look up SHA-256(token) — unknown → `Unauthenticated` "the join token is not valid"; expired → `Unauthenticated` "the join token has expired: get a new install command in the panel"; parse/verify the CSR (`InvalidArgument`); if used: same `used_key` and not expired and the node's current cert has that public key → return the current cert (no new audit row), else `Unauthenticated` "the join token was used already"; else sign, apply the join transaction, mark used, `limiter succeed`, audit `node.join` (target `node:<id>`, details `source` = caller IP, `arch`, `version`), `Notify(nodeID)`. Every failure counts against the address. `arch` must be `amd64` or `arm64`, `version` ≤ 64 chars of the version charset; both only recorded.
- [ ] `mgmt_host` fill: only when the node's `mgmt_host` is empty and the caller IP is global unicast and not private, loopback, link-local, CGNAT (`100.64.0.0/10`), documentation or unspecified (IPv4-mapped unmapped first). Otherwise the node keeps an empty `mgmt_host`.
- [ ] `CreateNode` accepts an empty `mgmt_host` (other validation unchanged). The connection manager must not fault a node whose `mgmt_host` is empty: it stays `provisioning`, no `node.error` event, no backoff noise; once a join fills it (or the admin edits it), `Notify` starts the connection. After a join replaces the certificate the manager must dial with the new pin (verify how the runner caches the target; make it re-read on Notify).
- [ ] `MintJoinToken`: 32 bytes from `crypto/rand`, base64url no padding, store hash with `expires_at = now + 24h`, replacing the node's previous row; audit `node.join_token`. Never logs or stores the token.
- [ ] Bundle download for a node whose `key_enc` is NULL: keep 409, message "the node joined with a key of its own, so the panel has no bundle for it; get a new install command instead".
- [ ] Tests (table-driven, real store in a temp dir): mint → join → cert matches CSR key, `key_enc` NULL, fingerprint updated, token used, audit row with source; retry with same CSR returns same cert; other CSR with used token refused; expired; unknown; limiter locks after 5 failures from one address and not another; `mgmt_host` fill rules; delete node cascades the token; connmgr leaves an empty-host node `provisioning`.
- [ ] `bash scripts/wsl 'go test ./internal/pki/... ./internal/panel/...'`, `bash scripts/race.sh` for the touched packages, lint clean.
- [ ] Commit: `feat(panel): join tokens and JoinService for nodes that bring their own key`.

---

### Task 1b: Panel: `CreateJoinToken`, the node image and the rendered command

**Files:**
- Modify: `proto/postern/panel/v1/nodes.proto`, `internal/version/version.go`, `cmd/panel/{serve.go,main.go}` (+ tests), `internal/panel/server/server.go` (Config), `internal/panel/nodes/{service.go,kit.go or a new installcmd.go}` (+ tests), `deploy/panel/{compose.yaml,compose_test.sh,README.md,Dockerfile}`, generated code.

**Interfaces:**
- Produces: `NodeService.CreateJoinToken(CreateJoinTokenRequest{node_id, panel_url}) → CreateJoinTokenResponse{token, expires_at (Unix seconds, int64), docker_command, compose_yaml, image}`; `GetNodeInstallResponse.node_image` (resolved reference, empty when none); Go helpers `nodes.RenderDockerCommand(image, panelURL, token string) string` and `nodes.RenderCompose(image, panelURL, token string) string` producing exactly the Global Constraints text; `nodes.CheckPanelURL(string) (string, error)` (normalises: lower-case scheme/host, strips a trailing `/`).
- Consumes: `MintJoinToken` (Task 1a).

**Requirements:**
- [ ] `version.NodeImage` string var (ldflag); env `POSTERN_NODE_IMAGE` parsed in `configFromEnv` like the others (empty = unset), validated, named in the usage text (the usage tests enforce it), carried in `server.Config.NodeImage`; resolution rules exactly as Global Constraints.
- [ ] `deploy/panel/Dockerfile`: `ARG NODE_IMAGE=` added to the ldflags of the panel build (`-X .../version.NodeImage=${NODE_IMAGE}`); `deploy/panel/compose.yaml` passes `POSTERN_NODE_IMAGE: ${POSTERN_NODE_IMAGE:-}` into the container; `compose_test.sh` updated; panel README env table documents it.
- [ ] `CreateJoinToken`: admin only; `FailedPrecondition` without an image; `InvalidArgument` for a bad `panel_url`; mints (Task 1a), renders both texts, returns them. The token appears only in this response.
- [ ] Render tests: golden strings for both texts; quoting is safe because URL and token charsets exclude `'`, `"`, space and `\` (assert the validators guarantee it).
- [ ] `bash scripts/wsl 'go test ./cmd/panel/... ./internal/panel/... ./internal/version/...'`, `bash deploy/panel/compose_test.sh` (as CI runs it), lint clean.
- [ ] Commit: `feat(panel): CreateJoinToken renders the one-command node install`.

---

### Task 2: Node: `postern-node bootstrap`

Read facts §2, §3 and Risks 1–4, 10, 15 first.

**Files:**
- Create: `internal/node/bootstrap/{bootstrap.go,env.go,join.go,layout.go,seed.go,sysctl.go,self.go}` (+ tests), `cmd/node/bootstrap.go`.
- Modify: `cmd/node/main.go` (subcommand + usage), `internal/dockerapi/{types.go,client.go}` (+ tests: `ContainerSpec.Privileged`, `Client.Info` → `SecurityOptions`, whatever one-shot run/wait support the helper needs), `internal/node/agent/{run.go,update_edge.go}` (the `edge-handoff-unsafe` and related messages: "re-run install.sh, or restart the node container (`docker restart postern-agent`) on a node installed with Docker").

**Interfaces:**
- Consumes: `panelv1connect.NewJoinServiceClient` (Task 1a), `pki` bundle format (`bundle.json`, `ca.pem`, `node.pem`, `node-key.pem`), `agent.RunnerImage`, `version.Version`.
- Produces: `bootstrap.Run(ctx, Options) error` that ends in `syscall.Exec` of `<home>/bin/launcher.sh agent`; `Options` carries home, the image binary/signature/launcher paths, env, a Docker client interface and a clock, so tests run without Docker or root.

**Requirements (in execution order):**
- [ ] **Environment:** running as root; `POSTERN_HOME` absolute; Docker answers (`Ping`); `Info.SecurityOptions` has no `name=userns` (refuse: "Docker remaps user namespaces; the node needs a daemon without userns-remap"). Find the own container (container id from `/proc/self/mountinfo` paths `/containers/<64 hex>/`), inspect it: the mount whose destination is `POSTERN_HOME` must have the same source path (refuse otherwise, explaining `-v /opt/postern:/opt/postern`); `/var/run/docker.sock` mounted; restart policy `unless-stopped` or `always` (warn otherwise: self-update needs it). When the own container cannot be found, warn and go on.
- [ ] **Layout:** create the directories and modes of `install.sh make_layout` (facts §3); never loosen modes of existing dirs.
- [ ] **Join decision:** parse `POSTERN_JOIN` when set (rules in Global Constraints; errors never print the token). Join when (a) `pki/` is incomplete, or (b) a token is given whose SHA-256 differs from `data/state/join-token.sha256`. Otherwise skip. Unset `POSTERN_JOIN` with incomplete `pki/` → exit 1 with "no keys yet: start the container with POSTERN_JOIN from the panel".
- [ ] **Join:** if `data/run/join/token.sha256` matches the token, reuse `data/run/join/key.pem`; else generate ECDSA P-256, write both (0600) before any network call. CSR with CN `postern-node`. Connect client to `<base>/api` (HTTP/1.1 or 2, system roots, TLS ≥ 1.2, `Proxy: nil`, 30 s per call); retry network errors and `Unavailable` 5 times with 2/4/8/16 s backoff; do not retry other codes. Validate the response (`node_id` matches `^[0-9A-Z]{26}$`, port 1..65535, PEMs parse, the certificate's public key equals ours, it chains to `ca_pem`). Write `pki.new-<pid>` (0700) with the four files (0600; `bundle.json` byte-identical to what `pki.Bundle` produces), then swap: an existing `pki` becomes `pki.old` (replacing an older `pki.old`), `pki.new-*` becomes `pki`. State: if `data/state/node-id` exists, differs, and `data/state` holds anything else → move `data/state` to `data/state.bak-<unix>` (suffix `-1`, `-2` … if taken); write `node-id`; write `join-token.sha256`; remove `data/run/join/`.
- [ ] **Join failure:** with a complete `pki/` → `slog.Warn` the error and continue with the old keys; without → exit 1 (Docker restarts the container).
- [ ] **Seed:** image binary (= resolved `os.Executable()`), its `.minisig` when present, and the image's `launcher.sh`. Install `bin/postern-node-<version>` (0755, staged in `bin/` then renamed; same name + different SHA-256 → warn and do not switch). `bin/current` absent → point it at the image version. Present → compare versions (reuse the module's semver comparison; a non-semver version only ever fills an absent `current`); image newer → `previous` = old `current`, `current` = image version (relative symlinks, atomic like `install.sh set_link`); otherwise keep. Signature kept as `bin/.postern-node-<version>.minisig` (0644). `bin/launcher.sh` (0755, atomic) is replaced when `current` is absent or when the image version is ≥ the version `current` points to. Never touch `data/run/launcher/*`.
- [ ] **Sysctls:** compute in Go (unit-tested) the union of the current `net.ipv4.ip_local_reserved_ports` (read from `/proc/sys`) with `20000-40999` and the file text of `install.sh reserved_ports_file` (its header names "the Postern node (bootstrap or install.sh)"; the `tcp_migrate_req = 1` line only when `/proc/sys/net/ipv4/tcp_migrate_req` exists). If the running values already match and the file is known identical, do nothing. Else run a one-shot container: runner image (pull when missing), `Privileged`, host network, bind `/etc/sysctl.d:/host/etc/sysctl.d`, a short `sh -c` script that writes the file through a temp file + `mv` only when it differs and runs `sysctl -w` for each key, values passed by env; wait ≤ 30 s, collect its log, remove it. Any failure is a `slog.Warn`, never fatal. Name `postern-sysctl-<8 hex>`, labels `postern.managed=true`, `postern.role=helper` (no `postern.generation`, so the reconciler ignores it; check `takeover/legacy.go` and the inventory treat it as Postern's).
- [ ] **Exec:** `syscall.Exec(<home>/bin/launcher.sh, ["launcher.sh","agent"], env without POSTERN_JOIN)`.
- [ ] `bootstrap` given extra args is a usage error; `postern-node version` keeps working.
- [ ] Tests: env parsing (good/bad URLs, http loopback only, token charset/length, token never in errors); join client against an `httptest` TLS server implementing `JoinServiceHandler` (success, retry on 503, no retry on Unauthenticated, lost-response retry reuses the key, response validation failures); pki writing and swap; state move-aside; seed matrix (absent current, older, newer, equal, non-semver, same-name-different-content); launcher replacement rule; sysctl union and file text (golden vs `install.sh`'s output for the same input — run `install.sh`'s functions in a shell test or copy their expected text); the helper spec (privileged, binds, labels) through a fake Docker; own-container check through a fake mountinfo + inspect. Tests must not need root or Docker.
- [ ] `bash scripts/wsl 'go test ./internal/node/... ./internal/dockerapi/... ./cmd/node/...'`, race for touched packages, lint clean.
- [ ] Commit(s): `feat(node): bootstrap joins the panel, lays out /opt/postern and starts the launcher` (+ a separate `feat(dockerapi): ...` commit is fine).

---

### Task 3: Node image, release and CI

**Files:**
- Create: `deploy/node/Dockerfile`.
- Modify: `.dockerignore` (admit what the node build needs), `scripts/release.sh` (ldflag `version.NodeImage` from env `POSTERN_NODE_IMAGE` when set) and its tests, `.github/workflows/release.yml` (build job env; image job builds + pushes the node image when `vars.POSTERN_NODE_IMAGE` is set), `.github/workflows/ci.yml` (image job builds the node image from source and checks it), `scripts/release/integration_test.go` (node image from `dist`), `docs/releasing.md`.

**Requirements:**
- [ ] Dockerfile mirrors the panel's binary stages: `PREBUILT=` empty → build `./cmd/node` for `$TARGETARCH` from source in the same pinned golang image the panel Dockerfile uses, with `VERSION`/`COMMIT`/`DATE` args and an optional `EXTRA_PUBLIC_KEYS` arg (`-X .../release.extraPublicKeys=`, for e2e); `PREBUILT=<dir>` → copy `<dir>/postern-node-linux-${TARGETARCH}` and its `.minisig` when present (the build must not fail when it is absent). Final stage `FROM` the runner image digest; files at the Global Constraints paths (binary and launcher 0755, signature 0644), labels (the three postern labels + `org.opencontainers.image.{source,version,revision}` from args), `ENV POSTERN_HOME=/opt/postern`, `ENTRYPOINT`/`CMD` as in Global Constraints. Verify that the base image holds a CA bundle the Go TLS client finds (`/etc/ssl/certs/ca-certificates.crt`); if not, install `ca-certificates` pinned.
- [ ] `release.yml`: the build job passes `POSTERN_NODE_IMAGE: ${{ vars.POSTERN_NODE_IMAGE }}` so the panel binary defaults to it; the image job, after the panel image, builds `--platform linux/amd64,linux/arm64 --build-arg PREBUILT=dist -f deploy/node/Dockerfile` with the same tag rule (`:<tag>`, `:latest` only for the newest non-prerelease) and pushes; skipped (with a printed line) when the variable is empty. The panel image job keeps working when only one of the two variables is set.
- [ ] `ci.yml` image job: build the node image from source (`--build-arg VERSION=v0.0.0-ci`), `docker run --rm <img> version` prints that version, `docker image inspect` shows the entrypoint, cmd, labels and env.
- [ ] Release integration test: build the node image from `dist` and assert the binary and `.minisig` in it equal the `dist` files, modes as above.
- [ ] `docs/releasing.md`: the variable, the second image, its tags, the order (both images before publish).
- [ ] Local check (WSL Docker): build from source for the host arch, run `version`; run `bootstrap` in a throwaway container with a temp `POSTERN_HOME` bind and no `POSTERN_JOIN` → exits 1 with the "no keys yet" message. Record the commands and outputs in the report.
- [ ] Commit: `feat(release): the node image, built and pushed with the panel image`.

---

### Task 4: Web UI: the one-command install

**Files:**
- Create: `web/src/components/NodeDockerInstall.tsx` (+ test), `web/src/app/panelUrl.ts` (+ test).
- Modify: `web/src/components/{NodeCreateDialog,NodeInstallSteps,NodeForm}.tsx` (+ tests), `web/src/pages/{NodeDetail,NodeFacts}.tsx` (+ tests), `web/src/app/bundle.ts` (+ test), `web/src/api/hooks/{nodes.ts,keys.ts}`, `web/src/test/fakeInventory.ts`, `web/src/i18n/{ru,en}.json`, generated TS.

**Requirements:**
- [ ] `NodeDockerInstall` (props: node id): shows the panel-URL field ("Адрес панели для нод" / "Panel address for nodes"), prefilled from `localStorage` (try/catch) or `window.location.origin`, validated like `CheckPanelURL` (https, or http on loopback) with an inline error; a button "Получить команду" / "Get the command" that calls `CreateJoinToken`; then tabs `docker run` / `compose.yaml` with `CommandLine` copy blocks of the server-rendered texts, the expiry ("действует до <время>, один раз"), a hint that getting a new command cancels the previous one, and the firewall reminder with the node's management port (or the hidden-mode alternative). When `GetNodeInstall.node_image` is empty: a short note that the panel has no node image (`POSTERN_NODE_IMAGE`) and that the methods below still work.
- [ ] `NodeCreateDialog` after creation and the install section of `NodeDetail` show `NodeDockerInstall` first; the SSH button stays; the kit/bundle steps (`NodeInstallSteps`) move into a collapsed block "Без Docker-реестра: архив и бандл" / "Without a registry: kit and bundle". The command is fetched only on the button, never automatically (a token per page view would be noise in the audit).
- [ ] `NodeForm` on create: `mgmtHost` optional, hint "Можно оставить пустым: панель возьмёт адрес, с которого нода подключится." / English equivalent; edit keeps it required.
- [ ] `ROLL_EDGE_COMMAND` becomes `sudo sh -c 'date +%s > /opt/postern/data/run/roll-edge'` (works for both install styles); strings that say "re-run install.sh" also name `docker restart postern-agent` for Docker nodes.
- [ ] Tests (vitest + Testing Library, fakes in `web/src/test`): URL validation table; the button mints and shows both tabs; no image → note; dialog/detail layout; form create without host. `npm run lint`, `npm run typecheck`, `npm test` in `web/` pass.
- [ ] Commit: `feat(web): install a node with one Docker command`.

---

### Task 5: SSH install runs the command

Read facts §4 first.

**Files:**
- Modify: `proto/postern/panel/v1/deploy.proto` (`InstallRequest.panel_url`, `PreflightRequest.panel_url`), `internal/panel/deploy/{service.go,install.go,report.go,preflight.go,install_docker.sh}` (+ tests incl. `fakehost_test.go`), `web/src/pages/NodeInstall.tsx`, `web/src/components/deploy/*` (+ tests), `web/src/test/fakeDeploy.ts`, i18n, generated code.

**Requirements:**
- [ ] Path choice: the docker path when the panel has a node image and `panel_url` passes `CheckPanelURL`; otherwise the kit path, unchanged. The report states the path.
- [ ] Docker-path preflight: `compose_missing`, `bash_missing` and `kit_missing` are not blockers; `arch_unsupported` still is (amd64/arm64); the rest unchanged; `install_docker.sh` does not fail the job when it cannot add Compose on this path.
- [ ] Docker-path job: connect → check → (Docker setup if asked) → "Removing an old agent container" (`docker rm -f postern-agent` when it exists; the compose project of a kit install is left on disk) → mint a token → "Starting the node" (the rendered `docker run`, with the long timeout because of the pull) → wait online (unchanged). The token is a job secret (redacted in the log). Audit `node.install` as before.
- [ ] UI wizard: the same remembered panel-URL field (reuse `panelUrl.ts`), sent with preflight and install; copy explains the path.
- [ ] Tests: fake-host runs of both paths, redaction of the token, preflight issue sets per path. Go + web suites pass; lint clean.
- [ ] Commit: `feat(deploy): the SSH install starts the node with the Docker command`.

---

### Task 6: e2e for the docker path and the docs

Read facts §8 first.

**Files:**
- Modify/Create: `scripts/e2e.sh` (+ `e2e_test.sh`), `test/e2e/` (a new `docker_join_test.go` and helpers), `docs/testing/e2e.md`, `deploy/node/README.md`, `docs/testing/smoke-remote.md`.

**Requirements:**
- [ ] `scripts/e2e.sh` builds the node image from the e2e node binary (a temp context with `postern-node-linux-<arch>`, `PREBUILT`, tag `postern-node:e2e-<run>`), exports `POSTERN_E2E_NODE_IMAGE`, launches the panel with `POSTERN_NODE_IMAGE` set to it, and its cleanup removes the image and any `postern-sysctl-*` leftovers.
- [ ] Test: create a node (mgmt host `127.0.0.1`), `CreateJoinToken` with `http://127.0.0.1:<panel port>`, assert the rendered command's flags, start the container with the equivalent spec (POSTERN_HOME under the work dir bound at the same path), wait online, assert: bundle download → 409 (`key_enc` NULL), one `node.join` audit row, `/proc/sys/net/ipv4/ip_local_reserved_ports` covers 20000-40999, the agent runs `bin/current` = the image version; restart the container → still online, still one `node.join`; mint a new token for the same node and recreate with it → re-joins (two rows), same node id, proxies (if the test adds one) keep their link. Respect `checkNoOtherNode` ordering.
- [ ] `deploy/node/README.md`: "Install with one Docker command" becomes the first section (the command, compose variant, the token, the panel URL rule, firewall or hidden mode, re-enrolment with a new token, moving a kit node to Docker: `docker compose -f /opt/postern/compose.yaml down` then the command, uninstall); the kit section is "Without a registry". `smoke-remote.md` gets the docker path.
- [ ] `bash scripts/e2e_test.sh` passes; the full e2e is run by the controller on the test server (record the command for it in the report).
- [ ] Commit(s): `test(e2e): install a node with the Docker command`, `docs(node): the one-command install first`.
