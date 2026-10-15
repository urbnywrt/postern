# Postern Slice 5 (Versions and Updates) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Engine and egress binaries come from a tracked, verified catalog with `latest` and `stable` channels; telemt (and mtg, Xray, warp-plus) is updated on every node with one action through a canary rollout (one proxy → its node → every other node) that cancels a failed step by itself and drops no connection; a proxy switches between telemt and mtg on the fly with the same link; the agent, the edge and the panel update themselves from signed releases and fall back when the new version fails; a node may fetch its artifacts itself.

**Architecture:** The panel tracks upstream releases (GitHub or Gitea REST API, paged, with ETag), verifies them (built-in pins, GitHub asset digests, upstream checksum files or trust on first use, our signed `engines-stable.json`, a static-ELF check) and keeps them; every node trial-runs an artifact in the runner image before it uses it. A proxy's engine version follows its node's channel unless pinned, and a channel version moves only when a rollout completes. The rollout runner writes the target into the panel's data step by step, lets the node's existing blue-green do the change, verifies it from the node's reports and reverts a failed step. mtg is a second engine driver behind the same edge, so a switch is one more blue-green. Postern's own binaries are signed with minisign under two key sets (releases, stable list): the agent installs a signed binary and restarts through its launcher, the edge rolls to it by the existing two-generation handoff, and the panel installs its new binary in its data volume and restores its database snapshot when its launcher rolls it back.

**Tech Stack:** Go 1.27, `aead.dev/minisign` v0.3.0, `debug/elf`, GitHub and Gitea REST APIs, mtg v2.2.8 release binaries, the packages of slices 1–2, React UI.

**Spec:** `docs/design/2026-10-04-postern-design.md` §7 (updates and versions, including the "node downloads by itself" option), §5.5 (engines, mtg, blue-green), §5.2 (agent), §6 (`UpdateSelf`, `UpdateEdge`, `UploadArtifact`, the previous-minor window), §8.3 (versions screen, «работает»/«должна быть», filter «устарел», bulk engine/version), §12 (releases, the scheduled stable job), §13 (slice 5), §14, §15 item 3 (mtg).

## Findings carried into this slice

- **F1 — telemt has no version flag.** telemt 3.5.13 parses `start|stop|reload|status|run|healthcheck` and ignores unknown flags, so `telemt --version` would run with `./config.toml` (https://github.com/telemt/telemt/blob/3.5.13/src/cli.rs, verified 2026-10-05). The trial uses `telemt healthcheck --mode liveness <missing file>`, which prints `[telemt] healthcheck failed: config load failed: …` and exits 1 (https://github.com/telemt/telemt/blob/3.5.13/src/healthcheck.rs; 3.5.12 has the same file, verified 2026-10-05). → Tasks 3a, 16.
- **F2 — the edge handoff drops queued connections.** `Edge.Drain` closes its listeners and keeps the connections it accepted, so a held connection survives a roll whatever the kernel does. Connections still in the accept queue of the closing listener, and half-open handshakes, are aborted unless `net.ipv4.tcp_migrate_req = 1` (default 0, Linux ≥ 5.14) moves them to another listener of the `SO_REUSEPORT` group (https://docs.kernel.org/networking/ip-sysctl.html, https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SK_REUSEPORT/, verified 2026-10-05). → Task 6b (install.sh sets it, the agent warns), Task 14 (an accept-queue flood at 1 and at 0).
- **F3 — rollouts need truthful, structured reports.** `ProxyStatus` says why an upgrade was aborted only in free text, its `engine` is the desired proxy's engine (`proxyStatus` in `internal/node/reconcile/reconciler.go`), so after a failed telemt→mtg switch it says mtg while telemt serves, and egress provider instances report no version. → Task 5.
- **F4 — a rolled-back panel cannot open its database.** `store.Open` refuses a database that a newer version migrated, so after the launcher rolls a failed panel update back the old binary would crash-loop. → Task 11b keeps a `VACUUM INTO` snapshot taken before the update and restores it.
- **F5 — released panels would have no UI and an unsigned, stale kit.** `internal/panel/webui/dist` holds only the committed placeholder (the Dockerfile builds `web/` first), the Dockerfile builds an unsigned `postern-node`, and a panel that updates its binary in `/data/bin` keeps serving the image's older kit. → Task 2 (the release build includes the UI; release images carry the signed binaries), Task 12 (the kit follows the running panel version).
- **F6 — mtg v2.2.8 fronts to an IP only, through its proxies.** `[domain-fronting]` takes `ip`, `port`, `proxy-protocol` (a `host` key exists only on mtg's master branch) (https://github.com/9seconds/mtg/blob/v2.2.8/example.config.toml, verified 2026-10-05), and with `[network] proxies` set every TCP connection of the proxy goes through them: `makeNetwork` joins one SOCKS network per entry (https://github.com/9seconds/mtg/blob/v2.2.8/internal/cli/run_proxy.go, verified 2026-10-05). The edge's SOCKS port refuses loopback and private destinations, so such a mask target can never work. → Tasks 4, 5.
- **F7 — mtg downloads a block list at start by default.** `[defense.blocklist] enabled = true` with the FireHOL list in v2.2.8's example config (same URL). → Task 4 turns it off.
- **F8 — GitHub polling.** 60 requests per hour per IP without a token, and a 304 is free only for authorized requests (https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api, https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api, verified 2026-10-05). Verified 2026-10-05 against `https://api.github.com/repos/XTLS/Xray-core/releases`: the list ETag is weak (`W/"…"`) and changed between two requests seconds apart; an unauthenticated `If-None-Match` got a 304 that still lowered `X-RateLimit-Remaining`; the first page (30 by default) held 23 prereleases and 7 releases, with `Link: rel="next"`. → Task 8a pages, keeps the raw ETag and never relies on 304.
- **F9 — Gitea attachments differ from GitHub assets.** A Gitea release attachment has `id`, `name`, `size`, `download_count`, `created_at`, `uuid`, `browser_download_url` and no digest; lists page with `Link` and `X-Total-Count` (https://gitea.com/api/v1/repos/gitea/tea/releases?limit=1, verified 2026-10-05). → Tasks 8a, 11a, 15.
- **F10 — a generation is pushed once.** connmgr builds and pushes a desired generation once (`session.sync`), and `recheckArtifacts` only uploads at each resync; it never re-pushes. A state that leaves an artifact out stays without it. → Task 9 always names pinned versions.
- **F11 — telemt closes an idle client after 60 s.** A fake-TLS client that sends nothing after its handshake is dropped at `telemtIdle` (60 s, `test/e2e/e2e_test.go`). → Task 14 opens held connections right before each change.
- **F12 — "the agent answers" is not "the agent is healthy".** The agent serves gRPC before its first reconcile pass writes the launcher's healthy marker (`internal/node/agent/run.go`), and the launcher resets its failure counter whenever the previous start wrote the marker (`deploy/node/launcher.sh`). → Tasks 6a, 12: a node update succeeds only on the marker.

## Rulings

- Ruling: a channel version moves only when a rollout completes — §12 "кнопкой"; a channel that moved by itself would roll the fleet without a canary — cost: one click per update; nothing starts automatically.
- Ruling: a failed step reverts only itself and stops the rollout; earlier steps keep the target — §0.2 keeps only cancelling the failed update — cost: mixed versions until Retry or Abort.
- Ruling: engine switches, single and bulk, are `switch` rollouts — §5.5 has one blue-green mechanism, and switches get canary and automatic cancel — cost: a one-proxy switch is a one-step rollout.
- Ruling: the trial runs on the node; the panel checks checksums and the static ELF — the panel has no Docker and runs as the UID that reads `master.key` — cost: a trial failure that is the node's fault marks a non-built-in version unusable for its arch until Recheck (only trials that ran count; a built-in pin only gets a note).
- Ruling: self-update replaces only the binary; a node never goes above the panel's version nor below its previous minor; the panel never downgrades itself (by hand: remove `/data/bin/current`) — §7 "Спутников и сборок нет", §6 window — cost: a release that changes `launcher.sh` needs install.sh; F2 needs an install.sh re-run on existing nodes.
- Ruling: rollouts need capability `rollout-status` — cost: slice-1 nodes need one install.sh update first.
- R5-1: "node downloads by itself" (§7 option) is Task 6c: node setting `artifact_source = panel | direct` (default `panel`), `ArtifactRef.url` only for `direct`, the same pin and trial, fallback to the panel's upload — cost: one small task.
- R5-2: "no downtime" is proven by held connections opened right before each change, L2 sessions online, an accept-queue flood at `tcp_migrate_req` 1 (no failure) and at 0 (failures expected), and the 250 ms L1 prober — cost: a longer e2e.
- R5-3: a node update step succeeds only when `GetInfo` shows the running process wrote its healthy marker for the target version; `agent_rolled_back` or an agent restart during the step or the following pause fails it; an agent without its marker after 10 min exits so the launcher counts the start — cost: a slow first pass may cost a start.
- R5-4: built-in pins always win: a disagreeing stable-list or checksum-file entry is rejected with `release_checksum_mismatch`, and the built-in asset's state is never changed by another source — cost: a wrong built-in pin needs a panel release.
- R5-5: hooks for slice 6: `Hooks{BeforeStep, AfterStep func(ctx, *store.Rollout, *store.RolloutStep) error}`; a step's timeout starts after `BeforeStep` returns; `AfterStep` also runs after a failed step was reverted, its error ignored, the step status `reverted` — cost: none.
- R5-6: two key sets (release keys for `postern-node`, `postern-panel`, `sha256sums`; stable keys for `engines-stable`), the key picked by the signature's key id inside the component's set, `extraPublicKeys` ignored once production keys exist (reported as a warning), a stable-sign job apart from the e2e in a protected environment, rotation and compromise procedures, and no node downgrade except an explicit rollback to the recorded previous version — cost: two keys to keep.
- R5-7: at most one active rollout per (component, channel) for `version` rollouts and at most one active rollout per node, both enforced by partial unique indexes in the creating transaction; active = preparing, running, paused, failed; `started_at` persisted and kept on resume; a stored generation 0 re-runs Apply; Check judges only reports with `applied_generation` ≥ the step's generation and fails at once on that generation's `state_rejection`; a skipped node's and a disabled proxy's items are pinned at their previous version when the rollout completes; an empty step completes once its generation is applied — cost: an operator unpins those few items later.
- R5-8: Tasks 3, 6, 8, 10, 11 and 13 are split in two (a/b); `lane/s5-base` merges into dev twice — cost: more reviews.
- R5-9: field numbers are taken now and listed under Global Constraints (Numbers) with the ones to renumber at merge; migrations take the next free number at implementation time — cost: renumbering at merge.

## Order and lanes

Slices 0–1 are on `dev`. Slice 2 (lane/s2) is finishing (its Tasks 7–8); slices 3 (lane/s3-web, lane/s3-acme) and 4 (lane/s4, Tasks 5–7 blocked on 2 and 3) merge later. `lane/s5-base` merges into dev twice: after Task 8b (Task 9 needs it) and after Task 11b (Task 12 needs it). `lane/s5-node` merges after Task 6b (Task 12 needs it); Task 6c follows on that lane once Task 9 is on dev. `lane/s5-panel` may merge after Task 9 so that Task 6c can start.

| Task | Lane (base) | Starts | Waits for | Shares files with |
|---|---|---|---|---|
| 1 release library | `lane/s5-base` (dev) | now | — | — |
| 7 store + VersionService contract | `lane/s5-base` | after 1 | 1 | migrations (s2 `0003_egress` uncommitted in its worktree, s4 `0003–0005`, s6 `0003_insights`); `internal/panel/server/api.go` (s4) |
| 8a feeds, checksums, Prepare | `lane/s5-base` | after 7 | 1, 7 | new package |
| 8b tracker, stable list, catalog API | `lane/s5-base` | after 8a | 8a | `internal/panel/server` (s4) — first merge of lane/s5-base |
| 11a Postern source, cache, upload | `lane/s5-base` | after 8b | 8b | `internal/panel/server` |
| 11b panel self-update, recovery | `lane/s5-base` | after 11a | 11a | `cmd/panel`, `internal/panel/server`, `internal/panel/store/store.go`, `deploy/panel/README.md` (Task 2, s4) — second merge |
| 2 release workflow, signed kit | `lane/s5-ci` (lane/s5-base after 1) | after 1 | 1 | `deploy/panel/Dockerfile`, `deploy/panel/README.md` (11b), `.github/workflows/ci.yml` (s4, Tasks 14, 15) |
| 4 mtg driver | `lane/s5-mtg` (dev) | now | — | — |
| 3a trial runs, upload | `lane/s5-node` (dev after slice 2 merges, + lane/s5-mtg + Task 1) | after slice 2 merge | slice 2, 4 | agent `server.go`/`info.go`, node.proto (s3, s4) |
| 3b reconcile usability, artifact GC | `lane/s5-node` | after 3a | 3a | reconcile (s3 T3, s4 T6) |
| 5 mtg proxies, version reports | `lane/s5-node` | after 3b | 3b, 4 | `validate.go`, reconcile, node.proto |
| 6a UpdateSelf | `lane/s5-node` | after 5 | 1, 5 | agent, `cmd/node`, node.proto, `deploy/node/README.md` (s2, s4) |
| 6b UpdateEdge, safe handoff | `lane/s5-node` | after 6a | 6a | `edgemgr.go`, `install.sh`, `deploy/node/README.md` — lane/s5-node merges |
| 6c node downloads by itself | `lane/s5-node` (merge dev with Task 9 first) | after 6b and Task 9 on dev | 3a, 3b, 9 | statebuilder, panel nodes, node settings |
| 9 versions in the desired state | `lane/s5-panel` (dev after slice 2 and the first lane/s5-base merge) | after those merges | 7, 8a, 8b, slice 2 T7 | statebuilder, proxies service/catalog/ingest (s3 T4, s4) |
| 10a runner, engine version rollouts | `lane/s5-panel` | after 9 | 9 | `internal/panel/server` |
| 10b switch and provider rollouts | `lane/s5-panel` | after 10a | 10a | — |
| 12 node and edge updates | `lane/s5-panel` | after 10b, the lane/s5-node merge and the second lane/s5-base merge | 6a, 6b, 10a, 11a, 11b | `internal/panel/nodes` kit/connmgr, s4 deploy (if merged) |
| 13a Versions page | `lane/s5-panel` | after 12 | 8b, 10a, 10b, 11a, 11b, 12 | web (s2 T7 UI, s3 T4, s4) |
| 13b proxy, node and overview views | `lane/s5-panel` | after 13a | 9, 10b, 12, 13a | web |
| 14 e2e | dev | after every slice-5 lane merges | all | `test/e2e`, `scripts/e2e.sh`, `ci.yml` |
| 15 stable channel job | dev | after 14 | 2, 14 | CI |
| 16 real-server check | controller | last | all | — |

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply verbatim (module, WSL runner, commits without trailers, hygiene, runner image digest, labels, port ranges, timeouts), with one addition: `postern.role` also takes `trial`. Where a task changes code of slice 2, 3 or 4, that slice's Global Constraints apply to it too.
- **Components** (`{n}` is the version without a leading `v`; the version string is the upstream tag as published, so mtg, Xray and warp-plus keep their `v`):

  | Component | Repo | Tag | amd64 asset | arm64 asset | Checksums | Binary (archive member) | Trial |
  |---|---|---|---|---|---|---|---|
  | telemt (engine) | `telemt/telemt` | `3.5.13` | `telemt-x86_64-linux-musl.tar.gz` | `telemt-aarch64-linux-musl.tar.gz` | `<asset>.sha256` (`<hex>  <file>`) | `telemt` (member path: implementer verifies against the archive) | `healthcheck --mode liveness /nonexistent/config.toml` → exit 1, output starts `[telemt] healthcheck failed: config load failed` |
  | mtg (engine) | `9seconds/mtg` | `v2.2.8` | `mtg-{n}-linux-amd64.tar.gz` | `mtg-{n}-linux-arm64.tar.gz` | `mtg-{n}-checksums.txt` (sha256sum format) | `mtg` (`mtg-{n}-linux-<arch>/mtg`) | `--version` → exit 0, output contains `{n}` (full text: implementer verifies against upstream) |
  | xray (provider) | `XTLS/Xray-core` | `v26.3.27` | `Xray-linux-64.zip` | `Xray-linux-arm64-v8a.zip` | `<asset>.dgst`, line `SHA2-256= <hex>` | `xray` (member path: implementer verifies) | `version` → exit 0, output starts `Xray {n} (` |
  | warp-plus (provider) | `bepass-org/warp-plus` | `v1.2.6` | `warp-plus_linux-amd64.zip` | `warp-plus_linux-arm64.zip` | `<asset>.dgst` | `warp-plus` (member path: implementer verifies) | `version` → exit 0, output contains `{n}` (printed to stderr; exact text: implementer verifies) |

  Sources, all verified 2026-10-05: https://api.github.com/repos/telemt/telemt/releases/tags/3.5.13 and `/tags/3.5.12` (musl assets and `.sha256` files); https://api.github.com/repos/9seconds/mtg/releases/latest, https://github.com/9seconds/mtg/blob/v2.2.8/.goreleaser.yml (CGO_ENABLED=0, `wrap_in_directory`), https://github.com/9seconds/mtg/blob/v2.2.8/internal/cli/cli.go (kong `VersionFlag`, `run <config-path>`); https://github.com/XTLS/Xray-core/releases/tag/v26.3.27 (`.dgst` has `MD5=`, `SHA1=`, `SHA2-256=`, `SHA2-512=` lines), https://github.com/XTLS/Xray-core/blob/v26.3.27/core/core.go (`VersionStatement`: `Xray <version> (<codename>) …`); https://github.com/bepass-org/warp-plus/blob/v1.2.6/cmd/warp-plus/versioncmd.go (`fmt.Fprintf(os.Stderr, …)`). Built-in pins (the stable channel before any signed list; GitHub asset digests, equal to the upstream checksum files): telemt 3.5.13 as in slices 0–1; mtg v2.2.8 amd64 `7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102`, arm64 `562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644`; xray v26.3.27 amd64 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`, arm64 `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c`; warp-plus v1.2.6 amd64 `380d2c8655b33db818adf407c706d52d14c2ab1764e702e91f356a7d7d9c3c98`, arm64 `c0b430c117eaa33513fa012aca983303ee88a4bda0f935dc62ff016109e492f3` (slice 2's catalog pins must agree).
- **mtg v2.2.8 config** (https://github.com/9seconds/mtg/blob/v2.2.8/example.config.toml, verified 2026-10-05): top-level `debug`, `secret` (written as `ee`-prefixed hex), `bind-to` (literal IP), `proxy-protocol-listener` (PROXY v1 and v2), `concurrency`, `prefer-ip` (`prefer-ipv6|prefer-ipv4|only-ipv6|only-ipv4`), `auto-update`, `tolerate-time-skewness` (example `"5s"`), `allow-fallback-on-unknown-dc`; `[domain-fronting] ip, port, proxy-protocol`; `[network] dns` (`""` = default resolver), `proxies` (socks5 URIs only); `[network.timeout] tcp, http, idle, handshake`; `[defense.anti-replay]`; `[defense.blocklist]`, `[defense.allowlist]`; `[defense.doppelganger] urls, repeats-per-raid, raid-each, drs`; `[stats.statsd]`; `[stats.prometheus] enabled, bind-to, http-path, metric-prefix`. mtg has no ad tag and no middle proxy.
- **Signing.** `aead.dev/minisign` v0.3.0 (MIT; `GenerateKey`, `Sign`/`SignWithComments`, `Verify` checks the key id, the signature and the global signature over the trusted comment, legacy `Ed` and prehashed `ED`; https://pkg.go.dev/aead.dev/minisign, verified 2026-10-05). Trusted comment: `postern <component> <version>` plus ` <os>/<arch>` for binaries (`postern postern-node v0.5.0 linux/amd64`). Two key sets: release keys sign `postern-node`, `postern-panel`, `sha256sums`; stable keys sign `engines-stable` (its version is the list's `generated_at` in Unix seconds); a signature by a key of the other set is refused. Production keys are committed by the owner into `internal/release/keys.go`; `-ldflags -X github.com/urbnywrt/postern/internal/release.extraPublicKeys=<key>[,<key>]` adds test keys to a set only while that set's production keys are empty, and a binary built with ignored extra keys reports the warning `test-release-keys-ignored` (in use: `test-release-keys`). Our signatures are prehashed. Every verifier outside `internal/release` takes its keys through a field `Keys func(release.KeySet) ([]minisign.PublicKey, error)` (nil = `release.TrustedKeys`) and verifies with `release.VerifyWith`, so tests inject generated keys. No secret key ever enters the repository, a log or a test fixture; tests generate keys at run time (Ruling S4-5). Rotation and compromise follow `docs/releasing.md` (Task 2).
- **Release assets** of a Postern tag `vX.Y.Z`: `postern-node-linux-amd64`, `postern-node-linux-arm64`, `postern-panel-linux-amd64`, `postern-panel-linux-arm64`, each with `<file>.minisig`; `SHA256SUMS` + `SHA256SUMS.minisig`; `postern-vX.Y.Z-bundle.tar` (all of these). The signed stable list is the asset `engines-stable.json` (+ `.minisig`) of the release with tag `engines-stable` in the Postern repository.
- **`engines-stable.json`:** `{"schema":1,"generated_at":<unix>,"components":{"<component>":[{"version":"<tag>","assets":{"amd64":{"file":"…","sha256":"…"},"arm64":{…}}}]}}`. A list older than the applied one, or with `generated_at` more than 5 min ahead of the panel's clock, is refused. A version that a newer list no longer names loses its stable flag (the release row stays; built-in pins stay stable).
- **Checksum rules (engines, providers).** Per asset: (1) a built-in pin is the expected SHA-256 and always wins: a stable-list or checksum-file entry that disagrees is rejected with event `release_checksum_mismatch` (error), and no other source changes the built-in asset's state; (2) otherwise a GitHub API `digest` (`sha256:<hex>`, https://github.blog/changelog/2025-06-03-releases-now-expose-digests-for-release-assets/, verified 2026-10-05), when present, is the expected SHA-256, and the component's checksum file, when present, must agree; (3) without a digest (Gitea, older releases) the checksum file is the expected SHA-256; (4) only when both are absent is the first download that passes extraction and the static check pinned (TOFU). A stable-list entry that disagrees with (2)–(4) makes the asset unusable with the event. A download that fails verification is neither kept nor pinned. A pinned SHA-256 never changes. Only static binaries are taken: ELF64 little-endian, `EM_X86_64` for amd64 or `EM_AARCH64` for arm64, type EXEC or DYN, no `PT_INTERP`.
- **Trial runs** (spec §7, F1): on the node, container `postern-trial-<binary>-<8 hex>` from the runner image, the binary bound read-only at `/opt/engine/<binary>`, user `65534:65534`, network `none`, read-only root, `cap_drop: ALL`, `no-new-privileges`, 64 MiB, 16 pids, log `json-file` 1m × 1, no restart policy, labels `postern.managed=true`, `postern.role=trial`; 10 s to exit; stdout and stderr read together, at most 4 KiB kept; pass = the component's exit code and output (table above). Only a trial that ran counts: the container started and exited, or Docker refused to start it for an exec error of the binary (exec format error, missing interpreter, no such file). An orphan trial container is one not in the running trial set of its agent and older than 2 × the timeout. The node binary is tried by running `<file> version` in the agent container (stdout starts with `<version> (`); the panel binary likewise in the panel container.
- **Channels.** `stable` = built-in pins ∪ signed stable list; `latest` = `stable` ∪ every non-draft upstream release, by the release's upstream `prerelease` flag (never inferred from the tag): prereleases only when setting `releases.include_prereleases` is on. A node follows `nodes.engine_channel`, or the panel default `versions.default_channel` (`stable`) when empty; changing either needs a confirmation when it changes the effective version of any proxy. A proxy whose `engine_version_policy` is `channel` runs the channel version of its engine on its node's channel (table `engine_channels`, seeded with the built-in versions); `pinned` runs `engine_version`; `rollout` runs `engine_version` while a rollout holds it. A provider on a node runs `nodes.provider_versions[<component>]` while set, else its channel version. A channel version moves only when a rollout completes. A version is named in a desired state as soon as it has a pinned SHA-256 for the node's arch, ready or not; readiness gates only the upload.
- **Rollouts.** Kinds: `version` (an engine or provider channel to a version), `switch` (selected proxies to an engine, optionally pinned to a version; also the bulk engine/version action), `node` (agent and/or edge of nodes). Active statuses: `preparing`, `running`, `paused`, `failed`. At most one active `version` rollout per (component, channel) and at most one active rollout of any kind per node, enforced by partial unique indexes in the transaction that creates the rollout. Steps: engines and switches — the canary proxy, then the rest of its node, then every other node by name; providers and `node` — the canary node, then every other node. Each step: `BeforeStep` hook → Apply (write the target into the panel's data, bump the node's generation, notify; the step's generation is stored) → Check from the node's reports → `AfterStep` hook → then wait `pause_seconds` (mode `auto`, default 120 s) or stop in `paused` until Continue (mode `manual`). The step's timeout runs from when `BeforeStep` returns: engines 2 min + 2 min per item, at most 60 min; providers 10 min; node 10 min for the agent (5 min upload, 5 min until healthy) + 3 min for the edge. Check judges only a state report whose `applied_generation` ≥ the step's generation; the node's `state_rejection` of that generation fails the step at once; an empty step is done once its generation is applied. A failed step is reverted (its items back to what they were), `AfterStep` still runs (error ignored), the step ends `reverted` and the rollout `failed`; earlier steps keep the target; Retry re-runs the failed step; Abort reverts every applied step. `started_at` is stored and kept when a panel restart resumes a step; a stored generation 0 means Apply runs again. A disabled proxy's item, and every item of a node skipped as offline (`skip_offline`; a node offline for more than 5 min during its step fails it otherwise), stays on its previous version (`deferred`) and is pinned at that version when the rollout completes. A failed upgrade is never retried by the panel on its own. Rollouts need node capability `rollout-status`.
- **Self-update.** Exit code 75 means "restart me with the new binary": `postern-node agent` and `postern-panel serve` exit with it after a successful install, and Docker (`restart: unless-stopped`, https://docs.docker.com/engine/containers/start-containers-automatically/, verified 2026-10-05) starts the launcher again. Binaries are `bin/postern-node-<version>` / `/data/bin/postern-panel-<version>` with relative `current` and `previous` symlinks switched by rename, as the launchers do. Version strings pass `release.ValidVersion`. A node update succeeds when the node's `GetInfo` shows that the running process wrote its healthy marker (`healthy`) with `agent_version` = the target (F12); an agent that has not written its marker 10 min after start exits with code 1, so the launcher counts the start. A node is never updated past the panel's version nor below the panel's previous minor; a node binary older than the running one is installed only with an explicit rollback flag to the node's recorded previous version. The panel updates itself only to a newer version, and only while no node's agent is older than the minor before that version (spec §6 window). Only the binary is replaced: `launcher.sh` and `compose.yaml` change only with install.sh.
- **HTTP.** Release traffic of the panel and of nodes that download for themselves: `https://` only (redirects too), `http://` only to a loopback host (tests); dial and TLS 15 s, headers 30 s, a whole download 5 min; `User-Agent: postern-<panel|node>/<version>`; `HTTPS_PROXY` honoured; request headers never logged; Go's default stripping of `Authorization` on a redirect to another host is kept (no `CheckRedirect` re-adds it), and a token is sent only to the host it belongs to. GitHub: API base from env `POSTERN_GITHUB_API` (default `https://api.github.com`), headers `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, optional `Authorization: Bearer <token>`; lists `per_page=100`, following `Link: rel="next"`; the raw ETag (with `W/`) stored per exact URL and sent as `If-None-Match`; a 304 is an optimization and never needed for correctness (F8); every API request goes through one limiter (without a token at most 50 an hour in all); on 403/429 wait for `Retry-After` or `X-RateLimit-Reset`. Gitea: `<base>/api/v1/repos/<owner>/<repo>/releases?limit=50` paged by `Link`, `Authorization: token <token>` (https://docs.gitea.com/development/api-usage, verified 2026-10-05), bytes from `browser_download_url` with the same token, no digest, and of two attachments with one name the newest `created_at` wins. Limits: feed page 4 MiB, checksum and signature files 64 KiB, release notes 64 KiB, archives 200 MiB, extracted binaries 256 MiB, an uploaded bundle 256 MiB. Tokens are sealed in settings (AAD `setting:<key>`), write-only in the API, never logged; URLs are logged without query and userinfo.
- **Node capabilities added:** `artifact-trial` (Task 3a), `engine-mtg`, `rollout-status` (Task 5), `update-self` (6a), `update-edge` (6b), `artifact-direct` (6c). The panel refuses what a node cannot take with "upgrade node <name> to use <feature>" (Ruling 43).
- **Hooks for slice 6** (R5-5): `rollout.Hooks{BeforeStep, AfterStep func(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error}`; none are set in this slice; slice 6 runs its diagnostics there.
- **Numbers** (R5-9; renumber at merge where noted). node.proto: `ArtifactRef.state = 8`, `state_reason = 9`; `UploadArtifactResponse.usable = 3`, `reason = 4`, `tried = 5`; `ProxyStatus.failed_engine = 7`, `failed_version = 8`; `StateReport.egress_instances = 5`; `GetInfoResponse.binaries = 11`, `healthy = 12`, `warnings = 13` (slice 6 takes 14–15); `NodeSettings.artifact_source = 7` (slice 2 has `dns_mode = 6`); `NodeBinary.rollback = 6`. Panel protos, taken today on dev and skipping what slice 4 holds on lane/s4 (`Proxy` 17, `CreateProxyRequest` and `UpdateProxyRequest` 10): `ProxyStatus.running_engine = 6`, `failed_version = 7` (1–5 are taken); `Proxy.version_source = 18`, `Proxy.channel = 19`; `CreateProxyRequest.engine = 11`; `ListProxiesRequest.engine = 3`, `outdated = 4`. These tasks start after slice 2 merges, and slice 2's Task 7 is adding proxy and node fields now: any of these numbers it took moves to the next free one, and the `Node` fields of Tasks 9, 6c and 12 take the next free numbers on that base. Store migrations: the next free number at implementation time (taken today: dev 0001–0002; s2 `0003_egress` uncommitted in its worktree; s4 0003–0005; s6 `0003_insights`).

---

### Task 1: Release signatures, key sets, static binaries and versions

**Lane:** `lane/s5-base` from dev, now · **Model:** sonnet

**Files:** Create `internal/release/keys.go`, `sign.go`, `elf.go`, `version.go`, `sums.go`, `export_test.go`, tests `sign_test.go`, `elf_test.go`, `version_test.go`, `sums_test.go`, `fuzz_test.go`, `testdata/cli.pub`, `testdata/cli.msg`, `testdata/cli.msg.minisig`; `go get aead.dev/minisign@v0.3.0`.

**Interfaces (Produces):**

```go
package release
var productionReleaseKeys = "" // newline-separated minisign public keys ("RW…"): postern-node, postern-panel, sha256sums; the owner commits it
var productionStableKeys = ""  // engines-stable only
var extraPublicKeys string     // -ldflags -X …/internal/release.extraPublicKeys=<k>[,<k>]: used for a set only while its production keys are empty
type KeySet int
const ( ReleaseKeys KeySet = iota; StableKeys )
func SetOf(component string) (KeySet, error)
func TrustedKeys(set KeySet) ([]minisign.PublicKey, error) // ErrNoKeys when empty; a bad key is an error naming its position, never the key
func ProductionKeys(set KeySet) []minisign.PublicKey
func KeyWarnings() []string // "test-release-keys" (extra keys in use), "test-release-keys-ignored" (compiled in, ignored)

type Signed struct{ Component, Version, OS, Arch string }
func (s Signed) TrustedComment() string                                                // "postern <component> <version>" + " <os>/<arch>" when Arch != ""
func Verify(r io.Reader, sig []byte, want Signed) error                                // keys = TrustedKeys(SetOf(want.Component))
func VerifyWith(r io.Reader, sig []byte, want Signed, keys []minisign.PublicKey) error // the key whose id is the signature's key id, verified once
func Sign(r io.Reader, priv minisign.PrivateKey, s Signed) ([]byte, error)             // prehashed, untrusted comment "postern release signature"
var ErrNoKeys, ErrUntrustedKey, ErrBadSignature, ErrWrongArtifact error

func CheckStaticELF(r io.ReaderAt, arch string) error // amd64 | arm64
var ErrNotELF, ErrWrongArch, ErrDynamic error

func ValidVersion(v string) bool // ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$
func Compare(a, b string) int    // semver 2.0 after an optional leading "v"
func Newer(a, b string) bool

type SumsFormat int
const ( SumsSHA256 SumsFormat = iota; SumsDgst )
func SumFor(name string, data []byte, f SumsFormat) (sha string, err error) // lower-case hex
var ErrNoSum error
```

**Requirements:** `VerifyWith` parses the signature, takes the key whose id equals its key id (none → ErrUntrustedKey), verifies the signature and the global signature (ErrBadSignature), then the trusted comment (ErrWrongArtifact); prehashed signatures stream, a legacy one is accepted for inputs up to 64 MiB. `Compare`: numeric dot segments (missing = 0), prerelease after `-` lower than the release, prerelease identifiers compared as semver §11 says (numeric ones numerically, so `rc.10` > `rc.2`; alphanumeric by ASCII; a shorter list lower when the rest is equal), build metadata after `+` ignored, a version that does not parse below every one that does and among such by string. Callers decide prerelease status from the upstream flag, never from `Compare`. `SumFor`: `SumsSHA256` reads `<hex>  <name>` and `<hex> *<name>` lines and a file holding only the hex; `SumsDgst` reads the `SHA2-256= <hex>` line; two different sums for one name, or a hex that is not 64 digits, are errors. No error quotes key material.

**Tests:** `TestVerifyRoundTrip` (generated key pair, 1 MiB, `{postern-node, v0.5.0, linux, amd64}`); `TestVerifyPicksKeyByID` (keys [A, B], signed by B → nil); `TestVerifyWrongArtifact` (arm64 or v0.5.1 wanted → ErrWrongArtifact); `TestVerifyTampered` (a data byte, a byte of the trusted comment → ErrBadSignature); `TestVerifyUntrustedKey`; `TestVerifyWrongSet` (an `engines-stable` list signed by a release key, `Verify` → ErrUntrustedKey); `TestExtraKeys` (production set empty → extra keys used and `test-release-keys`; non-empty → ignored and `test-release-keys-ignored`); `TestVerifyMinisignCLIVector` (a public key, a 64-byte message and its `.minisig` made once with the minisign CLI in a throwaway Alpine container, `apk add minisign`, committed under `testdata/` without any secret key; not skippable); `TestTrustedKeys` (malformed → error without the key text, none → ErrNoKeys); `TestCheckStaticELF` with synthetic headers (amd64 ET_EXEC and ET_DYN without PT_INTERP → nil; with PT_INTERP → ErrDynamic; EM_AARCH64 for amd64, ELFCLASS32, big-endian → ErrWrongArch; `#!/bin/sh`, truncated → ErrNotELF; arch `386` → error); `TestCompare` (`3.5.13`>`3.5.12`, `v2.2.8`=`2.2.8`, `3.5.13`>`3.5.13-rc.1`, `1.0.0-rc.10`>`1.0.0-rc.2`, `1.0.0-alpha`<`1.0.0-alpha.1`, `1.0.0-alpha.beta`<`1.0.0-beta`, `v26.3.27`<`v26.10.1`, `3.5`=`3.5.0`, `dev`<`0.0.1`, `1.2.3+b5`=`1.2.3`); `TestValidVersion`; `TestSumFor` (both sha256sum forms, mtg's list picks the right line, missing → ErrNoSum, conflicting → error, single-hex file, a four-line `.dgst` → the SHA2-256, upper-case folded); `FuzzSumFor`, `FuzzCheckStaticELF`.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/release/... && go test -run=^$ -fuzz=^FuzzSumFor$ -fuzztime=15s ./internal/release/ && go test -run=^$ -fuzz=^FuzzCheckStaticELF$ -fuzztime=15s ./internal/release/'` → PASS → commit `feat(release): minisign key sets, static binary check and versions`.

---

### Task 2: Release workflow, signing tool and a signed node kit

**Lane:** `lane/s5-ci` from `lane/s5-base` after Task 1 · **Model:** opus

**Files:** Create `scripts/release/main.go` (+ `main_test.go`), `scripts/release.sh`, `.github/workflows/release.yml`, `docs/releasing.md`; modify `deploy/panel/Dockerfile`, `deploy/panel/README.md`, `.github/workflows/ci.yml` (the panel image job also builds the prebuilt variant).

**Interfaces:** Consumes `release.Sign`, `release.VerifyWith`, `release.Signed`, `release.ProductionKeys`. Produces `go run ./scripts/release <command>`: `keygen --out <dir> [--unencrypted]` (writes `postern-release.key`, encrypted with env `POSTERN_MINISIGN_PASSWORD` unless `--unencrypted`; refuses a directory inside the repository; prints the public key line), `sign --key <file> --component <c> --version <v> [--arch <a>] <file>` (writes `<file>.minisig`), `sums <files…>` (`SHA256SUMS`, sorted), `bundle --version <v> <dir>` (`postern-<v>-bundle.tar`), `changelog --from <tag> --to <tag>` (conventional commits grouped feat/fix/perf/security/other, no trailers), `verify --pubkey <line> --component <c> --version <v> [--arch <a>] <file>`, `keys` (the key ids of both compiled production sets).

**Requirements:**
- `scripts/release.sh <tag>` (needs Go and Node 24: CI, or a container locally): exports the tag into a temporary directory with `git archive` (the working tree is never touched), runs `npm ci && npm run build` in its `web/` and copies `web/dist/.` over its `internal/panel/webui/dist/` (F5), then builds the four binaries there with `CGO_ENABLED=0 -trimpath` and the version ldflags; signs each with the release key (component, tag, `linux/<arch>`), writes and signs `SHA256SUMS` (component `sha256sums`), builds the bundle, verifies every signature with the key's public half; refuses a non-prerelease tag when that key is not in the compiled production release set. For a prerelease tag (a `-` in the version) env `POSTERN_EXTRA_PUBLIC_KEYS` is compiled in as `extraPublicKeys` (test servers); a non-prerelease tag refuses it.
- `release.yml` on tags `v*`: test → `scripts/release.sh` with secrets `POSTERN_RELEASE_KEY` (key file text) and `POSTERN_RELEASE_KEY_PASSWORD` (the release key only; the stable key exists only in the stable job's protected environment) → the release with notes from `changelog` and every asset: on GitHub (`github.server_url == 'https://github.com'`) `gh release create` with `permissions: contents: write`; on Gitea the API (`POST <server_url>/api/v1/repos/<repo>/releases`, then each asset `POST …/releases/<id>/assets?name=<file>`) with `Authorization: token ${{ secrets.GITEA_TOKEN }}` and `permissions: releases: write` (https://docs.gitea.com/usage/actions/token-permissions, verified 2026-10-05; the attachment's multipart field name: implementer verifies against upstream) → the multi-arch panel image built with `--build-arg PREBUILT=dist`, pushed to repo variable `POSTERN_IMAGE` (`<tag>`, and `latest` for non-prereleases). Secrets never echoed.
- Dockerfile: with `PREBUILT=<dir>` the image takes `postern-panel-linux-$TARGETARCH` and `postern-node-linux-{amd64,arm64}` with their `.minisig` byte for byte (no Go build) and the kit gets `<arch>/postern-node.minisig`; without it the image builds from source as today (the UI first; an unsigned kit).
- `docs/releasing.md`: two key pairs (release, engines-stable) made outside the repository (`go run ./scripts/release keygen --out ~/.config/postern/<name>`), their CI secrets, and the public lines committed into `internal/release/keys.go`; rotation (release N adds the new key to its set and is signed with the old one; N+1 is signed with the new one; the old key leaves in N+2; the same for the stable key with lists); compromise (publish a release signed with a new key; nodes reinstall with install.sh and the node kit, panels by an image pull, since old binaries cannot verify it); tagging; private Gitea (bundle upload to the panel); panel downgrade by hand (remove `/data/bin/current`); existing nodes re-run install.sh to get `tcp_migrate_req`. The controller does the key steps with the owner, never an implementer.

**Tests:** keygen refuses a path inside the repo and writes an encrypted key that `sign` opens with the password (and refuses without it); sign → `release.VerifyWith`; sums format; bundle members; changelog grouping on a temporary git repository (feat, fix, chore, a commit with a body); `scripts/release.sh v0.0.0-test` with a throwaway key builds `dist/` whose signatures verify with that key, its panel binary, started on a free port, serves at `/` an `index.html` that is not the placeholder, and with `POSTERN_EXTRA_PUBLIC_KEYS` the `-ldflags` that `go version -m` shows carry the key; `scripts/release.sh v0.0.0` with that key is refused; `bash scripts/wsl 'docker build --build-arg PREBUILT=dist -f deploy/panel/Dockerfile .'` → the kit holds the signatures and the binaries hash to the dist files; actionlint and shellcheck clean.

**Steps:** tests → FAIL → implement → PASS → commit `build: signed releases with the UI, release workflow and a prebuilt image kit`.

---

### Task 3a: Node: trial runs and artifact trial records

**Lane:** `lane/s5-node` (dev after slice 2 merges; merge `lane/s5-mtg` and Task 1 in first) · **Model:** opus

**Files:** Create `internal/node/trial/trial.go` (+ tests); modify `internal/artifacts/store.go` (+ tests), `internal/engines/telemt/telemt.go` (Trial), `internal/providers/provider.go`, `internal/providers/xray/xray.go`, `internal/providers/warpplus/warpplus.go` (Trial), `internal/node/agent/server.go` (UploadArtifact, capability `artifact-trial`), `internal/node/agent/info.go` (artifact state); `proto/postern/node/v1/node.proto` (+ regen): `ArtifactRef.state = 8`, `state_reason = 9` (GetInfo only), `UploadArtifactResponse.usable = 3`, `reason = 4`, `tried = 5`.

**Interfaces:** Consumes `internal/engines/trial.go` (made by the mtg driver task): `type Trial struct { Args []string; ExitCode int; Output *regexp.Regexp }` (nil Output: anything) and `type Trialer interface { Trial(version string) Trial }`; `dockerapi.Client` (`Logs` returns stdout and stderr as one stream); `artifacts.Store.Put`. Produces:

```go
package trial
type Runner struct { Docker dockerapi.Client; RunnerImage string; Timeout time.Duration; Log *slog.Logger }
type Result struct { Ran, OK bool; ExitCode int; Output, Reason string } // Ran false: nothing to judge (Docker unreachable, image missing, a create error that is not the binary's)
func (r *Runner) Run(ctx context.Context, binaryPath, binaryName string, t engines.Trial) Result
func (r *Runner) InFlight() map[string]bool // names of this runner's trial containers that are running

package artifacts
type TrialRecord struct { OK bool `json:"ok"`; Reason string `json:"reason,omitempty"`; At time.Time `json:"at"`; Image string `json:"image"` }
func (s *Store) RecordTrial(ref Ref, rec TrialRecord) error // <dir>/.trial, atomic
func (s *Store) Trial(ref Ref) (TrialRecord, bool)
func (s *Store) Remove(ref Ref) error
func (s *Store) List() []Ref
```

**Requirements:**
- Trial container and pass rules per Global Constraints (Components, Trial runs). The runner pulls the runner image when missing, polls `Inspect` until the container exits, keeps ≤ 4 KiB of the combined log as valid UTF-8, always removes the container. The agent makes one `Runner` and shares it between UploadArtifact and the reconciler, so `InFlight` covers every trial of the node. telemt, xray and warp-plus get `Trial` methods with the table's invocations.
- `UploadArtifact`: after `Put`, run the trial of the driver or provider named by `ref.Engine`. Ran → record it and answer `stored=true, tried=true, usable=<OK>, reason`. Not ran → answer `stored=true, tried=false, usable=false, reason="trial not run: …"` and record nothing (the panel uploads again later and marks nothing).
- `GetInfo.artifacts[].state`: `""` (usable), `untried` or `unusable`, with `state_reason` (≤ 256 bytes).
- Capability `artifact-trial`.

**Tests:** runner with `dockerapi.Fake`: exit code mismatch, output mismatch, an exec-format start error → Ran and not OK; Docker unreachable or image pull failure → not Ran; timeout → killed, Ran, not OK; the container removed in every case; the log options on the spec; 4 KiB clip; InFlight while running. Store: trial record round trip, Remove refuses invalid refs, List. Agent over TLS: passing fake trial → usable; failing → stored, tried, unusable with the reason; not ran → tried false, nothing recorded. Integration (`integration`, real Docker): telemt 3.5.13 musl → OK; telemt 3.5.13 `x86_64-linux-gnu` (checked against its `.sha256`) → Ran, not OK (no glibc loader in Alpine); mtg v2.2.8, xray v26.3.27, warp-plus v1.2.6 → OK (record each output in the report: it settles the table's "implementer verifies" items).

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/artifacts/... ./internal/node/... ./internal/engines/... ./internal/providers/...'` + integration → PASS → commit `feat(node): trial runs of artifacts in the runner image`.

---

### Task 3b: Node: artifact usability in reconcile and garbage collection

**Lane:** `lane/s5-node` after Task 3a · **Model:** opus

**Files:** Modify `internal/node/reconcile/instances.go`, `egress.go` (usability), `internal/dockerapi/types.go`, `client.go`, `fake.go` (`ContainerDetails.Binds` from `HostConfig.Binds`), tests; create `internal/node/reconcile/artifactgc.go` (+ tests).

**Interfaces:** Consumes `artifacts.Store` (`Has`, `Trial`, `RecordTrial`, `Remove`, `List`), `trial.Runner` (`Run`, `InFlight`, `Result{Ran, OK, Reason}`), the engines' and providers' `Trial(version)`. Produces `dockerapi.ContainerDetails.Binds []string`.

**Requirements:**
- An artifact counts as present only when `Has` and its trial record says OK. One without a record (stored before this slice) is tried in the pass before a new generation needs it; a trial that did not run leaves it untried and the start of that generation fails for this pass with `artifact not tried yet: …`. An unusable one fails the proxy or egress start with `artifact unusable: <engine> <version> for <arch>: <reason>` (event `artifact_unusable`). Serving generations are never touched.
- GC at most once an hour after a pass: remove artifacts not named by the desired state, not mounted by any container labelled `postern.managed=true` (inspect `Binds`), not in a runtime record, and not among the 2 most recently used versions of their engine and arch (by the time of their last trial or upload); `.stage-*` dirs older than 1 h; event `artifact_removed`. Orphan trial containers (Global Constraints) are removed at start and by every pass; a trial that UploadArtifact is running is never one.

**Tests:** reconcile with fakes: an untried artifact tried once then used; a trial that did not run → start fails this pass, tried again next pass; unusable → FAILED with the reason while a serving generation stays; GC keeps desired, mounted, recorded and the 2 newest, removes the rest and old stage dirs; an in-flight trial container survives the orphan sweep, an old one is removed; `Binds` from the fake and from a canned inspect answer.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/... ./internal/dockerapi/...'` → PASS → commit `feat(node): use only tried artifacts and collect old ones`.

---

### Task 4: mtg driver

**Lane:** `lane/s5-mtg` from dev, now · **Model:** opus

**Files:** Create `internal/engines/trial.go`, `internal/engines/mtg/mtg.go`, `internal/engines/mtg/config.go`, `internal/engines/mtg/mtg_test.go`, `internal/engines/mtg/testdata/faketls.toml`, `internal/engines/mtg/integration_test.go` (tag `integration`).

**Interfaces:** Consumes `engines.Driver`, `engines.Instance`, `dockerapi.ContainerSpec`, `artifacts.Store`, `probe.FakeTLS`, `socks5.Server`, `links.FakeTLSSecret` (slice 1). Produces:

```go
package engines
type Trial struct { Args []string; ExitCode int; Output *regexp.Regexp }
type Trialer interface { Trial(version string) Trial }

package mtg
const DefaultVersion = "v2.2.8"
func New() *Driver                                   // engines.Driver + engines.Trialer
func AssetName(version, arch string) (string, error) // mtg-{n}-linux-<amd64|arm64>.tar.gz
// ArtifactFile(arch) = AssetName(DefaultVersion, arch); BinaryName() = "mtg"; Supports: FAKETLS only
```

**Requirements:**
- `Render` → `config.toml`, exactly: `debug = false`, `secret = "ee" + secret + lower-hex(UTF-8 domain)` (the link's secret, byte for byte), `bind-to = "127.0.0.1:<ListenPort>"`, `proxy-protocol-listener = true`, `concurrency = 8192`, `prefer-ip = "prefer-ipv4"`, `auto-update = false`, `tolerate-time-skewness` = the client clock skew that telemt 3.5.13 accepts for the fake-TLS timestamp (implementer verifies against upstream, records the value and its source in a comment; if telemt's window cannot be found, `"5s"` and say so in the report), `allow-fallback-on-unknown-dc = false`; `[domain-fronting] port` (443 or the override's port), `ip` only when `mask_target_override` is an IP literal (F6); `[network] dns = ""` (the container's resolver, which the agent points at the edge's DNS forwarder as for telemt), `proxies = ["socks5://127.0.0.1:<SocksPort>"]`; `[network.timeout]` as the v2.2.8 example; `[defense.anti-replay] enabled = true`; `[defense.blocklist] enabled = false` (F7); `[defense.allowlist] enabled = false`; `[defense.doppelganger] urls = []`; `[stats.statsd] enabled = false`; `[stats.prometheus] enabled = true, bind-to = "127.0.0.1:<APIPort>", http-path = "/", metric-prefix = "mtg"`. Refused with a message and no secret: a type other than fake TLS, an ad tag, the middle proxy, engine overrides other than `{}`, a NAT IP, a mask target that is a host name ("mtg v2.2.8 fronts to an IP address only"), a mask IP that is loopback, private (RFC 1918, unique local), link-local, CGNAT or unspecified (F6: mtg reaches it through the edge's SOCKS port, which refuses it), a secret that is not 32 hex, a bad domain or port.
- `Container`: `postern-eng-<lower id>-g<N>`, runner image, `65534:65534`, host network, read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp` 16m, binds `<BinaryPath>:/opt/engine/mtg:ro` and `<InstanceDir>:/etc/mtg:ro`, entrypoint `/opt/engine/mtg run /etc/mtg/config.toml`, 256 MiB, 256 pids, logs 5m×2, restart `unless-stopped`, the engine labels.
- `Ready`: TCP connect to `127.0.0.1:<ListenPort>` (2 s), then `GET http://127.0.0.1:<APIPort>/` (no proxy, no redirects, 5 s, body ≤ 1 MiB) answers 200.
- `Trial(version)`: `--version`, exit 0, output contains the version without `v`.
- Record in the report what the v2.2.8 source shows for: `dns = ""` (default resolver), whether mtg logs the secret, and what `--version` prints.

**Tests:** golden config (`-update`); refusal per rule (incl. masks `127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `169.254.1.1`, `100.64.0.1`, `::1`, `fd00::1` — test-only special-use addresses, Ruling 24); the config secret equals `links.FakeTLSSecret(secret, domain)` for ASCII, upper-case, trailing-dot and IDN (UTF-8) domains — the real proof that a switch keeps the link; mask override `192.0.2.10:8443` → ip/port, `example.com` → refused; container spec; AssetName per arch and an unknown arch. Integration: mtg v2.2.8 for `runtime.GOARCH` from GitHub (pinned SHA-256) through `artifacts.Store.Put`, run with `mtg run` and the rendered config in the runner image on free ports with an in-process SOCKS5 recorder as the upstream: `Ready` within 30 s; `probe.FakeTLS` with a PROXY v2 header (src `127.0.0.1:1`) and the right secret → nil; a wrong secret → error, and the recorder sees mtg's fronting CONNECT to the proxy's mask override `192.0.2.1:443` (answered "host unreachable"); the container listens on exactly the two ports; its log holds no secret; the trial passes.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/engines/...'` + integration → PASS → commit `feat(engines): mtg driver`.

---

### Task 5: Node: mtg proxies, engine switches and version reports

**Lane:** `lane/s5-node` after Task 3b · **Model:** opus

**Files:** Modify `internal/node/state/validate.go` (+ tests), `internal/node/agent/run.go` (register `mtg.New()`), `internal/node/agent/server.go` (capabilities), `internal/node/reconcile/instances.go`, `egress.go`, `reconciler.go`, tests, `internal/engines/mtg/integration_test.go` (the online L2 subtest); `proto/postern/node/v1/node.proto` (+ regen): `ProxyStatus.failed_engine = 7`, `ProxyStatus.failed_version = 8`, `StateReport.egress_instances = 5` with `message EgressInstanceStatus { string egress_id = 1; string provider = 2; string version = 3; uint64 generation = 4; string phase = 5; string reason = 6; string failed_version = 7; }`.

**Interfaces:** Consumes `mtg.New()` (fake TLS only; refuses an ad tag, the middle proxy, overrides, a NAT IP, a mask target that is not a public IP literal), the reconciler's blue-green, failure memory (`failures[id]`), egress records, `probe.L2` (slice 2). Produces the report fields above and capabilities `engine-mtg`, `rollout-status`.

**Requirements:**
- Validation: `ENGINE_MTG` accepted for fake TLS only (WEB stays telemt); refused with an ad tag (existing message), `use_middle_proxy`, non-empty engine overrides ("telemt overrides do not apply to mtg"), a `nat_ip`, a mask target that is not an IP literal, and a mask IP that is loopback, private, link-local, CGNAT or unspecified (F6: always, whatever any test found). Drop the "mtg arrives in slice 5" refusal.
- An engine change is a new instance hash, so the existing blue-green does the switch: the new generation runs on the other driver beside the old one, passes readiness, the L1 probe and the slice-2 gate, then the route moves and the old one drains. Edge routes, SOCKS ports, the domain and the secret do not change. The resolv.conf mount of engine containers applies to mtg as to telemt; the middle-proxy code (NAT IP, `me_addrs`) never sees mtg proxies.
- `ProxyStatus.engine` is the engine of the serving instance (its runtime record); the desired engine only when nothing serves (F3). `running_version` stays the serving instance's.
- `failed_engine`/`failed_version`: set while any attempt at the proxy's current desired instance has been aborted (readiness, probe, gate, container start, render, a missing, untried or unusable artifact), to that instance's engine and version; cleared when the desired instance serves or the desired hash changes. `reason` keeps its text. The reconciler forgets a proxy's failed attempt (its retry backoff) as soon as the desired hash changes, so a rollout that reverted a step and is retried gets a fresh attempt at once; the 5-minute backoff applies only while the desired state stays on the failed target.
- `egress_instances`: one per provider egress: serving generation and version, phase `serving|starting|failed|draining`, reason, `failed_version` as for proxies.

**Tests:** validation table (mtg + WEB, ad tag, middle proxy, overrides, NAT IP, mask name, private and loopback masks, `192.0.2.10:8443` ok, plain mtg ok); reconcile with fakes: telemt → mtg makes generation N+1 from the mtg driver's spec (entrypoint `/opt/engine/mtg run …`), the route moves only after ready and probe, N drains; a failing mtg generation keeps telemt serving and reports `engine=ENGINE_TELEMT`, `failed_engine=ENGINE_MTG`, `failed_version=v2.2.8`, cleared after the desired state returns to telemt; going back to mtg right after is attempted at once; a version change reports the new `failed_version`; `egress_instances` report the serving version and a failed provider version; capabilities sorted. Online (`integration`, `POSTERN_E2E_ONLINE=1`): `probe.L2` through a real mtg v2.2.8 container to DC2 with an in-process SOCKS upstream that dials out.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/...'` → PASS → commit `feat(node): mtg proxies, engine switches and version reports`.

---

### Task 6a: Node: UpdateSelf

**Lane:** `lane/s5-node` after Task 5 · **Model:** opus

**Files:** Create `internal/node/selfupdate/install.go`, `gc.go`, tests; modify `proto/postern/node/v1/node.proto` (+ regen), `internal/node/agent/server.go` (UpdateSelf, GetInfo fields, capability `update-self`), `internal/node/agent/run.go` (restart path, healthy reporting, marker deadline), `cmd/node/agent.go` (exit 75), `deploy/node/launcher.sh` (header comment only), `deploy/node/README.md`, tests.

**Interfaces:** Consumes `release.VerifyWith` (`Signed{postern-node, <version>, linux, <arch>}`, release key set), `release.TrustedKeys`, `release.CheckStaticELF`, `release.ValidVersion`, `release.Compare`, `release.KeyWarnings`, `dockerapi.ContainerDetails.Binds` (Task 3b), the agent's healthy marker (`healthMarker.written`). Produces:

```proto
rpc UpdateSelf(stream UpdateSelfRequest) returns (UpdateSelfResponse);
message UpdateSelfRequest { oneof part { NodeBinary meta = 1; bytes chunk = 2; } }
message NodeBinary { string version = 1; string arch = 2; string sha256 = 3; uint64 size = 4; string signature = 5; bool rollback = 6; } // signature: the .minisig text
message UpdateSelfResponse { string version = 1; bool restarting = 2; }
message NodeBinaries { repeated string versions = 1; string current = 2; string previous = 3; }
// GetInfoResponse: NodeBinaries binaries = 11; bool healthy = 12 (this process wrote the launcher's healthy marker); repeated string warnings = 13 (codes)
```

```go
package selfupdate
type Installer struct { Home, Arch, Running string; Keys func(release.KeySet) ([]minisign.PublicKey, error); Exec func(ctx context.Context, path string, args ...string) ([]byte, error) }
func (i *Installer) Install(ctx context.Context, meta *nodev1.NodeBinary, r io.Reader) (changed bool, err error)
func Binaries(home string) *nodev1.NodeBinaries
func GC(home string, keep func(path string) bool) (removed []string)
```

**Requirements:**
- `Install`: version valid, arch = `runtime.GOARCH`, size ≤ 200 MiB; a version older than `Running` is refused unless `rollback` is set and it is `bin/previous`'s target; an existing `bin/postern-node-<v>` with other content is refused ("version <v> exists with other content"); streams to `bin/.postern-node-<v>.tmp-*`, checks size and SHA-256, the signature and trusted comment, the static ELF, and `<tmp> version` printing `<v> (`; renames to `bin/postern-node-<v>` (0755); points `previous` at `current`'s old target and `current` at the new file (relative links made beside and renamed over). Nothing is left behind on failure; `changed=false` when `current` already points at that version. No release key compiled in → FailedPrecondition "this node build trusts no release key".
- `UpdateSelf` codes: InvalidArgument (meta), PermissionDenied (signature, downgrade without rollback), FailedPrecondition (ELF, trial, other content), ResourceExhausted (size), Unavailable (another UpdateSelf running). On `changed=true`: event `agent_updating` (from, to), answer `restarting=true`, then stop the reconciler at its next step boundary and the server (as SIGTERM does) and return `agent.ErrRestart`; `postern-node agent` exits 75.
- `GetInfo.healthy`: true once this process wrote its healthy marker (F12). An agent that has not written its marker 10 min after it started logs why and exits with code 1, so the launcher counts the start.
- `GetInfo.warnings`: `release.KeyWarnings()` codes (the edge task adds `edge-handoff-unsafe`).
- Binary GC at start and after every UpdateSelf: keep `current`, `previous`, the agent's own executable and every binary a container labelled `postern.managed=true` mounts (inspect `Binds`); remove the others while more than 3 versions remain, never a kept one.
- Docs (`launcher.sh` header, `deploy/node/README.md`): the launcher's counter resets whenever the previous start wrote the marker, so a binary that writes the marker and crashes later is never rolled back by the launcher (the panel's node update fails such a step: an agent restart during the step or its pause); a downgrade is only the rollback to `bin/previous`.

**Tests:** Installer (fake `Exec`, synthetic static ELF, generated keys through `Keys`): untrusted key, wrong arch in the trusted comment, SHA-256 mismatch, oversize, dynamic ELF, a trial that prints another version, an older version without rollback, a rollback to something other than `previous`, an existing file with other content → refused and nothing changed; success → links and mode; rollback to `previous` → swapped; same version → unchanged. Agent over TLS: success → response, then `Run` returns ErrRestart (exit 75 in the `cmd/node` test); chunk before meta → InvalidArgument; oversize → ResourceExhausted; a concurrent call → Unavailable; `healthy` false before the first pass, true after; the marker deadline (fake clock) exits with 1. GC keeps mounted binaries and never removes a kept one.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/... ./cmd/node/...'` → PASS → commit `feat(node): self-update of the agent from signed binaries`.

---

### Task 6b: Node: UpdateEdge and a safe edge handoff

**Lane:** `lane/s5-node` after Task 6a · **Model:** opus

**Files:** Modify `proto/postern/node/v1/node.proto` (+ regen), `internal/node/agent/server.go` (UpdateEdge, capability `update-edge`, warning `edge-handoff-unsafe`), `internal/node/reconcile/edgemgr.go`, `internal/node/state/runtime.go` (`EdgeBinaries map[uint64]string`), `deploy/node/install.sh`, `deploy/node/install_test.sh`, `deploy/node/README.md`, tests.

**Interfaces:** Consumes the reconciler's edge roll (Ruling 44: a new generation beside the running one, drain of the old), `bin/postern-node-<version>` files (installed by UpdateSelf or install.sh), `GetInfoResponse.warnings`. Produces:

```proto
rpc UpdateEdge(UpdateEdgeRequest) returns (UpdateEdgeResponse);
message UpdateEdgeRequest { string version = 1; }
message UpdateEdgeResponse { uint64 generation = 1; string version = 2; }
```

**Requirements:**
- `UpdateEdge(v)`: needs `bin/postern-node-<v>` (regular, executable) whose `version` prints `v (`; hands the reconciler a roll request with that path and waits ≤ 120 s: the new generation answers Health with version `v` → its generation; a roll that fails leaves the old generation serving and answers Aborted with the reason (event `edge_roll_failed`). The running edge already on `v` and healthy → no roll. A second call while a roll runs → Unavailable.
- The reconciler records each edge generation's binary in `EdgeBinaries`; a generation it makes for another reason (a crash, a capability change, the start-up invariants) takes the binary of the generation it replaces when `EdgeBinaries` has it, else the agent's own; the file-based roll (Ruling 44) uses the agent's own binary as today.
- F2: install.sh writes `net.ipv4.tcp_migrate_req = 1` into `/etc/sysctl.d/90-postern.conf` next to the reserved ports and applies it with `sysctl -w` (a kernel without it, < 5.14, is a warning); the agent reads `/proc/sys/net/ipv4/tcp_migrate_req` at start, adds `edge-handoff-unsafe` to `GetInfo.warnings` and records the event `edge_handoff_unsafe` once per start when it is not 1. README: existing nodes re-run install.sh to get it.

**Tests:** UpdateEdge with a fake reconciler: success, Aborted, missing binary, a binary that prints another version, same version, concurrent call. Reconcile: a roll request puts the given binary in the new edge's bind; `EdgeBinaries` survives an agent restart; a generation made after a crash reuses the replaced generation's binary. `install_test.sh`: the sysctl line written and applied; a missing key warns and exits 0. Agent: the warning with a fake `/proc` value of 0. Integration (`integration`, real Docker): two builds of `cmd/node` (v9.9.8, v9.9.9); an edge on v9.9.8 rolls to v9.9.9 through UpdateEdge while a relayed connection (a stranger SNI on a listener whose stranger action masks to a local echo server) exchanges a byte every second across the roll without a break.

**Steps:** proto + regen → tests → FAIL → implement → race + `bash scripts/wsl 'sh deploy/node/install_test.sh'` + integration → PASS → commit `feat(node): edge rolls to a version and a safe handoff`.

---

### Task 6c: Node downloads artifacts itself

**Lane:** `lane/s5-node` after Task 6b, once Task 9 is on dev (merge dev in first) · **Model:** sonnet

**Files:** Node: create `internal/node/reconcile/download.go` (+ tests); modify `internal/node/reconcile/instances.go`, `egress.go` (download before a start needs the artifact), `internal/node/state/validate.go` (`artifact_source` values), `internal/node/agent/server.go` (capability `artifact-direct`); `proto/postern/node/v1/node.proto` (+ regen): `NodeSettings.artifact_source = 7`. Panel: store migration `00NN_artifact_source.sql` (next free number; `ALTER TABLE nodes ADD COLUMN artifact_source TEXT NOT NULL DEFAULT 'panel'`), `internal/panel/store/nodes.go`, `proto/postern/panel/v1/nodes.proto` (`Node.artifact_source`, `UpdateNodeRequest.artifact_source`, next free numbers) + regen, `internal/panel/nodes/service.go`, `internal/panel/proxies/statebuilder.go`, `internal/panel/proxies/catalog.go` (EnsureArtifacts), `web/src/pages/NodeDetail.tsx` (a select) + i18n RU/EN; tests.

**Interfaces:** Consumes `artifacts.Store.Put` (verifies the pinned SHA-256), `trial.Runner.Run`, the agent's resolver (slice 2), `ArtifactRef.url` (field 6, exists), the panel's state builder and `EnsureArtifacts(ctx, nodeID, info, state, client)`, connmgr's resync (`recheckArtifacts`, every 5 min). Produces the setting and capability.

**Requirements (R5-1):**
- `artifact_source` is `panel` (default, also when empty) or `direct`; `direct` needs capability `artifact-direct`. The state carries `NodeSettings.artifact_source` and fills `ArtifactRef.url` only for `direct` nodes.
- Node, `direct`: an artifact the state names that is missing (not unusable) is downloaded from its `url` before a new generation needs it: HTTP rules of the Global Constraints (`https` only, `http` only to loopback for tests), ≤ 200 MiB, at most 2 downloads at a time, no new try of a URL within 10 min after its failure; streamed into `Put` with the pinned SHA-256, then the same trial as an upload. Any failure → event `artifact_download_failed` (URL without query) and the artifact stays missing.
- Panel: for a `direct` node, EnsureArtifacts uploads nothing when it pushes a generation; at the next resync it uploads what the node still lacks, as for any node.

**Tests:** node: a download with the right SHA-256 → stored and tried; a wrong SHA-256 → missing + event, retried after 10 min (fake clock); an `http://` non-loopback URL refused; a redirect to `http` refused; oversize refused; `panel` mode never downloads. Panel: `url` only for direct nodes; EnsureArtifacts skips the push-time upload for a direct node and uploads at recheck; the capability gate; the select round-trips in the UI test.

**Steps:** proto + regen → tests → FAIL → implement → PASS → commit `feat(node): artifacts downloaded by the node itself, with the panel as fallback`.

---

### Task 7: Panel: version store and the VersionService contract

**Lane:** `lane/s5-base` after Task 1 · **Model:** sonnet

**Files:** Create `internal/panel/store/migrations/00NN_versions.sql` (NN = next free number), `internal/panel/store/releases.go`, `channels.go`, `rollouts.go`, tests; modify `internal/panel/store/nodes.go`, `proxies.go` (`EnginePolicyRollout = "rollout"`), `settings.go` (typed helpers), `sealed.go` (`HasSealedData` counts the sealed release tokens); create `proto/postern/panel/v1/versions.proto` (+ regen Go and TS), `internal/panel/versions/service.go` (every RPC Unimplemented through the embedded handler, admin required), wiring in `internal/panel/server/api.go`.

**Interfaces (Produces):** the schema

```sql
ALTER TABLE engine_releases ADD COLUMN tag TEXT NOT NULL DEFAULT '';
ALTER TABLE engine_releases ADD COLUMN prerelease INTEGER NOT NULL DEFAULT 0 CHECK (prerelease IN (0, 1));
ALTER TABLE engine_releases ADD COLUMN source TEXT NOT NULL DEFAULT 'upstream'; -- builtin | upstream | stable | upload
ALTER TABLE engine_releases ADD COLUMN notes TEXT NOT NULL DEFAULT '';           -- as published, at most 64 KiB, shown as text
ALTER TABLE engine_releases ADD COLUMN url TEXT NOT NULL DEFAULT '';
-- engine_releases.engine is the component (telemt, mtg, xray, warp-plus, postern); assets: JSON object by arch ('[]', the old default, reads as empty)
CREATE TABLE engine_channels (engine TEXT NOT NULL, channel TEXT NOT NULL CHECK (channel IN ('stable', 'latest')),
  version TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (engine, channel)) STRICT, WITHOUT ROWID;
INSERT INTO engine_channels VALUES ('telemt','stable','3.5.13',0),('telemt','latest','3.5.13',0),('mtg','stable','v2.2.8',0),
  ('mtg','latest','v2.2.8',0),('xray','stable','v26.3.27',0),('xray','latest','v26.3.27',0),('warp-plus','stable','v1.2.6',0),('warp-plus','latest','v1.2.6',0);
CREATE TABLE release_feeds (url TEXT PRIMARY KEY, component TEXT NOT NULL, etag TEXT NOT NULL DEFAULT '',
  checked_at INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '') STRICT;
ALTER TABLE nodes ADD COLUMN engine_channel TEXT NOT NULL DEFAULT '';            -- '' | stable | latest
ALTER TABLE nodes ADD COLUMN provider_versions TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provider_versions));
CREATE TABLE rollouts (id TEXT PRIMARY KEY, kind TEXT NOT NULL, component TEXT NOT NULL, channel TEXT NOT NULL DEFAULT '',
  from_version TEXT NOT NULL DEFAULT '', to_version TEXT NOT NULL DEFAULT '', to_engine TEXT NOT NULL DEFAULT '',
  options TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(options)), mode TEXT NOT NULL, pause_seconds INTEGER NOT NULL DEFAULT 120,
  status TEXT NOT NULL, current_step INTEGER NOT NULL DEFAULT 0, resume_at INTEGER, error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, finished_at INTEGER) STRICT;
CREATE UNIQUE INDEX rollouts_one_version_per_channel ON rollouts (component, channel)
  WHERE kind = 'version' AND status IN ('preparing', 'running', 'paused', 'failed');
CREATE TABLE rollout_nodes (rollout_id TEXT NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE, node_id TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)), PRIMARY KEY (rollout_id, node_id)) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX rollout_nodes_one_active ON rollout_nodes (node_id) WHERE active = 1;
CREATE TABLE rollout_steps (rollout_id TEXT NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE, idx INTEGER NOT NULL,
  node_id TEXT NOT NULL, proxy_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER, finished_at INTEGER, error TEXT NOT NULL DEFAULT '', PRIMARY KEY (rollout_id, idx)) STRICT, WITHOUT ROWID;
CREATE TABLE rollout_items (rollout_id TEXT NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE, proxy_id TEXT NOT NULL,
  node_id TEXT NOT NULL, step_idx INTEGER NOT NULL, prev_engine TEXT NOT NULL, prev_policy TEXT NOT NULL, prev_version TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY (rollout_id, proxy_id)) STRICT, WITHOUT ROWID;
-- kind: version | switch | node; mode: manual | auto; status: preparing | running | paused | failed | completed | aborted
-- step status: pending | applying | verifying | done | failed | reverted | skipped; item state: pending | applied | reverted | detached | deferred
```

Settings keys (JSON): `versions.default_channel` (`"stable"`), `releases.source` (`{"kind":"github","base_url":"","repo":"urbnywrt/postern"}`), `releases.include_prereleases` (`false`), `releases.stable_generated_at` (`0`), sealed `releases.github_token` and `releases.source_token` (`{"sealed":"<base64>"}`, AAD `setting:<key>`); helpers `ReleaseSource(ctx)` / `PutReleaseSource(ctx, ReleaseSource)` and `SealedSetting(ctx, key) ([]byte, bool, error)` / `PutSealedSetting(ctx, key string, sealed []byte)` (the store keeps sealed bytes and never sees the master key).

```go
type ReleaseAsset struct { File, URL, SHA256, SHASource, State, Reason, NodeID string; Size int64; CheckedAt time.Time }
// SHASource: builtin | digest | sums | tofu | stable | signed; State: unchecked | ready | unusable
type Release struct { Engine, Version, Tag, Source, Notes, URL string; Stable, Prerelease bool; PublishedAt, FetchedAt time.Time; Assets map[string]ReleaseAsset }
func (db *DB) UpsertRelease(ctx, *Release) error // another SHA256 for an asset that has one → ErrChecksumChanged, row unchanged
func (db *DB) ReleaseOf(ctx, engine, version string) (*Release, error); ListReleases(ctx, engine string) ([]*Release, error) // newest first (release.Compare)
func (db *DB) SetAssetState(ctx, engine, version, arch, state, reason, nodeID string) error // the release catalog enforces R5-4 before calling it
func (db *DB) ChannelVersions(ctx) (map[string]map[string]string, error); SetChannelVersion(ctx, engine, channel, version string) error
func (db *DB) Feed(ctx, url string) (Feed, error); PutFeed(ctx, Feed) error
func (db *DB) CreateRollout(ctx, *Rollout, nodeIDs []string, []RolloutStep, []RolloutItem) error // inserts rollout_nodes rows; a unique-index violation → ErrRolloutConflict naming the holder
func (db *DB) Rollout(ctx, id string) (*Rollout, []RolloutStep, []RolloutItem, error); ListRollouts(ctx, activeOnly bool, limit int) ([]*Rollout, error)
func (db *DB) UpdateRollout(ctx, *Rollout) error // completed/aborted also set its rollout_nodes inactive, in the same transaction
func (db *DB) UpdateRolloutStep(ctx, *RolloutStep) error // never clears a stored started_at
func (db *DB) ApplyItems(ctx, rolloutID string, items []RolloutItem, engine, policy, version string) (nodeIDs []string, err error) // one transaction; an item whose proxy no longer holds what the rollout last wrote (or its prev values, before the first apply) becomes detached
func (db *DB) RevertItems(ctx, rolloutID string, items []RolloutItem) (nodeIDs []string, err error)
func (db *DB) DeferItems(ctx, rolloutID string, proxyIDs []string) error
func (db *DB) FinishItems(ctx, rolloutID, appliedPolicy string) (nodeIDs []string, err error) // applied → appliedPolicy (channel | pinned); deferred → pinned at their prev version
func (db *DB) SetNodeProviderVersion(ctx, nodeID, component, version string) error // "" removes
```

`versions.proto`, `service VersionService` (every call needs a session; errors INVALID_ARGUMENT, NOT_FOUND, FAILED_PRECONDITION, UNAVAILABLE; each RPC has its own request and response, as `buf lint` STANDARD requires):

```proto
rpc ListComponents(ListComponentsRequest) returns (ListComponentsResponse);       // {} → {components, default_channel, include_prereleases}
rpc ListReleases(ListReleasesRequest) returns (ListReleasesResponse);             // {component} → {releases}
rpc RefreshReleases(RefreshReleasesRequest) returns (RefreshReleasesResponse);    // {component ("" all)} → {components}
rpc PrepareRelease(PrepareReleaseRequest) returns (PrepareReleaseResponse);       // {component, version, archs} → {release}
rpc RecheckRelease(RecheckReleaseRequest) returns (RecheckReleaseResponse);       // {component, version, arch} → {release}
rpc SetDefaultChannel(SetDefaultChannelRequest) returns (SetDefaultChannelResponse); // {channel, confirm} → {affected_proxies, applied}
rpc SetNodeChannel(SetNodeChannelRequest) returns (SetNodeChannelResponse);       // {node_id, channel ("" default), confirm} → {affected_proxies, applied}
rpc StartRollout(StartRolloutRequest) returns (StartRolloutResponse);             // → {rollout}
rpc GetRollout(GetRolloutRequest) returns (GetRolloutResponse);                   // {id} → {rollout}
rpc ListRollouts(ListRolloutsRequest) returns (ListRolloutsResponse);             // {active_only, limit} → {rollouts}
rpc ContinueRollout(ContinueRolloutRequest) returns (ContinueRolloutResponse);    // {id} → {rollout}
rpc PauseRollout(PauseRolloutRequest) returns (PauseRolloutResponse);             // {id} → {rollout}
rpc RetryRollout(RetryRolloutRequest) returns (RetryRolloutResponse);             // {id} → {rollout}
rpc AbortRollout(AbortRolloutRequest) returns (AbortRolloutResponse);             // {id} → {rollout}
rpc GetPanelVersion(GetPanelVersionRequest) returns (GetPanelVersionResponse);
rpc UpdatePanel(UpdatePanelRequest) returns (UpdatePanelResponse);                // {version} → {version, restarting}
rpc GetReleaseSource(GetReleaseSourceRequest) returns (GetReleaseSourceResponse); // {} → {source}
rpc SetReleaseSource(SetReleaseSourceRequest) returns (SetReleaseSourceResponse); // {source, optional token, optional github_token} → {source}
message Component { string name = 1; string kind = 2; map<string, string> channel_versions = 3; map<string, string> newest = 4; int64 checked_unix = 5; string feed_error = 6; }
message ReleaseAsset { string arch = 1; string file = 2; string sha256 = 3; string sha_source = 4; string state = 5; string reason = 6; int64 size = 7; string node_id = 8; }
message Release { string component = 1; string version = 2; bool stable = 3; bool prerelease = 4; string source = 5; int64 published_unix = 6; string notes = 7; string url = 8; repeated ReleaseAsset assets = 9; repeated string channels = 10; }
message StartRolloutRequest { string kind = 1; string component = 2; string channel = 3; string to_version = 4; repeated string proxy_ids = 5; repeated string node_ids = 6; string mode = 7; uint32 pause_seconds = 8; string canary_proxy_id = 9; string canary_node_id = 10; bool agent = 11; bool edge = 12; bool skip_offline = 13; }
message RolloutStep { uint32 index = 1; string node_id = 2; string node_name = 3; string proxy_id = 4; string status = 5; string error = 6; int64 started_unix = 7; int64 finished_unix = 8; uint32 items = 9; uint32 items_done = 10; uint32 items_deferred = 11; }
message Rollout { string id = 1; string kind = 2; string component = 3; string channel = 4; string from_version = 5; string to_version = 6; string to_engine = 7; string mode = 8; uint32 pause_seconds = 9; string status = 10; uint32 current_step = 11; string error = 12; repeated RolloutStep steps = 13; int64 created_unix = 14; int64 updated_unix = 15; int64 finished_unix = 16; int64 resume_unix = 17; bool agent = 18; bool edge = 19; bool skip_offline = 20; }
message AffectedProxy { string proxy_id = 1; string name = 2; string node_id = 3; string from_version = 4; string to_version = 5; }
message GetPanelVersionResponse { string version = 1; string commit = 2; string date = 3; string image_version = 4; bool can_update = 5; string cannot_update_reason = 6; repeated Release releases = 7; string last_update = 8; bool kit_signed = 9; bool trusts_test_keys = 10; }
message ReleaseSource { string kind = 1; string base_url = 2; string repo = 3; bool has_token = 4; bool has_github_token = 5; bool include_prereleases = 6; }
```

**Requirements:** the service type is `versions.Service{panelv1connect.UnimplementedVersionServiceHandler; …}` built with `versions.New(db, log)`; later tasks add their methods in files of their own (`catalog.go`, `channels.go`, `rollouts.go`, `panel.go`) and their dependencies through setters. The migration applies cleanly over every migration on its base and passes the store's name check.

**Tests:** migration on a slice-1 database (backup made) seeds the channel rows once; an `assets` value of `'[]'` reads as an empty map; release upsert keeps a pinned SHA-256 (ErrChecksumChanged) and round-trips assets; channel versions; feeds keyed by URL; rollout conflicts: a second active `version` rollout for one (component, channel), any second active rollout touching a node (two goroutines inserting at once: exactly one wins), a `failed` rollout still holds its nodes, completing releases them; `UpdateRolloutStep` keeps `started_at`; `ApplyItems` detaches an item the operator re-pinned; `RevertItems`; `DeferItems` + `FinishItems` pin deferred items at their previous version; `SetNodeProviderVersion`; `HasSealedData` true with a sealed release token; the stub service answers Unimplemented after auth and 401 without a session; `buf lint` clean.

**Steps:** proto + regen → tests → FAIL → implement → PASS → commit `feat(panel): version store and the VersionService contract`.

---

### Task 8a: Release feeds, checksum rules and Prepare

**Lane:** `lane/s5-base` after Task 7 · **Model:** opus

**Files:** Create `internal/panel/releases/components.go`, `builtin.json`, `builtin.go`, `feed.go`, `limiter.go`, `verify.go`, `extract.go`, `catalog.go`, tests (`httptest` fake GitHub and Gitea APIs and download hosts), `fuzz_test.go`.

**Interfaces:** Consumes store releases/feeds/settings (Task 7: `UpsertRelease`, `ReleaseOf`, `ListReleases`, `SetAssetState`, `Feed`, `PutFeed`, `SealedSetting`), `release.SumFor`, `release.CheckStaticELF`, `release.Compare`, `seal`. Produces:

```go
package releases
type Component struct { Name, Kind, Repo, Binary, Member string; TagV bool; Assets map[string]string; Sums SumsSpec } // Member: the cleaned archive path of the binary, "{n}" and "{arch}" expanded
var Components []Component // telemt, mtg, xray, warp-plus (Global Constraints)
type FeedSource struct { Kind, APIBase, Repo, Token string } // github | gitea
type FeedAsset struct { Name, URL, Digest string; Size int64; Created time.Time }
type FeedRelease struct { Tag string; Prerelease bool; Published time.Time; Notes, URL string; Assets []FeedAsset }
type Limiter struct{ /* every API request of the panel */ }
func FetchReleases(ctx context.Context, hc *http.Client, lim *Limiter, src FeedSource, etag string, full bool) (rels []FeedRelease, newETag string, notModified bool, retryAt time.Time, err error)
type Config struct { DB *store.DB; Key seal.Key; Keys func(release.KeySet) ([]minisign.PublicKey, error); Dir string; HTTP *http.Client; APIBase string; Limiter *Limiter; Log *slog.Logger; Now func() time.Time }
func New(cfg Config) *Catalog
func (c *Catalog) Seed(ctx context.Context) error
func (c *Catalog) Prepare(ctx context.Context, component, version string, archs []string) error
func (c *Catalog) Ref(ctx context.Context, component, version, arch string) (*nodev1.ArtifactRef, error) // a pinned SHA-256 suffices; ErrUnknown | ErrNoPin
func (c *Catalog) Ready(ctx context.Context, component, version, arch string) error             // ErrNotReady | ErrUnusable
func (c *Catalog) Open(ctx context.Context, component, version, arch string) (io.ReadCloser, *nodev1.ArtifactRef, error)
func (c *Catalog) MarkUnusable(ctx context.Context, component, version, arch, nodeID, reason string) error
func (c *Catalog) Recheck(ctx context.Context, component, version, arch string) error
func (c *Catalog) Known(ctx context.Context, component, version string) bool
func (c *Catalog) InChannel(ctx context.Context, component, channel, version string) (bool, error)
func (c *Catalog) Newest(ctx context.Context, component, channel string, archs []string) (string, error)
```

**Requirements:**
- `Seed` on every start: built-in releases (source `builtin`, stable, `sha_source=builtin`, state `unchecked` until prepared, URL `https://github.com/<repo>/releases/download/<tag>/<file>`); channel rows are inserted only by the migration and never reset.
- `FetchReleases` per Global Constraints (HTTP: GitHub `per_page=100` or Gitea `limit=50`, `Link` paging, the raw ETag per exact URL, `If-None-Match`, 304 optional, `Retry-After`/`X-RateLimit-Reset`); `full` (no stored ETag) keeps paging until a non-prerelease release has been seen, at most 5 pages; later polls read page 1. Every request goes through the `Limiter` (without a token ≤ 50 an hour in all; with one ≤ 1000). Drafts skipped; a tag that `release.ValidVersion` refuses skipped; prerelease from the upstream flag; notes clipped to 64 KiB of valid UTF-8; Gitea attachments without digest, the newest `created_at` for a duplicated name (F9); bodies ≤ 4 MiB a page.
- Prepare per arch: the expected SHA-256 per Global Constraints (Checksum rules: built-in, digest, checksum file, TOFU; R5-4); download to `<Dir>/<component>/<version>/<file>` through a temp file renamed only after the SHA-256 matched (a failed download is neither kept nor pinned); extraction: only a regular-file member whose cleaned path equals the component's `Member` is read, straight into a fixed temp file (absolute paths, `..`, links and devices are never followed or written; two members with that path → unusable; ≤ 256 MiB); `CheckStaticELF` → `ready`, else `unusable` with the reason (event `release_unusable`); the extracted copy removed. Concurrent Prepares of one file wait for one download.
- `Ref` names any version whose asset has a pinned SHA-256 for that arch (F10), ready or not; `Ready` says whether it may be uploaded; `Open` re-hashes while read (a mismatch fails the read and deletes the file). `MarkUnusable` records a node's failed trial (Task 9 passes only trials that ran): a non-built-in asset becomes `unusable` for that arch; a built-in asset keeps its state (R5-4) and gets the node and reason as a note, so one node cannot block a channel's version everywhere.
- Channels: `InChannel(stable)` = stable releases; `latest` adds the rest (prereleases with the setting); `Newest` skips unusable versions and versions without an asset for every arch given.

**Tests:** `TestFetchPaging` (two GitHub pages via `Link`; a full fetch stops after the first non-prerelease, at most 5 pages); `TestFetchETag` (raw `W/"…"` stored per URL and sent back; a 304 and a 200 both handled); `TestLimiter` (the 51st unauthenticated request in an hour waits); `TestFetchRateLimit` (403 with reset → no request before it); `TestGiteaShape` (no digest, `browser_download_url` with the token, duplicate names → newest); drafts skipped, prerelease flag kept, `../x` tag skipped; `TestPrepareChecksumOrder` (built-in beats a disagreeing checksum file with the event and stays ready; digest present → expected, checksum file disagreeing → unusable; checksum file alone; TOFU only with neither; a failed download not kept, not pinned); `TestExtractSafety` (absolute, `..`, symlink, hardlink named like the member, duplicate member → unusable; a nested decoy with the right base name is ignored); `TestDynamicBinary`, `TestWrongArch`; `TestOpenDetectsChange`; `TestMarkUnusable` (a non-built-in asset becomes unusable; a built-in one stays ready with the note); `TestSeedIdempotent`; `TestRefNeedsPin` (an upstream version without digest or prepared checksum → ErrNoPin); `TestNewest`; `FuzzFetchReleases` (GitHub and Gitea bodies), `FuzzExtract` (tar.gz and zip). Online (`integration`, `POSTERN_E2E_ONLINE=1`): the real API for the four components; Prepare of every built-in pin on both arches → ready (if one fails the static check, stop and report; never weaken the check).

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/releases/...'` + the two fuzz targets 15 s each (anchored `-fuzz=^Name$`) → PASS → commit `feat(panel): release feeds, checksum rules and verified engine archives`.

---

### Task 8b: Release tracker, stable list and catalog API

**Lane:** `lane/s5-base` after Task 8a (the first merge of lane/s5-base follows) · **Model:** opus

**Files:** Create `internal/panel/releases/tracker.go`, `stable.go`, `gc.go`, tests; `internal/panel/versions/catalog.go` (ListComponents, ListReleases, RefreshReleases, PrepareRelease, RecheckRelease); wire `releases.New`, `Seed`, `Run` into `internal/panel/server` (the state builder keeps its current catalog until Task 9 moves it over).

**Interfaces:** Consumes `releases.Catalog` and `FetchReleases` (8a; its `Config.Keys` gives the keys), `release.VerifyWith` (stable key set), store settings (`releases.source`, `releases.source_token`, `releases.stable_generated_at`, `releases.include_prereleases`), the node list (archs in use). Produces:

```go
func (c *Catalog) Run(ctx context.Context)                       // feeds, stable list, background Prepare, archive GC
func (c *Catalog) Refresh(ctx context.Context, component string) error // ErrTooSoon within a minute of the last one
func (c *Catalog) ApplyStable(ctx context.Context, list, sig []byte) error
```

**Requirements:**
- Schedule: every 6 h ± 10 % per component and at start; `Refresh` at most once a minute per component (UNAVAILABLE); after a feed finds a version newer than a channel version, `Prepare` it in the background for the archs of the nodes; events `release_found`.
- Stable list every 6 h from the Postern source: the release with tag `engines-stable` through the API (GitHub `GET <api>/repos/<repo>/releases/tags/engines-stable`; Gitea `<base>/api/v1/repos/<repo>/releases/tags/engines-stable` with the source token; the newest attachment of each name), then `engines-stable.json` and `.minisig`; 404 means no list yet. `ApplyStable`: `release.VerifyWith` with `Signed{engines-stable, <generated_at>}` and the stable key set only; refused when older than `releases.stable_generated_at` or more than 5 min ahead; listed releases become stable (unknown ones are created with source `stable` and the listed SHA-256); releases of the previous list that the new one drops lose the stable flag (rows kept; built-ins stay stable); an entry disagreeing with a built-in pin is rejected and the built-in asset keeps its state (R5-4); an entry disagreeing with a non-built-in expected hash makes that asset unusable; both raise `release_checksum_mismatch` (error); `stable_list_applied` on success.
- Archive GC daily: keep the archives of versions named by any node's desired state, every channel version and channel newest, built-ins, and the 2 newest versions of each component; delete other archives older than 30 days.
- RPCs: ListComponents (channel versions, newest per channel, feed status), ListReleases (with `channels` naming the channels whose version it is), RefreshReleases, PrepareRelease (archs default to those of the nodes), RecheckRelease (an unusable asset back to unchecked, then Prepare).

**Tests:** schedule with a fake clock; refresh limit; background Prepare of a found newer version; `TestStableList` (good; bad signature; signed by a release key → refused; older; 6 min ahead → refused; a dropped version loses the flag, a built-in does not; disagreeing with a built-in → entry rejected, built-in still ready; disagreeing with a digest → unusable); a Gitea stable release with two `engines-stable.json` attachments → the newest; GC keeps what is named and recent; RPC answers and admin checks.

**Steps:** tests → FAIL → implement → PASS → commit `feat(panel): release tracker, signed stable list and the catalog API`.

---

### Task 9: Versions in the desired state and the engine of a proxy

**Lane:** `lane/s5-panel` (dev after slice 2 and the first lane/s5-base merge) · **Model:** opus

**Files:** Modify `internal/panel/proxies/catalog.go` (an adapter over `releases.Catalog`), `statebuilder.go`, `service.go`, `ingest.go`, `validate.go`, tests; `proto/postern/panel/v1/proxies.proto` and `nodes.proto` (+ regen Go/TS); create `internal/panel/versions/channels.go` (SetDefaultChannel, SetNodeChannel); in `internal/panel/server`, hand the running `releases.Catalog` to the proxies catalog adapter.

**Interfaces:** Consumes `releases.Catalog` (`Ref`, `Ready`, `Open`, `Prepare`, `Known`, `MarkUnusable`, `Newest`), store channel versions, `nodes.engine_channel`, `nodes.provider_versions`, node `UploadArtifactResponse.tried/usable/reason`, node `ProxyStatus.engine` (the serving engine), `failed_engine`, `failed_version`, `StateReport.egress_instances`. Produces:

```go
package proxies
type Effective struct { Engine, Version, Source string } // Source: pinned | rollout | channel
func EffectiveVersion(p *store.Proxy, nodeChannel, defaultChannel string, channels map[string]map[string]string) Effective
func ProviderVersion(n *store.Node, component, defaultChannel string, channels map[string]map[string]string) string
func (s *Service) NotifyChannel(ctx context.Context, component, channel string) error // bumps and notifies every node on the channel
func (s *Service) AffectedByChannel(ctx context.Context, nodeID, channel string) ([]*panelv1.AffectedProxy, error)
type ProxyReport struct { Phase nodev1.ProxyPhase; Reason, RunningVersion, FailedVersion string; RunningEngine, FailedEngine nodev1.Engine; InstanceGeneration uint64; Reported time.Time; ReportGeneration uint64 }
func (in *Ingestor) ProxyReport(nodeID, proxyID string) (ProxyReport, bool) // ReportGeneration: applied_generation of the state report it came from
type EgressReport struct { EgressID, Provider, Version, Phase, Reason, FailedVersion string; Generation, ReportGeneration uint64 }
func (in *Ingestor) EgressReports(nodeID string) []EgressReport
```

API (numbers per Global Constraints, Numbers): `CreateProxyRequest.engine` (`telemt` default, `mtg`); `Proxy.version_source`, `Proxy.channel`; `ProxyStatus.running_engine` (from the node's `ProxyStatus.engine`), `ProxyStatus.failed_version`; `ListProxiesRequest.engine`, `ListProxiesRequest.outdated`; `Node.engine_channel` (effective), `Node.engine_channel_default` (bool).

**Requirements:**
- Effective versions per Global Constraints (Channels); `engine_version`/`engine_version_pinned` keep their meaning, `version_source` says which rule applies.
- State builder: proxies at their effective engine and version; one artifact per (engine, version) used and one per provider at the node's provider version, named whenever `Ref` has a pinned SHA-256 (F10), ready or not.
- EnsureArtifacts: `Prepare` what is not ready; upload through `Open` only what is `Ready`; meanwhile the node reports the artifact missing and gets it at a later resync. An answer `tried=true, usable=false` → `MarkUnusable(component, version, arch, node, reason)`; `tried=false` → nothing marked, uploaded again at the next resync. An artifact the node lists as unusable is not uploaded again. `tried`, `usable` and the GetInfo artifact `state` count only for nodes with capability `artifact-trial` (an older node leaves them unset).
- CreateProxy with `engine=mtg`: fake TLS only, no ad tag, no overrides, middle proxy off, mask target a public IP; the node needs capability `engine-mtg` (reuse slice 2's gate). UpdateProxy never changes the engine (a switch is a `switch` rollout) and refuses edits that would make an mtg proxy invalid, with the node validator's message.
- Pinning (`engine_version`) needs a version that `Ref` resolves for the node's arch; otherwise FAILED_PRECONDITION "not pinned yet" and `Prepare` starts.
- `outdated` = running engine/version differs from the effective one, or the effective version is older than `Newest` of the proxy's channel.
- SetNodeChannel and SetDefaultChannel answer OK with the list of proxies whose effective version would change (`AffectedByChannel`): without `confirm=true` they change nothing and answer `applied = false`; with it they apply the change, answer `applied = true` and bump the generations of the affected nodes (Ruling S5-11: an error has no body to carry the list).
- Ingest keeps the new fields and the report's `applied_generation` with each status (egress reports ≤ 1000 per node); the node phase enum maps to the panel's phase string as today.

**Tests:** EffectiveVersion table (pinned, rollout, node channel, default channel, unknown channel → default); state builder golden: a node on latest with a telemt proxy following it, an mtg proxy pinned, a proxy under rollout, an xray egress at the node's override, a built-in version not yet prepared still named; EnsureArtifacts uploads only ready archives, marks unusable only for `tried=true`, ignores unset fields from a node without `artifact-trial`; CreateProxy mtg allowed / refused per rule and per capability; UpdateProxy refuses an ad tag on an mtg proxy; pin before a pin exists → refused; outdated and engine filters; channel changes not applied without confirm (`applied = false` with the affected list), applied with it; `running_engine` from a report where telemt serves after a failed mtg switch.

**Steps:** proto + regen → tests → FAIL → implement → PASS → commit `feat(panel): engine versions by channel and the engine of a proxy`.

---

### Task 10a: Rollout runner and engine version rollouts

**Lane:** `lane/s5-panel` after Task 9 · **Model:** opus

**Files:** Create `internal/panel/rollout/runner.go`, `plan.go`, `engines.go`, tests; `internal/panel/versions/rollouts.go` (Start, Get, List, Continue, Pause, Retry, Abort); server wiring (the runner starts after the node manager and stops before it).

**Interfaces:** Consumes the store's rollout functions (`CreateRollout`, `Rollout`, `ListRollouts`, `UpdateRollout`, `UpdateRolloutStep`, `ApplyItems`, `RevertItems`, `DeferItems`, `FinishItems`, `SetChannelVersion`; `ErrRolloutConflict`), `releases.Catalog.Prepare/InChannel/Ref`, `proxies.Ingestor.ProxyReport` (with `ReportGeneration`), `(*proxies.Service).NotifyChannel`, `store.NextNodeGeneration`, `nodes.Manager.Notify`, node rows (`applied_generation`, `state_rejection`, `status`, `last_seen_at`, `capabilities`), the events and audit tables. Produces:

```go
package rollout
type Request = panelv1.StartRolloutRequest
type Executor interface {
  Plan(ctx context.Context, r *store.Rollout, req *Request) (nodeIDs []string, steps []store.RolloutStep, items []store.RolloutItem, err error)
  Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
  Check(ctx context.Context, r *store.Rollout, s *store.RolloutStep) (done bool, err error) // err: the step failed
  Revert(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
  Complete(ctx context.Context, r *store.Rollout) error
}
type Hooks struct { BeforeStep, AfterStep func(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error }
type Config struct { DB *store.DB; Executors map[string]Executor /* key: "version:engine", "version:provider", "switch", "node" */; Hooks Hooks; Log *slog.Logger; Now func() time.Time; Tick time.Duration }
func NewRunner(cfg Config) *Runner
func (r *Runner) Register(key string, e Executor) // the switch, provider and node tasks add theirs
func (r *Runner) Run(ctx context.Context)
func (r *Runner) Start(ctx context.Context, admin string, req *Request) (*store.Rollout, error)
func (r *Runner) Continue(ctx context.Context, id string) error // also Pause, Retry, Abort
```

**Requirements:**
- Semantics per Global Constraints (Rollouts, R5-5, R5-7). Each active rollout is driven by its own goroutine; every transition is stored before it acts; `Run` resumes active rollouts after a restart: a step in `applying` or `verifying` keeps its `started_at`; generation 0 → Apply again.
- Engine `version` executor: items = proxies with policy `channel`, the component as engine and their node on the channel. Refused: a target not `InChannel` (stable: stable only), a target without a pinned SHA-256 for an arch in scope, a target below a proxy's minimum (a WEB proxy with a base path needs telemt ≥ 3.5.8, spec §4), nodes without `rollout-status` (listed). Then `preparing`: `Prepare` for every arch in scope (a failure ends in `failed`). Steps: the canary proxy (given, else the first enabled item by node name, proxy name, id on an online node), the rest of its node, each other node by name.
- Apply: `ApplyItems` (policy `rollout`) for the step's enabled items, `DeferItems` for its disabled ones → `NextNodeGeneration` + `Notify` per node; the step's generation stored. Check: only reports with `ReportGeneration` ≥ the step's generation count; `state_rejection` for that generation → failed with its text; every applied item SERVING with running engine and version = target → done; `failed_engine`/`failed_version` = target or phase FAILED → failed with the node's reason; the timeout or the node offline beyond the grace → failed (or the step `skipped` and its items deferred with `skip_offline`). Revert = `RevertItems` + generation + notify; then `AfterStep` (error ignored); step `reverted`, rollout `failed`, event `rollout_failed` (error).
- Complete: `SetChannelVersion`, `FinishItems(channel)` (deferred items pinned at their previous version, with event `rollout_items_kept` naming them), `NotifyChannel`; event `rollout_completed`.
- Hooks (R5-5): a `BeforeStep` error fails the step before Apply (nothing to revert); an `AfterStep` error after a successful Check fails the step and reverts it; after a revert `AfterStep` runs once more and its error is ignored.
- Pause/Continue/Retry/Abort; Abort reverts applied steps in reverse order (`aborted`). Events `rollout_started`, `rollout_step_done`, `rollout_failed`, `rollout_completed`, `rollout_aborted`; audit entries for every API action. A conflict answers FAILED_PRECONDITION naming the rollout that holds the channel or node.

**Tests (fake clock, reports with generations, notifier):** `TestCanaryOrder` (3 nodes, 5 proxies → [canary, rest of A, B, C]); `TestAutoHappyPath` (pauses, channel moved, items back to channel); `TestManual`; `TestOldReportIgnored` (a report of an older generation saying `failed_version` = target does not fail a retried step); `TestStateRejectionFails`; `TestFailedStepIsReverted` (B fails → B reverted, `AfterStep` called with `reverted`, C never applied, A keeps the target, Retry re-applies B); `TestTimeoutStartsAfterBeforeStep` (a hook that blocks 3 min does not eat the timeout); `TestHooks` (a `BeforeStep` error fails the step without Apply; an `AfterStep` error after success reverts it; `AfterStep` after a revert is called and its error ignored); `TestSkipOfflineDefers` and `TestDisabledProxyDeferred` (pinned at the previous version on completion); `TestEmptyStep` (a canary-only node: the rest step completes once applied); `TestAbort`; `TestDetachedItem`; `TestResume` (`started_at` kept, generation 0 re-applied); `TestRefusals` (conflicts, stable target not stable, no pin, missing capability, WEB minimum, unusable target → failed at preparing).

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/rollout/... ./internal/panel/versions/...'` → PASS → commit `feat(panel): canary rollouts of engine versions with automatic cancel`.

---

### Task 10b: Switch and provider rollouts

**Lane:** `lane/s5-panel` after Task 10a · **Model:** opus

**Files:** Create `internal/panel/rollout/switch.go`, `providers.go`, tests; register both in the server wiring.

**Interfaces:** Consumes `rollout.Executor`, `Runner.Register`, the store's item and node functions (`ApplyItems`, `RevertItems`, `DeferItems`, `FinishItems`, `SetNodeProviderVersion`, `SetChannelVersion`), `proxies.Ingestor.ProxyReport/EgressReports` (with `ReportGeneration`), the proxies service's validation for an engine (as CreateProxy uses), node capabilities, `releases.Catalog.Ref/Prepare/InChannel`. Produces the `switch` and `version:provider` executors.

**Requirements:**
- `switch`: given proxies (1..n) to `component` as engine, at `to_version` (pinned on completion) or at that engine's channel version on each proxy's node; each proxy validated as CreateProxy would with that engine (mtg rules, capability `engine-mtg`) before start; steps: the first proxy, the rest of its node, each other node by name; Apply writes engine + version (policy `rollout`); Check as for engine versions; Complete → `FinishItems(pinned or channel)`.
- `version` for providers (xray, warp-plus): nodes on the channel that run an egress of that provider; steps: the canary node, then the others; Apply `SetNodeProviderVersion` + generation; Check: every egress instance of the provider on the node reports the target serving (reports with `ReportGeneration` ≥ the step's generation); `failed_version` = target or phase failed → failed; Revert removes the override; Complete → `SetChannelVersion`, overrides of applied nodes removed, a skipped node keeps an override at its previous version.

**Tests:** `TestSwitch` (telemt → mtg on two nodes; a failure on the second reverts only it; an mtg switch of a proxy with an ad tag refused at start; two one-proxy switches on two nodes run at once, on one node the second is refused); `TestSwitchPinned` (with `to_version` the items end pinned); `TestProviderRollout` (canary node, failure reverted, completion moves the channel, a skipped node keeps its previous version).

**Steps:** tests → FAIL → implement → race → PASS → commit `feat(panel): engine switches and provider rollouts`.

---

### Task 11a: Postern releases: source, verified cache and bundle upload

**Lane:** `lane/s5-base` after Task 8b · **Model:** opus

**Files:** Create `internal/panel/selfupdate/source.go`, `cache.go`, `upload.go`, tests, `fuzz_test.go`; `internal/panel/versions/panel.go` (GetReleaseSource, SetReleaseSource); the upload route in `internal/panel/server`.

**Interfaces:** Consumes `releases.FetchReleases` and `releases.Limiter` (component `postern`, kinds github/gitea), `releases.Catalog.ApplyStable`, `release.VerifyWith` (release key set for binaries), store settings and sealed settings, `seal`. Produces:

```go
package selfupdate
type Releases struct{ /* store, key, http, limiter, cache */ }
func (r *Releases) Source(ctx context.Context) (*Source, error)                 // from settings releases.source and the sealed token
func (s *Source) List(ctx context.Context) ([]releases.FeedRelease, error)    // newest first, prereleases per setting
type Cache struct { Dir string; Keys func(release.KeySet) ([]minisign.PublicKey, error) } // <data>/artifacts/postern/<version>/<asset>(.minisig)
func (c *Cache) Put(ctx context.Context, version, asset string, r io.Reader, sig []byte) error // verifies before keeping
func (c *Cache) Open(version, asset string) (io.ReadCloser, []byte, error)                     // re-verifies
func (c *Cache) Fetch(ctx context.Context, src *Source, version string, assets []string) error
func NodeAsset(arch string) string  // "postern-node-linux-" + arch
func PanelAsset(arch string) string // "postern-panel-linux-" + arch
func UploadHandler(…) http.Handler  // POST /api/releases/upload
```

**Requirements:**
- Source: GitHub (default repo `urbnywrt/postern`, API base `POSTERN_GITHUB_API`) or Gitea (`https://` base required); tokens sealed and write-only; Gitea bytes from `browser_download_url` with the token on that host only (F9).
- Cache: an asset is kept only with its `.minisig` verifying for its component, version and arch (`Signed{postern-node|postern-panel, version, linux, arch}`); `Open` verifies again.
- Upload `POST /api/releases/upload`: admin session, `Content-Type: application/x-tar`, ≤ 256 MiB; only known asset names (no paths) are read, into a temporary directory; every asset needs its valid `.minisig`; the set is accepted only whole: when every present asset verified, the directory is renamed into the cache at once and the release recorded (component `postern`, source `upload`); otherwise nothing is kept and the answer lists each asset's reason. `engines-stable.json` + `.minisig` in the bundle go to `ApplyStable` only when the rest of the bundle is accepted. JSON summary.

**Tests:** cache put/open (good; bad signature; an asset whose trusted comment names another arch or a panel binary under a node name); source settings and token sealing (DB holds no plaintext token); Gitea download sends the token to its host only; upload (a complete good bundle accepted; one bad asset → nothing kept, reasons listed; `../x` member ignored; a truncated tar → nothing kept; size limit; 401); `FuzzUpload` (tar bodies).

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/selfupdate/...'` + `FuzzUpload` 15 s → PASS → commit `feat(panel): Postern release source, verified cache and bundle upload`.

---

### Task 11b: Panel self-update and recovery

**Lane:** `lane/s5-base` after Task 11a (the second merge of lane/s5-base follows) · **Model:** opus

**Files:** Create `internal/panel/selfupdate/update.go`, `recover.go`, tests; extend `internal/panel/versions/panel.go` (GetPanelVersion, UpdatePanel); modify `internal/panel/store/store.go` (exported `Backup(ctx, label) (string, error)` = the existing `VACUUM INTO` copy, `NewerSchema(path string) (bool, error)` read-only), `cmd/panel/serve.go` (Recover before `server.New`, exit 75 on `selfupdate.ErrRestart`), `internal/panel/server/server.go` (updater, restart → graceful stop), `deploy/panel/launcher_test.sh` (exit 75 case), `deploy/panel/README.md`.

**Interfaces:** Consumes `selfupdate.Releases/Source/Cache` (11a), `release.CheckStaticELF/Compare/KeyWarnings`, node rows (`agent_version`), the launcher contract (`POSTERN_HEALTHY_FILE`, `run/launcher/rollback` = `"<unix> <from> <to>"`, `previous` may be the image binary). Produces:

```go
var ErrRestart = errors.New("selfupdate: restart into the new version")
type Updater struct{ /* data dir, releases, store, now, exec */ }
func (u *Updater) Available(ctx context.Context) (ok bool, reason string)
func (u *Updater) Update(ctx context.Context, version string) error // ErrRestart when installed
func Recover(dataDir, version string, log *slog.Logger) (Outcome, error)
```

**Requirements:**
- `Available`: launched by the launcher (`POSTERN_HEALTHY_FILE` set), `/data/bin` writable and executable (a trial run), a release key compiled in.
- `Update(v)`: refuses `v` not newer than the running version; refuses while any node's agent is older than the minor before `v` (spec §6), naming them; fetches `postern-panel-linux-<GOARCH>` and both node assets (so the kit can follow); static ELF; `<binary> version` prints `<v> (`; `store.Backup(ctx, "pre-"+v)`; journal `/data/run/selfupdate.json` `{from, to, backup, at}` (atomic); installs `/data/bin/postern-panel-<v>` 0755; `previous` = current's target, or the image binary (absolute) when there is no `current`; `current` = the new file; audit `panel_update_started`; returns ErrRestart: the RPC is answered, the server stops as on SIGTERM, the process exits 75.
- `Recover`, before the store opens: (a) journal `to` = the running version → once the server serves, delete the journal, event `panel_updated`; (b) a launcher rollback record not older than the journal's `at`, rolled back from `postern-panel-<journal to>`, with the running version = the journal's `from`: if the database holds a migration this version does not know (`NewerSchema`), move `postern.db`, `-wal` and `-shm` to `backups/failed-<to>-<unix>/` first and then put the journal's snapshot in place as `postern.db` (0600); event `panel_update_rolled_back` with the paths; delete the journal and the rollback record; a record older than the journal is ignored; (c) running from `/data/bin` while the image binary reports a newer version → remove `current` and `previous` and exit 75 (a pulled newer image wins).
- GetPanelVersion: version, commit, date, image version, `can_update` + reason (incl. the §6 window), newer releases, last outcome, whether the image kit is signed, `trusts_test_keys` (`release.KeyWarnings`).
- README: self-update, the automatic rollback and restore, the manual downgrade (remove `/data/bin/current`).

**Tests:** Update in a temp data dir with a fake restart: links (the image binary as previous without a current), journal, a `VACUUM INTO` backup that opens; downgrade refused; an old node refused by name; a failing trial leaves nothing; Recover (a); (b) with a test migration set that makes the DB "newer" (`-wal`/`-shm` moved before the snapshot; the record removed); (b) with a stale record older than the journal → ignored; (c) with a fake image binary; GetPanelVersion fields; launcher test: a binary that writes the marker and exits 75 is started again without counting a crash.

**Steps:** tests → FAIL → implement → PASS (+ `bash scripts/wsl 'sh deploy/panel/launcher_test.sh'`) → commit `feat(panel): self-update with rollback and database restore`.

---

### Task 12: Node and edge updates from the panel

**Lane:** `lane/s5-panel` after Task 10b, once lane/s5-node (Task 6b) and the second lane/s5-base merge are on dev · **Model:** opus

**Files:** Create `internal/panel/nodeupdate/executor.go`, `client.go`, `internal/panel/nodes/kitsource.go`, tests; modify `internal/panel/nodes/kit.go`, `internal/panel/nodes/connmgr.go` (keep `binaries`, `healthy`, `warnings` of GetInfo in `nodes.host_info` JSON, no new column; a reconnection signal), `proto/postern/panel/v1/nodes.proto` (`Node.previous_agent_version`, `Node.node_binaries`, `Node.healthy`, `Node.warnings`, next free numbers) + regen; the server wiring registers the executor; if slice 4 is on dev, its SSH install job takes the binary from the kit source.

**Interfaces:** Consumes node `UpdateSelf` (NodeBinary meta: version, arch, sha256, size, signature text, rollback; codes InvalidArgument, PermissionDenied, FailedPrecondition, ResourceExhausted, Unavailable) and `UpdateEdge` (Aborted, Unavailable), GetInfo `agent_version`, `edge_version`, `binaries`, `healthy`, `warnings`, node events `agent_rolled_back` and `agent_started` (events table), `selfupdate.Releases.Source`, `selfupdate.Cache.Open/Fetch`, `selfupdate.NodeAsset`, `rollout.Executor`/`Runner.Register`, capabilities `update-self`, `update-edge`. Produces the `node` executor and:

```go
package nodes
type KitSource interface { NodeBinary(ctx context.Context, arch string) (r io.ReadCloser, sig []byte, version string, err error) } // the running panel's version
```

**Requirements:**
- `node` rollouts: scope = given nodes or all; target = a Postern version from the cache (fetched on demand) or the image kit (only when its signatures verify, `kit_signed`) — for an edge-only rollout, a version listed in the node's `binaries` is enough — never above the panel's version nor below its previous minor; nodes without the needed capability are refused by name ("update them once with install.sh and the node kit"). Per node: (1) `agent` and `agent_version` ≠ target → UpdateSelf (≤ 5 min; `rollback=true` only when the target is the node's recorded `previous` and older than its agent) expecting `restarting`, then wait (≤ 5 min) until GetInfo shows `agent_version` = target and `healthy` (R5-3); a reconnection on another version, a node event `agent_rolled_back`, or an `agent_started` after the healthy answer, during the step or the pause after it, fails the step "the node rolled back or restarted"; (2) `edge` → UpdateEdge(target) (≤ 3 min) and GetInfo `edge_version` = target. No revert (the launcher and the edge handoff cancel themselves); a failure stops the rollout. Nodes on other rollouts are refused by the per-node rule, so updates of different nodes may run at once. Single-node buttons are one-node rollouts.
- Kit source: `/api/node-kit/{arch}` and the SSH install send the running panel's version: the image kit when its version is the panel's, else the cache's `postern-node-linux-<arch>` (fetched on demand), else the image kit with a log warning that the versions differ.

**Tests:** executor against an in-process fake NodeService over mTLS (as the connmgr tests): agent + edge happy path; success only after `healthy`; PermissionDenied → failed; reconnect with the old version → failed; `agent_started` during the pause → failed; UpdateEdge Aborted → failed; rollback flag only for the recorded previous; an edge-only rollout to a version the node lists in `binaries`, with none in the cache; missing capability, a target above the panel or below its previous minor, an unsigned image kit → refused; two one-node rollouts on two nodes at once; KitSource picks the image kit, the cache, the fallback; GetInfo fields stored and shown on the Node.

**Steps:** proto + regen → tests → FAIL → implement → PASS → commit `feat(panel): node and edge updates from signed releases`.

---

### Task 13a: Versions page

**Lane:** `lane/s5-panel` after Task 12 · **Model:** sonnet

**Files:** Create `web/src/pages/Versions.tsx` (+ test), `web/src/components/{ComponentCard,ReleaseList,RolloutDialog,RolloutView,PanelUpdateCard,ReleaseSourceForm,NodeVersionsTable}.tsx` (+ tests), `web/src/api/hooks/versions.ts`; modify `router.tsx`, `AppShell.tsx` (navigation), `i18n/{ru,en}.json`.

**Interfaces:** Consumes `VersionService` (every RPC; per-RPC request types), `NodeService` (`agent_version`, `edge_version`, `previous_agent_version`, `node_binaries`, `healthy`, `warnings`, capabilities), `POST /api/releases/upload` (JSON summary per asset).

**Requirements:** per component: channel versions, newest, "Update <channel> to <version>" (RolloutDialog: mode manual/auto, pause, canary proxy or node, skip offline) and the release list (stable/prerelease badges, per-arch state and reason, checksum source, Prepare/Recheck, notes as plain text with `white-space: pre-wrap`, never HTML); default channel select (with the confirmation listing affected proxies); refresh (shows "too soon" from UNAVAILABLE); active and recent rollouts (RolloutView polled every 2 s while active: steps, items done and deferred, errors; Continue only when paused, Retry only when failed, Pause when running, Abort when running, paused or failed; a conflict message names the rollout holding the node or channel); panel card (version, image version, newer releases, Update with a confirm naming the version, the reason when it cannot, last outcome, a warning when `trusts_test_keys`); release source form (tokens write-only); bundle upload with progress and the per-asset result; nodes table (agent, edge, previous binary, healthy, warnings, capabilities; "Update nodes" → node rollout with agent/edge checkboxes). RU and EN for every string.

**Tests (vitest):** RolloutDialog builds the StartRollout request for each kind and mode; RolloutView buttons per status; release notes containing `<img src=x onerror=alert(1)>` render as text; the upload shows each asset's result; the channel confirmation lists the affected proxies; i18n ru/en key parity.

**Steps:** tests → FAIL → implement → `npm run lint && npm run typecheck && npm test -- --run && npm run build` (in `web/`) → commit `feat(web): versions page with rollouts and updates`.

---

### Task 13b: Proxy, node and overview views of versions

**Lane:** `lane/s5-panel` after Task 13a · **Model:** sonnet

**Files:** Create `web/src/components/SwitchEngineDialog.tsx` (+ test); modify `ProxyDetail.tsx`, `Proxies.tsx`, `ProxyTable.tsx`, `NodeDetail.tsx`, `Overview.tsx`, `i18n/{ru,en}.json`, tests.

**Interfaces:** Consumes `ProxyService` (`engine`, `engine_version`, `version_source`, `channel`, status `running_engine`/`running_version`/`failed_version`, filters `engine`/`outdated`, UpdateProxy `engine_version`), `VersionService` (`StartRollout` kinds `switch` and `node`, `SetNodeChannel` with `confirm`, `ListReleases`), `NodeService` (`engine_channel`, `engine_channel_default`, capabilities, `warnings`).

**Requirements:** Proxy page: «работает» (running engine + version) and «должна быть» (effective + source); "Switch engine" (SwitchEngineDialog: mtg disabled with the reason when the proxy has an ad tag, overrides, a mask target that is not a public IP, a WEB type, or the node lacks `engine-mtg`) → a one-proxy `switch` rollout; pin/follow-channel select from versions that have a pin. Proxies list: engine column, running/desired, filters engine and outdated, bulk "Switch engine/version" → a `switch` rollout for the selected proxies. Node page: channel select (default/stable/latest) with the confirmation listing affected proxies; versions with Update agent / Roll edge (one-node rollouts); warnings shown (`edge-handoff-unsafe`: "re-run install.sh"; `test-release-keys`). Overview: an "update available" badge per channel. RU and EN.

**Tests (vitest):** SwitchEngineDialog disables mtg with each reason; the outdated filter sends `outdated=true`; bulk switch sends the selected ids; the channel select shows the affected list before confirming; node warnings rendered; i18n parity.

**Steps:** tests → FAIL → implement → `npm run lint && npm run typecheck && npm test -- --run && npm run build` → commit `feat(web): engine and version views of proxies and nodes`.

---

### Task 14: Versions end-to-end

**Lane:** dev after every slice-5 lane has merged · **Model:** opus

**Files:** Create `test/e2e/versions_test.go` (tag `e2e`), `test/e2e/releasehost.go`, `test/e2e/flood.go`, `test/e2e/testdata/badengine/main.go`; modify `test/e2e/node.go` (the installed binary is named `postern-node-<version>`, as install.sh names it), `scripts/e2e.sh`, `.github/workflows/ci.yml` (e2e timeout 30 min, run through `scripts/e2e.sh`), `docs/testing/e2e.md`.

**Interfaces:** Consumes the e2e harness (`newEnv`, `startPanel`, `installNode`, `waitApplied`, `probeUntil`, `expectOpen`, `checkLinks`, `telemtIdle` = 60 s, `heldMargin` = 10 s, the log scan), the panel API (VersionService, ProxyService, NodeService), `probe.FakeTLS`, `probe.Handshake`, `probe.L2` (online), `release.Sign`, `go run ./scripts/release keygen --unencrypted`.

**Requirements:**
- `scripts/e2e.sh` makes a throwaway key pair in the work dir and builds, with `-X …/internal/release.extraPublicKeys=<public key>`: postern-panel `v0.90.1-e2e`, postern-node `v0.90.0-e2e` (installed) and `v0.90.1-e2e` (the update, signed for `linux/<arch>`), and the stand-in engine; it passes their paths and the key path in the environment. Without that environment the test builds them itself when `go` is on PATH, else skips with a message.
- `releasehost.go`: HTTP on `127.0.0.1` in GitHub's shape: `/repos/telemt/telemt/releases` → `3.5.90` (the real telemt 3.5.13 musl binary repacked into a new tar.gz, with its `.sha256`) and `3.5.91` (the stand-in: for `healthcheck` it prints `[telemt] healthcheck failed: config load failed: e2e` and exits 1, otherwise exits 3; a static Go build for the daemon's arch); `/repos/urbnywrt/postern/releases` → `v0.90.1-e2e` with `postern-node-linux-<arch>` + `.minisig`; the release lists of other repos → `[]`; the downloads; anything else 404 (no stable list). The panel gets `POSTERN_GITHUB_API=http://127.0.0.1:<port>`. telemt 3.5.13 and mtg v2.2.8 come from GitHub through the built-in pins (skip when GitHub is unreachable, as today). The blue-green gate's datacenter check runs as the slice-2 e2e sets it up. The test polls `ListReleases` until the fake versions appear (no `RefreshReleases`, which may be too soon after start).
- Held connections (R5-2, F11): right before each change, one fake-TLS connection per proxy that the change moves, checked with `expectOpen` within `telemtIdle − heldMargin` of its handshake, after the route moved or the new edge answered; a change too slow for that fails with a message. With `POSTERN_E2E_ONLINE=1` they are L2 sessions that exchange `req_pq_multi`/`resPQ` with DC2 every 10 s for the whole test instead.
- Prober: an L1 probe every 250 ms, alternating the proxies, counting failures for the whole test (paused only during the negative flood run).
- Flood (`flood.go`, R5-2, F2): during an edge roll, 32 workers open short connections back to back (connect, fake-TLS handshake to a proxy, close) and count failures; the sysctl `net.ipv4.tcp_migrate_req` of the listeners' network namespace is read and set with a privileged helper container on the host network, and restored at the end.
- One test, ordered subtests on one node (several nodes are covered by Tasks 10a/10b/12 and Task 16):
  1. Node on channel `latest`; proxies A and B (telemt, following the channel) SERVING on 3.5.13; the prober starts.
  2. StartRollout(`version`, telemt, latest, 3.5.90, auto, pause 2 s): held connections on A (step 1) and B (step 2); steps [A, rest of the node] → `completed` within 5 min; both run 3.5.90; the channel version is 3.5.90.
  3. StartRollout → 3.5.91: step 0 (A) fails as the stand-in exits; the rollout is `failed`, A's effective version is back to 3.5.90 (source channel) and A serves on the generation it had; B's instance generation is unchanged; event `rollout_failed`; Abort clears it.
  4. StartRollout(`switch`, mtg, [B]) → `completed`; B runs mtg v2.2.8; GetProxyLinks(B) byte-equal to before; L1 with B's secret passes through mtg (the proof the link still works); the held connection on B's telemt generation still open; switch back to telemt → links equal again.
  5. With `tcp_migrate_req` = 1: StartRollout(`node`, postern-node, v0.90.1-e2e, agent and edge) with the flood during the edge roll → `completed` (the agent `healthy` on v0.90.1-e2e, `edge_version` v0.90.1-e2e on a new generation), held connections open, the flood saw 0 failures.
  6. Negative run: the prober paused, `tcp_migrate_req` = 0, an edge-only `node` rollout back to `v0.90.0-e2e` (the node keeps that binary as `previous`) with the flood → at least one failure (otherwise the test fails: "the flood did not reach the accept queue, so the zero-failure run proves nothing"; tune the flood until 5 of 5 local runs fail at 0 and record the numbers); then 1 again and an edge-only `node` rollout to `v0.90.1-e2e` with the flood → 0 failures.
  7. The prober saw 0 failures; the log scan for secrets passes.

**Steps:** write the test → iterate until PASS (`bash scripts/wsl 'bash scripts/e2e.sh -test.run TestVersions'`) → commit `test(e2e): rollouts, engine switch and node update without downtime`.

---

### Task 15: Stable channel job

**Lane:** dev after Task 14 · **Model:** opus

**Files:** Create `.github/workflows/stable.yml`, `scripts/stable.sh`; modify `scripts/release/main.go` (+ tests: `candidates`, `stable-add`, `stable-sign`), the e2e tests (version overrides), `docs/releasing.md`.

**Interfaces:** Consumes `releases.FetchReleases`, `releases.Limiter` and the checksum and extraction rules (as a library from the tool), `release.Sign/VerifyWith`, the e2e (`scripts/e2e.sh`), the egress e2e of slice 2. Produces env overrides `POSTERN_E2E_TELEMT_VERSION`, `POSTERN_E2E_MTG_VERSION`, `POSTERN_E2E_XRAY_VERSION`, `POSTERN_E2E_WARPPLUS_VERSION`: the e2e's release host serves that upstream version (bytes and checksum from upstream) and the tests run on it.

**Requirements:** weekly schedule + manual dispatch, only where the e2e runs (Ruling 29). Job `candidates`+`e2e` (no secrets): per component the newest upstream release newer than its newest stable entry whose assets pass the checksum rules and the static-ELF check; each candidate runs the matching e2e with its override (telemt: the slice-1 test and `TestVersions`; mtg: `TestVersions`; xray and warp-plus: the egress e2e); passing candidates (with their SHA-256) are the job's artifact. Job `stable-sign` (`needs: e2e`, in a protected environment that alone holds the stable key `POSTERN_STABLE_KEY` and its password; no candidate code runs there): `stable-add` (sorted; a version is dropped only by a deliberate `--drop <component>@<version>` in a manual dispatch), `stable-sign` (`generated_at` = now, stable key), then replace the assets of release `engines-stable` (made when missing): on GitHub `gh release upload --clobber`, on Gitea delete the attachment of that name and upload the new one (duplicates are kept otherwise). Failing candidates are listed in the job summary and not added.

**Tests:** candidates against a fake API (newer only, unusable skipped); stable-add sorting, dedupe, `--drop`; sign/verify round trip with a test stable key, refused by a release key; `scripts/stable.sh --dry-run` against the fake API; actionlint and shellcheck; the e2e jobs' environment holds no signing secret (a workflow lint check).

**Steps:** tests → FAIL → implement → PASS → commit `ci: stable channel of engines from end-to-end runs`.

---

### Task 16: Real-server check (controller)

Not an implementation task. On the two clean test servers (the panel on one, a node on each), with binaries built by `scripts/release.sh` (a test key through `extraPublicKeys` until the owner's keys exist) and install.sh from the kit (which sets `tcp_migrate_req`): proxies on both nodes follow `latest`; a rollout to telemt 3.5.12 and then the one button back to 3.5.13 while the controller's machine runs L1 probes through both nodes every 250 ms and a real Telegram client stays connected — zero probe failures, the client never reconnects; during an edge roll, a flood of short connections from the controller's machine sees no failure; a canary failure (Telegram's datacenters dropped with iptables on the canary node for the duration, so the blue-green gate fails; rules removed afterwards) stops the rollout at the canary and reverts it; one proxy switched to mtg and back, its link compared byte for byte and used by a real client (L2 from the panel when DCs are reachable); a node update (agent + edge) with a held connection; a deliberately crashing signed node build to confirm the launcher rolls back after three starts under Docker's restart policy, and a build that writes the marker and then crashes, which the panel's node update must fail; one node switched to `artifact_source = direct` fetches a new version itself, and with GitHub blocked on it falls back to the panel's upload; a panel update from an uploaded bundle, then a failing panel build to confirm the launcher rollback and the database restore. Results go to the final report.
