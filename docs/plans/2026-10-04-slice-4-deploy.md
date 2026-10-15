# Postern Slice 4 (Deployment) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nodes are installed from the panel over SSH, with a preflight of the server, and the management of a node can hide behind the port of its proxies.

**Architecture:** The panel gains an SSH client (host-key TOFU, no stored credentials unless asked, sealed when stored) and a job runner whose logs the UI polls. SSH installs upload the node kit (slice 1 Task 24) and the bundle and run `install.sh`.

**Tech Stack:** Go 1.27, `golang.org/x/crypto/ssh`, existing packages (`internal/pki`, `internal/seal`), React UI.

**Spec:** `docs/design/2026-10-04-postern-design.md` §9 (deployment), §7 (node kit, artifacts), §10 (security).

**Depends on:** slice 1 Task 24 (node kit); Task 4b runs after slices 2 and 3.

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply verbatim.
- **SSH:** `golang.org/x/crypto/ssh`; auth by password or private key (+ passphrase); host keys: first contact shows the SHA-256 fingerprint and the admin must confirm it (stored per node, `ssh_host_key`); a changed key is refused with both fingerprints shown; no agent forwarding, no port forwarding, no PTY; commands as root or through `sudo -n` (passwordless); dial timeout 15 s, per-command timeout explicit (default 120 s, installs 15 min); credentials are not stored unless "remember" is ticked, then sealed (`ssh_secret_enc`, AAD `ssh:<node id>`); never logged; command output kept in job logs is scrubbed (secrets known to the job are replaced by `***`) and capped at 1 MiB per job.
- **Uploads over SSH** use `exec` with stdin (`umask 077; cat > <tmp> && mv -f <tmp> <path>`), never SFTP; remote paths are fixed by the code, never taken from the operator.
- **Docker install over SSH** (only with explicit confirmation in the wizard): `https://get.docker.com` first; if it fails, distro packages (`docker.io` + `docker-compose-v2` on Debian/Ubuntu); userns-remap must be off (§7).
- **Store migrations** follow `0001_init.sql` and `0002_node_errors.sql`, which `dev` owns: this slice's are `0006_ssh_jobs.sql` (Task 1) and `0007_use_middle_proxy.sql` (Task 3).

---

### Task 1: Panel SSH client and job runner

**Model:** opus

**Files:** Create `internal/panel/sshx/client.go` (dial, host-key policy, run, upload), `internal/panel/sshx/client_test.go` (in-process SSH server from `x/crypto/ssh` test helpers), `internal/panel/jobs/jobs.go` (job table, bounded scrubbed log, status), `internal/panel/jobs/jobs_test.go`; store migration `0006_ssh_jobs.sql`: `ssh_targets(node_id PK, host, port, user, host_key, auth_kind, secret_enc, updated_at)`, `jobs(id, node_id, kind, status, log, started_at, finished_at, error)`.

**Interfaces (Produces):**

```go
package sshx
type Target struct{ Host string; Port int; User string; HostKey string /* "SHA256:..." or "" for first contact */ }
type Auth struct{ Password string; PrivateKeyPEM []byte; Passphrase string }
type Client struct{ /* … */ }
func Dial(ctx context.Context, t Target, a Auth) (*Client, *HostKeyResult, error) // HostKeyResult{Fingerprint string; FirstContact bool}; with HostKey "" it returns ErrHostKeyUnconfirmed + the fingerprint and no client
func (c *Client) Run(ctx context.Context, cmd string, stdin io.Reader, out io.Writer) (exitCode int, err error)
func (c *Client) Upload(ctx context.Context, path string, mode os.FileMode, r io.Reader) error
func (c *Client) Close() error

package jobs
type Runner struct{ /* store, scrubber */ }
func (r *Runner) Start(ctx context.Context, nodeID, kind string, secrets []string, fn func(ctx context.Context, log io.Writer) error) (jobID string, err error)
func (r *Runner) Get(ctx context.Context, id string) (Job, error) // status: running | done | failed | cancelled; log tail
```

**Requirements:** Global Constraints (SSH, uploads). `sudo -n` wrapping when `User != "root"`, with a clear error when sudo needs a password. Jobs survive a page reload (DB), one running job per node, cancellation via context, logs capped at 1 MiB (oldest lines dropped with a marker), scrubbing of the job's secrets in every line.

**Tests:** in-process SSH server: password and key auth, host-key first contact / confirmed / changed, command exit codes, stdin, upload path and mode, timeouts, sudo wrapping; jobs: cap, scrub, single running job per node, persisted status after restart.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/sshx/... ./internal/panel/jobs/...'` → PASS → commit `feat(panel): SSH client and job runner`.

---

### Task 2: Install a node over SSH

**Model:** opus

**Files:** Create `internal/panel/deploy/preflight.sh` (embedded POSIX sh, prints one JSON object), `internal/panel/deploy/service.go` (`DeployService`), tests; `proto/postern/panel/v1/deploy.proto` (+ regen Go/TS); web wizard `web/src/pages/NodeInstall.tsx`, components for the fingerprint confirmation, preflight report and job log; i18n RU/EN.

**Requirements:** `DeployService.Preflight(target, auth)` → facts: OS/arch, Docker and Compose versions, userns-remap, free space on `/opt`, listening TCP ports with process names (`ss -ltnpH`), public IPv4/IPv6, clock skew vs the panel, whether port 443 and the node's management port are free. `DeployService.Install(node_id, target, auth, install_docker bool, remember bool)` → job: (optional Docker install) → upload node kit for the detected arch + bundle to `/root/postern-install/` (0700) → `bash install.sh --bundle … --binary ./postern-node` → remove the bundle → wait for the node to come online (timeout 3 min) → job done. Refuses when the kit for the arch is missing, when 443 or the management port is taken by something that is not Postern, or when userns-remap is on. Re-running is idempotent. UI: target form → fingerprint confirmation → preflight report (warnings highlighted) → install with live log (polling every 1 s) → node online.

**Tests:** preflight script parsed from canned outputs of Ubuntu 24.04, Debian 12, Alpine (busybox `ss` variants) and a host where the containers of another stack hold 443; service against the in-process SSH server with a fake shell that records commands and uploads; refusal cases; UI tests for the wizard steps.

**Steps:** tests → FAIL → implement → PASS → commit `feat(panel): install nodes over SSH`.

---

### Task 3: telemt engine overrides (whitelist)

**Model:** sonnet

**Files:** Modify `internal/engines/telemt/config.go` (render overrides), `internal/engines/driver.go` (drop `ErrOverridesUnsupported` for telemt), `internal/node/state/validate.go`, `internal/panel/proxies/validate.go`, store column `use_middle_proxy` (migration `0007_use_middle_proxy.sql`; `auto` | `on` | `off`, default `auto` = on when an ad tag is set) and its state-builder mapping; tests.

**Requirements:** `engine_overrides_json` is a JSON object whose keys come only from this whitelist, each with its type and range: `fast_mode` bool, `me2dc_fallback` bool, `me2dc_fast` bool, `me_keepalive_enabled` bool, `me_keepalive_interval_secs` int 1–3600, `me_keepalive_jitter_secs` int 0–600, `me_keepalive_payload_random` bool, `me_reconnect_backoff_base_ms` int 1–600000, `me_reconnect_backoff_cap_ms` int 1–600000, `me_reconnect_fast_retry_count` int 0–1000, `desync_all_full` bool, `me_writer_pick_mode` string ∈ {`p2c`, `sorted_rr`}, `me_warmup_stagger_enabled` bool, `me_warmup_step_delay_ms` int 0–60000, `me_warmup_step_jitter_ms` int 0–60000, `upstream_connect_retry_attempts` int 0–100, `upstream_connect_retry_backoff_ms` int 0–600000, `tg_connect` int 1–600, `rst_on_close` string ∈ {`off`, `errors`, `always`}, `update_every` int 1–86400, `server_client_mss` int 0–65535, `me_init_retry_attempts` int 0–1000, `network_prefer` string ∈ {`system`, `ipv4`, `ipv6`}, `tls_emulation` bool (`[censorship]`), `tls_front_dir` string (path-safe, `[censorship]`). Keys Postern owns are refused with a message naming the reason: `log_level` (telemt prints links at higher levels), `stun_servers`/`stun_use` (no STUN), `beobachten*` and `unknown_dc_file_log_enabled` (no files in a read-only container), anything about listeners, upstreams, users, `ad_tag`, `middle_proxy_nat_ip`. Rendering keeps Postern's own lines authoritative and adds overrides in their sections. Check every key against the telemt 3.5.13 config reference (`docs/` of the release) and record the source in a comment; drop a key from the whitelist if 3.5.13 does not have it.

**Tests:** golden configs with overrides; refusal per owned key; type and range errors; panel/node parity of the whitelist (one table shared or a parity test).

**Steps:** tests → FAIL → implement → PASS → commit `feat(engines): telemt overrides from a whitelist`.

---

### Task 4b: Hidden management mode

**Model:** sonnet · added by Ruling S6-1 (slice 6 plan) after slices 2 and 3 merged.

**Files:** Modify `internal/node/agent/proxylistener.go` (+ test), `internal/node/agent/run.go` (hidden listener), `internal/node/reconcile` (mgmt route), `proto/postern/node/v1/node.proto` (`NodeSettings`), `internal/panel/proxies/statebuilder.go`, `validate.go`, `internal/panel/nodes` (mode switch, dialing with `mgmt_sni`), the node page in `web/`, i18n; `test/e2e` (one case).

**Requirements:** spec §5.3 ("SNI управления") and §6 (PKI, `mgmt_sni`).
- **PROXY v2 listener first** (from slice 6 Task 4's review): `run()` retries temporary `Accept` errors (`ECONNABORTED`, `EMFILE`, `ENFILE`, any `net.Error` with `Temporary()`/timeout) with a backoff of 5 ms doubling to 1 s instead of ending the loop; `Accept` prefers `done` after `Close` (a closed listener never hands out a connection); connections still reading their header are closed on `Close`.
- **Agent.** A hidden management listener on `127.0.0.1:<port>`, the port allocated once from the `service` range (key `mgmt-hidden`, kept in `runtime.json`), wrapped by `newProxyV2Listener`, serving the same mTLS handler as the plain listener. It runs whenever `NodeSettings.mgmt_sni` is set. The plain listener refuses PROXY (unchanged).
- **Edge route.** When `mgmt_sni` is set, the reconciler adds a route of kind `mgmt` (SNI = `mgmt_sni`, backend = the hidden listener, `proxy_protocol` on) to every public `tls` listener. A `mgmt_sni` equal (after folding) to a proxy domain or a pool domain on that listener is refused by both validators.
- **Plain listener off.** `NodeSettings.mgmt_hidden_only` (next free number; 7 is reserved, 8–10 are slice 6's): the agent closes the plain listener. **Fallback:** if no request authenticated by the panel's client certificate arrives through the hidden listener for 15 min while the plain one is off, the agent reopens the plain listener and records event `mgmt.fallback` (the reason, never a secret); it closes it again after the next authenticated request through the hidden one.
- **Panel switch** (node page: mode `port` | `hidden`, `mgmt_sni`, the public port to use): to hidden — push state with `mgmt_sni` → dial `mgmt_host:<public port>` with TLS `ServerName = mgmt_sni` (verification unchanged: CA chain + pinned fingerprint, no hostname check) → `GetInfo` OK → store mode `hidden` and the port → push `mgmt_hidden_only`. Back to port — push without `mgmt_hidden_only` → dial the plain port → `GetInfo` OK → store mode `port` → push without `mgmt_sni`. A failed check leaves the stored mode unchanged and shows the reason. Audit `node.mgmt_mode`.
- `checkMgmtPort` keeps refusing a listener on the plain management port in mode `port`.

**Tests:** listener: a temporary Accept error does not end the loop; Close wins over a ready connection; a header-less connection is closed. Reconcile: mgmt route rendered on every tls listener only with `mgmt_sni`. Agent: the fallback reopens the plain listener (shortened timers) and closes it again. Validators: `mgmt_sni` colliding with a proxy/pool domain refused. Panel: switch to hidden and back against a fake agent, failed check keeps the mode. e2e: the panel reaches `GetInfo` through the public port with `mgmt_sni` (spec §5.3), and a stranger with that SNI but no client certificate is refused at the TLS handshake.

**Steps:** tests → FAIL → implement → PASS (race once on `./internal/node/agent/...`) → commit `feat(node): hidden management through the proxy port`.
