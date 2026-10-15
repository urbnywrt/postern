# Postern Slice 6 (Statistics, Diagnostics, Public Page) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Statistics the owner can trust and diagnostics that find the first broken link of client → edge → engine → egress → Telegram: minutes, hours and days with configurable retention; graphs of traffic, connections and unique IPs per proxy and per node; top proxies; client countries from an offline DB-IP database and, when the IP policy allows it, IP history; egress member history; a full report per node or proxy with one-click safe fixes, light checks that run all the time, full runs before and after every operator change, probes from the panel and from the node, a problem feed and a journal; and the public page with proxy links on a domain of its own.

**Architecture:** On the node the agent keeps turning edge snapshots into minutes and adds client countries (looked up on the node in a DB-IP database that the panel uploads with its own call, so that no client address leaves the node under the `countries` policy), per-minute egress member health, the edge's refusal counters and node probe results to `StatsBatch`; it filters what it sends by the IP policy at send time. A check catalogue (`internal/node/diag`) runs its light checks continuously — results reach the panel as a new `Watch` record when a status changes — and all checks of a scope on `RunDiagnostics(scope)`, a server stream (spec §6). The panel stores per-minute rows and recomputes hours and days from them (replays replace, never add), makes retention configurable, keeps deleted client addresses off the disk, serves a statistics API, probes every proxy from outside (the edge exempts the panel's exact addresses, bounded), adds its own checks to every run, runs a full check before and after every operator change, applies fixes declaratively (nonces and settings in the desired state, audited), keeps the GeoIP database current, and renders the public page for one configured `Host` only.

**Tech Stack:** Go 1.27; `github.com/oschwald/maxminddb-golang/v2` (MMDB reader, `OpenBytes`); `github.com/yuin/goldmark`, newest release (Markdown of the public page); `github.com/maxmind/mmdbwriter` (test databases only); `html/template`; React 19, Mantine 8.3 and `@mantine/charts` 8.3 on recharts 3 (already installed: no new UI dependency).

**Spec:** `docs/design/2026-10-04-postern-design.md` §3 (tables, retention, the "unique IPs" label), §5.3, §5.7 (diagnostics), §5.8 (node statistics), §6 (protocol), §8.1, §8.2, §8.3 (screens), §8.4 (statistics), §8.5 (public page), §8.6 (IP policy), §11, §13, §14.

**What exists (build on it, do not rebuild):**
- Node: `internal/node/agent/stats.go` (minutes from edge snapshots every 10 s, increments per edge generation, IP sightings only under `IP_POLICY_FULL`, 10,000 sightings a minute at most, IP baseline `ipFull && !a.ipsAsked`), `buffer.go` (`data/stats.db`, 7 days, ≤ 1,000,000 records, `ScrubIPs` when the policy leaves full, `forPanel` strips IPs unless full), `Watch` replay from the panel's cursor; edge `Snapshot` with per-IP counters on request, member health and the counters `refused_prehello`, `refused_total`, `evicted_prehello` (not forwarded yet).
- Probes: `probe.FakeTLS` (L1), `probe.Handshake`, `probe.L2`, `probe.DCPing`, `probe/probetest` (slice 2); the blue-green gate of slice 2 (`internal/node/reconcile/gate.go`: DC ping through an instance's SOCKS port, getProxySecret, L2 through the test listener with `EdgeConfig.probe_routes`); `state.TestListenerPortKey`.
- Reconciler: a serving engine container that is `exited` or `created` is started again, `dead` is replaced, `paused` is left alone (Docker reports `Running=true`; `adoptEngines` in `internal/node/reconcile/instances.go`).
- Panel: `store/stats.go` (1m/1h/1d tables, rollups, prune with fixed 48 h / 90 d / 7 d), table `ip_sightings` (never written yet), `proxies/ingest.go` (minutes, statuses in memory, events), `StatsService.ProxyLive`/`ProxySeries`; the state builder hard-codes `IP_POLICY_OFF`; nodes keep `last_error`, `state_rejection`, capabilities and port owners; slice 2's panel (lane/s2 c5cf67d) has `UpdateProxy` (`egress_chain_id`, `egress_scope_chains`), `SetNodeDefaultChain`, `UpdateEgress`, `RefreshSubscription`, `SetNodeDnsMode` in `internal/panel/proxies` and `internal/panel/egress`; UI `TrafficChart` (24 h), `LiveStats`, the label "Unique IPs".
- Not in the schema yet (spec §3): `egress_health`, `probes`, `public_page`, `public_page_items`.
- Not built by any slice plan: the hidden management listener of spec §5.3 (PROXY v2, then mTLS). Task 4 adds the listener wrapper it needs for the panel's address.

## Ordering and lanes

Slice 6 touches files that slices 2–5 also change. Wave 1 is panel-only and starts now; everything that touches node or edge contracts waits for the slice-2 merge; the WEB and edge pieces wait for slice 3, and the rollout hooks for slice 5.

| Task | Start | Needs | Lane (suggested) | Shared files to watch at merges |
|---|---|---|---|---|
| 1 Store: schema, settings, ingest, rollups, privacy | now, from `dev` | — | `lane/s6` | `store/migrations` (number), `store/store.go`, `store/stats.go`, `server/maintenance.go` |
| 1b Store: read API | after 1 | 1 | `lane/s6` | `store/stats.go`, `proxies/service.go` (`ProxySeries` call) |
| 2 GeoIP (panel) | now, from `dev` | — | `lane/s6-geoip` → into `lane/s6` before wave 2 | `go.mod`, `server/*`, `cmd/panel/serve.go`, READMEs |
| 3 Public page: backend | after 1b | 1 | `lane/s6` | `server/api.go` (slice 4 adds services), `proxies/service.go` (`GetProxyLinks`, also changed by slice 2 T7, slice 3 T4, slice 5 T9) |
| 3b Public page: admin UI | after 3 | 3 | `lane/s6` | `Settings.tsx`, `web/src/i18n/*` |
| 4 Node contracts and fix knobs | slice 2 merged into `dev`, then `dev` into `lane/s6` | — | `lane/s6` | `node.proto` (slices 3–5), `state/validate.go`, `reconcile/{instances,edgemgr}.go` (slice 5 T6), `agent/server.go` |
| 5 Node statistics and privacy | after 4 | 2, 4 | `lane/s6` | `agent/{stats,buffer,server,run}.go` |
| 6 Panel ingest, settings, node settings | after 4 | 1, 2, 4 | `lane/s6-panel` (beside 5) | `proxies/{ingest,statebuilder}.go`, `nodes/connmgr.go`, server wiring |
| 7 Statistics API | after 6 | 1b, 6 | `lane/s6-panel` | `proxies/service.go` |
| 8 Panel probes | slice 2 merged (`probe.L2`) | 1, 1b, 3 | `lane/s6-probes` (beside 4–7) | `server/server.go` |
| 9a Node diagnostics: framework, host checks | after 5 | 4, 5 | `lane/s6` | `agent/{buffer,server,run,info}.go` |
| 9b Node diagnostics: engine checks | after 9a | 9a | `lane/s6` | `engines/*` (slice 5 T4), `dockerapi` (slice 5 T3) |
| 9c Node diagnostics: egress and e2e checks | after 9b | 9a | `lane/s6` | `reconcile/gate.go` |
| 10a Panel diagnostics: runs and light checks | after 6, 8, 9a (side lanes merged into `lane/s6`) | 6, 8, 9a | `lane/s6` | server wiring |
| 10b Panel diagnostics: fixes, before/after | after 10a | 10a, slice 2 Task 7 | `lane/s6` | `proxies/service.go` (`mutate`), `internal/panel/egress`, `nodes/service.go` |
| 10c Panel diagnostics: problem feed, journal | after 10a | 10a | `lane/s6` | — |
| 11a UI: proxy and node statistics | after 7 | 3b, 7 | `lane/s6-panel` | `ProxyDetail.tsx`, `NodeDetail.tsx` |
| 11b UI: Overview, Settings, About | after 11a | 2, 3b, 6, 7 | `lane/s6-panel` | `Overview.tsx`, `Settings.tsx`, `NodeCard.tsx`, `AppShell.tsx` |
| 12 UI: diagnostics, probes, feed, journal | after 10b, 10c, 11b | 8, 10a–c, 11b | `lane/s6` | the same pages, `router.tsx`, `AppShell.tsx`, the proxy/egress/chain/DNS forms of slices 1–2 |
| 13 WEB diagnostics and the certificate fix | slice 3 merged | 9c, 10b | `lane/s6` or `dev` | `node.proto` `WebSettings`, `internal/node/acme`, `internal/panel/preflight` |
| 14 Edge probe sources | slice 3 merged | 4, 6 | `lane/s6` or `dev` | `edge.proto`, `internal/edge/*` (slice 3's `web.go`), `reconcile/edgecfg.go` |
| 15 Rollout hooks | slice 5 Task 10 merged, with its revision's hook amendments | 10a, 10b | `lane/s6` or `dev` | rollout runner wiring, Versions UI |
| 16 End-to-end | after 1–12; its Task-14 assertion when 14 is merged | 1–12 | `dev` after `lane/s6` merges | `test/e2e` |
| 17 Docs and acceptance checklist | after 16 | all | `dev` | `docs/` |

Wave 2 starts when slice 2 is merged into `dev`: `lane/s6` (with `lane/s6-geoip` merged in) merges `dev` first, and the side lanes `lane/s6-panel` and `lane/s6-probes` branch from `lane/s6` after that merge. They merge back into `lane/s6` before Task 10a (Tasks 6, 7, 8) and again before Task 12 (Tasks 11a, 11b). `lane/s6` merges into `dev` after Task 12 passes review; wave-3 tasks (13–16) then run on `dev` or a fresh lane from it, each when its slice is merged. Task 17 skips its Task-14 assertion, with a message, while Task 14 is not merged; Tasks 13, 15 and 16 bring their own tests (the end-to-end tests of slices 3, 5 and 4 cover WEB, rollouts and the switchover). Package dependencies stay one-way: `internal/panel/proxies` imports neither `geodb`, `insights`, `probes`, `publicpage` nor `diagnostics` (they reach it through function values set at wiring in `internal/panel/server`).

## Decisions and rulings

Controller rulings carry their ids (R6-n) and supersede the writer's earlier rulings on the same points.

- **Countries are looked up on the node.** The node gets the DB-IP database from the panel through its own upload call (`UploadGeoIP`, outside the artifact store, so that slice 5's trial runs and artifact garbage collection never see a data file) and sends per-minute country aggregates — why: the slices 0–1 plan (Task 14) binds that no `IpSighting` leaves the node under `countries`, so only the node can map addresses — cost if wrong: about 8 MB a month uploaded to each node that uses countries, one more RPC and one more dependency in the node binary.
- **Default IP policy `countries`** (the panel sent `off` until now); at its first start without an `ip_policy` key the panel stores the defaults and bumps every node once — why: aggregates without any stored address are the privacy-safe useful default, and nodes must get it deliberately, not at the next unrelated change — cost if wrong: an owner who wants nothing switches to `off`.
- **R6-5 Privacy across policy changes.** The node filters what it sends by its current policy and by the policy the panel names when it opens `Watch`; on leaving `full` it scrubs its buffer and the open minute before the next send; `full` and `countries` share one "IP counters received" baseline (no absolute-counter spikes). The panel writes the policy and deletes the data in one transaction (leaving `full` deletes `ip_sightings`; `off` deletes the country tables) and drops `CountryMinute` under `off`. Both databases run `PRAGMA secure_delete = ON` and `wal_checkpoint(TRUNCATE)` after deletes and scrubs; backups are kept with `ip_sightings` emptied and vacuumed; diagnostic text passes an IP redactor. Tests grep the database, its `-wal` file and the backups — why: §8.6, §10, and SQLite keeps deleted rows in free pages and in the WAL — cost if wrong: an owner who switches to `off` loses the country history.
- **Country metric = per hour, the most distinct client IPs of the country in one minute ("peak unique IPs in a minute"), plus bytes**, not distinct per day — why: distinct-per-day needs addresses kept across minutes, which `countries` forbids — cost if wrong: users who come and go within an hour are under-counted.
- **R6-6 Idempotent statistics.** Country and egress hours are recomputed from stored per-minute rows, replacing rather than adding, the way proxy hours already are; ingest markers (needed now only for the additive IP history) live 8 days, as long as ingest accepts a minute; a country day (`SUM(bytes)`, `MAX(ips)`) is final before any of its hours is deleted — why: a replay or a minute emitted twice must neither add twice nor freeze a smaller first value — cost if wrong: about 115 MB more at 100 proxies and 100 egress members for the minute rows.
- **`robots.txt` `Disallow: /` and `X-Robots-Tag: noindex` together by default**, as the spec says, although Google never sees a noindex on a page it may not crawl (verified 2026-10-05, https://developers.google.com/search/docs/crawling-indexing/block-indexing) — why: compliant crawlers never fetch the page and its secrets; the header covers the others — cost if wrong: a bare URL may appear in results when someone links it.
- **R6-10 and M18 The public host and the admin.** A configured public host never serves the admin, also while the page is disabled; the panel refuses a public host equal to any name an admin has been served on (recorded) or to the current request's; env `POSTERN_PUBLIC_PAGE=off` turns host routing off for an operator who locked himself out; only the page chrome is cached, items and their availability are rendered for every request; assets come from an embedded allowlist — why: §8.2 "админка недоступна на домене публичной страницы", a hidden or paused proxy must leave the page at once — cost if wrong: one render of the items per request.
- **R6-4 `mark` shows no secret.** A marked item shows only its public name, its note and "unavailable": no link, QR or parameters — why: a paused, offline or failing proxy's link must not stay public — cost if wrong: none.
- **R6-2 Engine log checks.** `engine.log` scans the engine log at the highest telemt level that an integration test proves free of secrets and client addresses, set through the container's `RUST_LOG`, which keeps it out of the instance hash (no engine rolls); API-only only if no such level exists, recorded then as a deviation. Secrets stay out of telemt's log because of `[general.links] show = []`, not because of `silent` — why: §5.7 names "известные ошибки в логах" — cost if wrong: a level that leaks under a condition the test did not cover (the end-to-end log check still guards).
- **R6-3 Full runs before and after operator changes.** Rollout steps (slice 5 hooks), panel egress edits (a proxy's chain and scope chains, the node's default chain, egress parameters, DNS mode) and version pins made outside rollouts get a full run before and after. A panel edit validates, runs a full run of the affected scope (waiting at most 90 s), then commits; when the node is offline, lacks `diagnostics` or the run times out, it commits anyway with a `skipped` or `partial` before-run. A fix uses the run it was offered from as its before-run. Changes the node makes by itself use the light checks as the baseline. A regression is recorded and shown, never turned into a failed rollout step or a rollback; the slice 5 amendments (AfterStep also after a reverted step, the step timer starting after BeforeStep) are made in slice 5's plan and only consumed here — why: §5.7 "до и после обновлений и смены выхода"; an automatic rollback on degradation is a non-goal (§0.2) — cost if wrong: an operator edit waits up to 90 s.
- **Fixes are declarative:** nonces in the desired state (`Proxy.restart_nonce`, `NodeSettings.edge_roll_nonce`, `WebSettings.reissue_nonce`) and the panel's own edits (egress chain, DNS mode, subscription refresh nonce of slice 2); no new imperative RPC — why: spec §2 principle 1, survives restarts, goes through validation and the audit log — cost if wrong: one field per fix.
- **No new automatic fixes**: failover, blue-green abort, ACME renewal and subscription refresh already run by themselves; an automatic engine rollback is a non-goal (§0.2) — cost if wrong: none.
- **R6-1 Probe exemption, exact addresses only.** The edge exempts only the panel's real probe source addresses, as exact `/32` and `/128` addresses, learned from the PROXY v2 source on the hidden management listener and the TCP source on the plain one (the last IPv4 and the last IPv6 seen), plus operator extras that are single addresses (prefixes refused, at most 16). The exemption applies on public listeners only and is bounded: at most 4 exempt connections per proxy at once (further ones are ordinary clients), each closed after 30 s, its bytes still counted in the traffic totals; it takes no device slot and no IP counter. Settings warns when a learned address is private or CGNAT (100.64.0.0/10) — why: a probe must not take the only device slot of a `limit_devices = 1` proxy nor count as a client, and a shared address must not unlimit a whole network — cost if wrong: an operator with a pool of probe addresses lists them one by one (max 16).
- **`egress_health` is hourly** (minutes up/down/unknown, latency average and maximum, exit IP), recomputed from per-minute rows and kept 30 days; probes are kept raw for 7 days; country hours 30 days — why: per-check rows of every member would dominate the database — cost if wrong: no per-check timeline, uptime shown for 24 h and 7 d only.
- **DB-IP attribution next to every country view as well as in About** — why: DB-IP's terms ask for "a link back to DB-IP.com on pages that display or use results from the database" (verified 2026-10-05, https://db-ip.com/db/download/ip-to-country-lite); the spec names About only — cost if wrong: one caption.
- **Light results travel as a `Watch` record (`DiagnosticsReport`) on change; full runs as the `RunDiagnostics` stream; node probe results inside `StatsBatch`** — why: §6 lists the stream; light results are state that must survive a panel outage (buffered); probe results are minute data — cost if wrong: none.
- **The Journal screen (§8.3) ships here**, with the problem feed — why: no slice owns it, and diagnostics without a history of events and fixes cannot be trusted — cost if wrong: one more page.
- **R6-7 Numbers.** `GetInfoResponse` 14–15 and `NodeSettings` 8–11 are taken now (`GetInfoResponse` 11–13 are slice 5's, `NodeSettings` 7 is reserved); the panel's `Node.panel_addrs` takes 30 (slice 2 holds 19–20, slice 5 takes 21 and up); every other proto number and every migration takes the next free number at implementation time — why: a `NodeSettings` clash would make a node read `ip_retention_hours = 168` as another field — cost if wrong: none.
- **R6-8 Task splits.** Tasks 9, 10 and 11 are split into 9a–9c, 10a–10c and 11a–11b, the store and public-page tasks into backend and read API / UI (1, 1b, 3, 3b) — why: each task stays reviewable — cost if wrong: more merges inside the slice.
- **R6-9 Markdown.** The newest goldmark release; the implementer verifies against upstream that the entity-encoded `javascript:` scheme is neutralised (reported as CVE-2026-5160, fixed in goldmark 1.17.6); the goldens include `[x](javascript&colon;alert(1))`, and fuzz tests guard the renderer — cost if wrong: none.
- **Deviations recorded:** a per-member HTTPS check (§5.7 "по каждому звену: DC, HTTPS") waits for an edge health field — HTTPS to `core.telegram.org` is checked per proxy (`egress.me`), while per member the edge checks the datacenters and, through the echo URLs, the exit IP; WEB proxies are probed at the HTTP/2 + decoy level, not at the MTProto level.
- **Public page defaults:** `unavailable = mark`, `default_locale = ru`, `noindex = on`, off until enabled with a host.

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply verbatim (module, WSL runner, `scripts/race.sh`, commits without trailers, hygiene, runner image, labels, port ranges, timeouts). Slice 2's constants apply where used: DoH endpoints `https://1.1.1.1/dns-query`, `https://1.0.0.1/dns-query`, `https://8.8.8.8/dns-query`, `https://8.8.4.4/dns-query`; DC targets `149.154.175.50:443` … `91.108.56.130:443`; `probe.DCPing`/`probe.L2` semantics.
- **Numbering (R6-7).** `GetInfoResponse` 14–15 and `NodeSettings` 8–11 as Task 4 lists them; the panel `Node.panel_addrs = 30`; every other proto field, enum and oneof number and every migration: the next free number on the branch at implementation time. A collision at merge renumbers the later branch and regenerates (desired state and edge config on disk are protojson by name; binary records in a test node's `stats.db` may misdecode, accepted before the first release); migrations are renumbered by the later branch (the store checks names). `GetInfoResponse.capabilities`: union, sorted.
- **UI strings** of this slice go into `web/src/i18n/insights.en.json` and `insights.ru.json` (top-level key `insights`), merged into the `translation` resources in `web/src/i18n/index.ts`; `web/src/i18n/i18next.d.ts` types `translation` as `typeof en & typeof insightsEn`; the ru/en parity test covers them. The label of devices stays "Unique IPs" / "Уникальные IP" (spec §3); charts say "Unique IPs (peak)", per node "Unique IPs, sum of proxies", countries "peak unique IPs in a minute".
- **Hygiene in tests:** addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32 and loopback; hosts `*.example.com`, `*.test` (the e2e public host is `proxies.example.test`). Real hosts appear only as the public endpoints the features need (DB-IP download, DoH endpoints, Telegram).

### Storage and retention

| Table | Kept (default; setting, range) | Rows | ≈ size at 100 proxies, 20 nodes, 100 members |
|---|---|---|---|
| `stats_proxy_1m`, `stats_node_1m` | 48 h (`stats.minutes_hours`, 6–168) | 2,880 per proxy / node | 35 MB + 9 MB |
| `stats_country_1m` | = minutes retention | ≈ 3 countries × 2,880 per proxy (≤ 50 a minute) | 85 MB |
| `egress_health_1m` | = minutes retention | 2,880 per member | 30 MB |
| `stats_proxy_1h`, `stats_node_1h` | 90 d (`stats.hours_days`, 7–730) | 2,160 per proxy / node | 26 MB + 7 MB |
| `stats_country_1h` | 30 d, fixed | ≈ 3 × 720 per proxy (≤ 50 an hour) | 24 MB |
| `egress_health` (hours) | 30 d, fixed | 720 per member | 9 MB |
| `stats_proxy_1d`, `stats_node_1d`, `stats_country_1d` | forever | 365 a year each (× countries) | ≈ 17 MB a year |
| `probes` | 7 d, fixed | ≈ 3,000 per proxy (panel every 5 min, node every 10 min) | 27 MB |
| `ip_sightings` | 7 d (`stats.ip_days`, 1–30), policy `full` only, ≤ 100,000 per proxy | one per proxy and address | 17 MB at 1,000 addresses a proxy |
| `stats_batches` (markers of the IP history) | 8 d, fixed (the age ingest accepts) | 11,520 per node | 12 MB |
| `diagnostic_runs` + `diagnostic_results` | 30 d and ≤ 100 runs a node; evidence of warn/fail only, ≤ 64 KiB a run | ≈ 40 results a run | ≤ 7 MB a node, typically under 1 MB |

About 300 MB plus 17 MB a year at that size, about 30 MB for 10 proxies on 3 nodes; `SettingsService.GetStorage` shows the real numbers. **Node buffer** (`data/stats.db`): 7 days and ≤ 1,000,000 records (exist), ≤ 256 MiB of payload (new: over it, the oldest statistics lose their client addresses first, then the oldest records go), `secure_delete` on; client addresses in it are scrubbed after `ip_retention_hours` (= `stats.ip_days`). A minute of 20 proxies under `countries` is ≈ 3 KB (≈ 30 MB a week); `full` adds ≈ 45 bytes per address sighted in the minute. **GeoIP files:** panel `/data/geoip/dbip-country-lite-<YYYY-MM>.mmdb` and node `data/geoip/<sha256>.mmdb`, current and previous (≈ 8 MB each, read into memory).

### IP policy (spec §8.6, R6-5)

| Policy | Edge asked for client IPs | Node buffers and sends | Panel stores |
|---|---|---|---|
| `full` | yes | sightings (scrubbed after `ip_retention_hours`) and country minutes | `ip_sightings` (country looked up by the panel), country minutes/hours/days |
| `countries` (default) | yes | country minutes only | country minutes/hours/days |
| `off` | no | nothing | nothing (device counts stay: they are numbers) |

- **Send time:** the node sends a sighting only when its own policy and the policy in the panel's `WatchRequest.ip_policy` are both `full` (unset = the node's own), and a country minute only when neither is `off`; this covers records buffered before a change and replayed before the new state arrives.
- **Leaving `full` on the node:** before `ApplyState` returns, the open minute's sightings are dropped and the buffer is scrubbed (exists), then `wal_checkpoint(TRUNCATE)`. `full` and `countries` share one baseline: the per-IP byte counters are taken as increments only after a snapshot in which they were received.
- **Panel:** the policy is written and the data deleted in one transaction — leaving `full` deletes `ip_sightings`, `off` deletes `stats_country_1m/1h/1d` too; ingest stores a sighting only under `full` and a country minute only when the policy is not `off`.
- **On disk:** the panel database and the node buffer run `PRAGMA secure_delete = ON` on every connection; after deleting sightings or country rows and after a scrub, `PRAGMA wal_checkpoint(TRUNCATE)`; the panel's backups are kept with `ip_sightings` deleted and `VACUUM`ed. No new code logs a client address; diagnostic text passes the IP redactor (Diagnostics).

### GeoIP

- Source: DB-IP "IP to Country Lite", MMDB, monthly; `https://download.db-ip.com/free/dbip-country-lite-<YYYY-MM>.mmdb.gz` (8.0 MB for 2026-10); licence CC BY 4.0 with "a link back to DB-IP.com on pages that display or use results from the database"; the page publishes only SHA1/MD5 sums on HTML, which are not used (verified 2026-10-05, https://db-ip.com/db/download/ip-to-country-lite). Record field `country.iso_code` (verified 2026-10-05, https://db-ip.com/db/format/ip-to-country-lite/mmdb.html). When a month's file appears is not documented: try the current UTC month, then the previous one. Env `POSTERN_GEOIP_BASE_URL` replaces the download base (tests).
- Reader `github.com/oschwald/maxminddb-golang/v2`: ISC, pure Go, `Open` / `OpenBytes`, `Lookup(netip.Addr).Decode(&v)`, `Verify()` (verified 2026-10-05, https://github.com/oschwald/maxminddb-golang); the newest v2 tag and its Go requirement: implementer verifies. Files are read into memory and opened with `OpenBytes` (≈ 8 MB): no memory map, so dropping a reader during a lookup cannot fault.
- Test databases: `github.com/maxmind/mmdbwriter` (Apache-2.0 or MIT, verified 2026-10-05, https://github.com/maxmind/mmdbwriter), an IPv6 tree with IPv4 aliasing left on, reserved networks admitted (loopback and the documentation ranges are reserved) — the option's name `IncludeReservedNetworks`: implementer verifies against upstream.
- Attribution text `IP Geolocation by DB-IP` linking `https://db-ip.com`, licence `CC BY 4.0`: in About and under every view of countries. Country names in the UI come from `Intl.DisplayNames`; no flags or fonts from CDNs (§8.4: the browser calls nothing outside).
- To nodes: `NodeSettings.geoip = GeoIPRef{month, sha256}` names the database; the panel streams the file with `NodeService.UploadGeoIP` (meta, then chunks; ≤ 256 MiB) before the state that names it, when the sha256 is not among the node's `GetInfo.geoip_stored`; a failing (node, sha256) is retried at most every 30 min. The node verifies the sha256, opens it as a country database, keeps it as `data/geoip/<sha256>.mmdb` and records event `geoip_stored`. Only for nodes with capability `stats-v2` while the policy is `full` or `countries`. Not an artifact: slice 5's trial runs and artifact GC do not apply to it.

### Probes

- Vantages: `panel` (scheduler) and `node` (light check `e2e.l2`). Stored kinds: `l2` and `web` (web from Task 13) in table `probes`; L1 runs as a light check and to classify a failed L2, and is not stored.
- Panel schedule: every `probes.interval_minutes` (default 5, 0 = off) per enabled proxy of an online node, at an offset = FNV-32a(proxy id) mod interval, each round moved by a random ±20 % of the interval; at most 8 at a time; 10 s each. Fake TLS: `probe.L2` to DC 2 at `<link host>:<listener port>` with SNI = the proxy domain and its secret; on failure `probe.FakeTLS` to classify the error (`unreachable`, `refused the secret`, `no datacenter answered through the proxy (L1 ok)`). Panel probes reveal the fleet to anyone who can observe the panel's traffic; the Settings help text and the docs say so.
- Availability (public page, problem feed): a proxy is down when its last two panel probes failed and the newer one is at most 3 × interval old.
- Exemption (R6-1, Task 14): `NodeSettings.probe_sources` = the panel's addresses as the node saw them (`nodes.panel_addrs`: the last IPv4 and the last IPv6, from `GetInfoResponse.peer_addr`, which is the PROXY v2 source on the hidden management listener and the TCP source on the plain one) plus `probes.extra_sources` (single addresses). A connection of a public listener whose source equals one of them exactly is a probe while its proxy has fewer than 4 exempt connections open: no device slot, no device/total/per-IP limit, no IP counter; its bytes and its connection count in the proxy's totals; it is closed after 30 s. The blacklist and the pre-hello caps still apply; test listeners are unaffected.

### Diagnostics

- Result `{id, layer, target, status, summary, evidence, hint, fix, checked, duration}` (§5.7); `layer` ∈ `host`, `ingress`, `engine`, `egress`, `web`, `e2e`, `panel`; `target` is `""` (node), `listener:<id>`, `proxy:<id>`, `member:<chain id>/<member key>`; status `ok`, `warn`, `fail`, `skip`. Summary ≤ 200 bytes; evidence only for `warn` and `fail`, ≤ 2 KiB a result and ≤ 64 KiB a run or report, plain text.
- **Scrubber** (every text, node and panel): proxy secrets as hex, in their fake-TLS form (`ee` + secret + hex(domain)), in base64 std and url with and without padding, and in their WEB link forms (`dd` + hex, `base64url_nopad(0x70‖secret)`, `base64url_nopad(0x70‖0xdd‖secret)`); ad tags; telemt API tokens; egress parameter values of 8 bytes or more; WARP tokens; DNS credentials → `***`. **IP redactor:** every IP literal (IPv4, IPv6, v4-mapped, with or without port or brackets) that is not one of the node's own service addresses (127.0.0.1, 127.0.0.2, ::1), a public IP of the node, a DC address, a DoH endpoint or an egress member's address → `<ip>`; other loopback addresses are redacted too.
- Light checks are scheduled per (check, target) with jitter, at most 16 at a time; a check whose previous run is still going skips its turn. A 60-s check reports `fail` only after two failing runs in a row (one failing run is `warn`), recovery at once. A `DiagnosticsReport` (the whole light set) is buffered when the set of `(id, target, status, fix)` changed, and sent live-only every 15 min otherwise.
- Scopes: `node` (every check of every target) and `proxy:<id>` (host checks, its listener, its proxy checks, the members of its chain). One full run per node at a time; 3 min at most.

| id | layer / target | light | ok / warn / fail | fix |
|---|---|---|---|---|
| `host.docker` | host / node | 60 s | Docker answers / — / no answer | — |
| `host.clock` | host / node | 10 min | skew ≤ 2 s / > 2 s / > 30 s; skew = distance from local time to [`Date`, `Date` + 1 s] widened by RTT/2, median of ≥ 2 of the four DoH endpoints, `Date` taken from any completed response (4xx too); skip with fewer | — |
| `host.dns` | host / node | 10 min | UDP to 1.1.1.1:53 and 8.8.8.8:53 for a random `<16 hex>.telegram.org` agrees with DoH / blocked (timeout, ICMP) or hijacked (another answer) while mode `doh` serves / forwarder down in mode `doh`, or blocked or hijacked in mode `system` | `set_dns_mode_doh` (mode `system`) |
| `host.disk` | host / node | 10 min | ≥ 1 GiB and ≥ 5 % free / less / < 256 MiB | — |
| `host.memory` | host / node | 10 min | ≥ 10 % available / less / < 64 MiB | — |
| `host.ports` | host / listener | 10 min | every listening socket on the bind and port is the edge's (or there is none) / an owner cannot be read / a socket of another process (owner in evidence) | — |
| `host.public_ips` | host / node | 10 min | known, every specific bind IP among them / the set changed within 24 h / none known, or a bind IP not among them | — |
| `host.reserved_ports` | host / node | full | 20000–40999 in `ip_local_reserved_ports` / not / — | — |
| `host.edge_caps` | host / node | 10 min | no refusal in 10 min / refusals or evictions (counts) / — | — |
| `ingress.bound` | ingress / listener | 60 s | in the edge's `Health.bound` / — / not bound | — |
| `ingress.external` | ingress / proxy | panel | L2 from the panel / L1 only / unreachable | — |
| `engine.container` | engine / proxy | 60 s | serving container running / restarted within 10 min / paused, exited, dead, restarting or crash loop (last 20 log lines, scrubbed) | `recreate_instance` |
| `engine.ready` | engine / proxy | 60 s | engine ready / — / not ready | `recreate_instance` |
| `engine.dcs` | engine / proxy | 60 s | ME on: every DC `available_pct` and `coverage_pct` 100 / some lower / all 0; ME off or no snapshot → skip | — (hint: egress) |
| `engine.log` | engine / proxy | 60 s | no known problem line since the last read / a known warning line / a known error line (cause, hint); skip while the generation logs at `silent` | per pattern |
| `engine.version` | engine / proxy | full | running = desired / differs for > 10 min / — | — |
| `egress.member` | egress / member | 60 s | up; unknown → skip / down, another member of the chain up / every member down | `refresh_subscription` (subscription members) |
| `egress.dc` | egress / proxy | full | a DC answers resPQ through the proxy's SOCKS port / — / none | `change_egress` |
| `egress.me` | egress / proxy with ME | full | getProxySecret 200 through the SOCKS port / — / fails | `change_egress` |
| `e2e.l1` | e2e / proxy | 60 s | L1 through the edge test listener / — / fails | `recreate_instance` |
| `e2e.l2` | e2e / proxy | 10 min | L2 through the test listener / — / fails while L1 passes | `change_egress` |
| `panel.connection` | panel / node | panel | online / state rejection or `last_error` / offline | — |
| `panel.state` | panel / node | panel | applied = desired / behind ≥ 5 min / — | — |
| `panel.versions` | panel / node | panel | edge = agent version / differs / — | `roll_edge` |
| `panel.link_host` | panel / node, listener | panel | link host resolves to a public IP of the node / does not / does not resolve | — |
| `panel.geoip` | panel / panel | panel | fresh (≤ 62 d) or not needed / older / missing while a policy uses countries | — |
| `web.cert`, `web.dns`, `web.http2`, `web.decoy`, `web.base_path` | web / proxy | Task 13 | see Task 13 | `reissue_cert` |

| Fix | Target | The panel changes | The node does | Needs capability |
|---|---|---|---|---|
| `recreate_instance` | proxy | `proxies.restart_nonce` + 1 | a new engine generation, blue-green with the gate and auto-abort | `restart-nonce` |
| `roll_edge` | node | `nodes.edge_roll_nonce` + 1 | a new edge generation beside the running one (the agent's own binary), the old one drains (Ruling 44 path) | `edge-roll-nonce` |
| `change_egress` | proxy (+ `chain_id`) | the proxy's egress chain through `UpdateProxy` | the edge routes the proxy's SOCKS port by it | — |
| `refresh_subscription` | member | `Egress.refresh_nonce` + 1 through `RefreshSubscription` | fetches the subscription again | `egress-xray` |
| `set_dns_mode_doh` | node | node `dns_mode = "doh"` through `SetNodeDnsMode` | the DNS forwarder serves the containers | `dns-forwarder` |
| `reissue_cert` | WEB proxy | `proxies.cert_reissue_nonce` + 1 | ACME issues the certificate again | `web-diagnostics` |

Every fix is confirmed in the UI, audited (`diagnostics.fix`), recorded as event `diagnostics.fix_applied`, and followed by an after-run of the target's scope once the node has applied the generation; its before-run is the run it was offered from (a copy of the light checks when offered from them). Nothing is fixed without an operator's click.

**Before and after changes (R6-3).**
- Operator changes get a full run of the affected scope before and after: rollout steps (Task 15) and the panel edits `UpdateProxy` (`egress_chain_id`, `egress_scope_chains`, a version pin `engine_version`), `SetNodeDefaultChain`, `UpdateEgress`, `SetNodeDnsMode`, and slice 5's version pin outside rollouts when it is on the base. Affected scope: `proxy:<id>` for a proxy edit, `node` for a node edit, `node` on every node that uses an edited egress.
- A panel edit: validate → before-run (full, waited for at most 90 s; node offline, without `diagnostics`, or the wait over → the before-run is kept as `skipped` or `partial`) → re-validate against the current data and commit (generation bump, notify) → after-run 60 s after the node has applied the generation.
- Changes the node makes by itself (a blue-green it starts, member failover, a NAT-IP roll, a subscription refresh): before = a copy of the light checks at that moment; after = a full run; when more than 3 proxies of a node change within 60 s, one `node` run; at most one automatic after-run per node and scope per 5 min.
- An after-run related to a before-run is `regressed` when a check that was `ok` or `warn` before is `fail` after; event `diagnostics.regressed` (error). Nothing is rolled back and no rollout step fails because of it.

### Public page (spec §8.5)

- Served for exactly one `Host` (`public_page.host`, compared lower-case without port and trailing dot): `GET`/`HEAD` `/` (the page), `/robots.txt`, `/assets/page.<hash>.css`, `/assets/copy.<hash>.js` (an embedded allowlist; nothing is read from the file system); anything else 404 plain text; other methods 405. A request for that host never reaches the admin UI or API (also while the page is disabled: then everything is 404). Off until an admin sets the host and enables it. Env `POSTERN_PUBLIC_PAGE=off` turns host routing off (the admin on every host, the page on none).
- The panel records the canonical `Host` of every authenticated admin request (≤ 32 names, setting `admin_hosts`); a public host equal to one of them, or to the host of the request that saves it, is refused.
- Headers: `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, page `Cache-Control: no-store` and `CDN-Cache-Control: no-store` (it holds secrets), assets `public, max-age=31536000, immutable`; with `noindex` (default on) `X-Robots-Tag: noindex, nofollow, noarchive` on every response and `robots.txt` = `User-agent: *` / `Disallow: /`, else `User-agent: *` / `Allow: /`.
- Server-rendered (`html/template`), readable without JS (`copy.js` only adds copy buttons), RU/EN by `?lang=`, then `Accept-Language`, then `default_locale`. Per available item: public name and note, "Connect" (`tg://`), the `https://t.me/...` fallback, manual parameters (fake TLS: server, port, secret; WEB: server, secret) in read-only fields, a QR (inline SVG of the `tg://` link on a white tile, a class of `page.css`: the CSP forbids inline style).
- Unavailable = paused, node offline or probe down (Probes). `hide` leaves the item out; `mark` (default, R6-4) shows only its public name, its note and "unavailable" — no link, QR or parameters.
- Only the chrome (title, rendered Markdown, labels, per locale) is cached, until an update; items, their links and their availability are rendered for every request, so a pause, an offline node, a probe-down or an item change shows at once. QR SVGs are memoized by link text (≤ 256).
- `template.HTML` only for goldmark's output and the QR SVG this repository builds; names, notes and parameters are escaped text. Nothing else of the panel shows: no node names, ids, addresses other than link hosts, versions or statuses beyond "unavailable".

### Settings (table `settings`, JSON; absent = default)

`stats` = `{"minutes_hours":48,"hours_days":90,"ip_days":7}`; `ip_policy` = `"countries"` (`"full"`, `"countries"`, `"off"`; stored by Task 6 at the first start); `probes` = `{"interval_minutes":5,"extra_sources":[]}` (0–60; ≤ 16 single IP addresses); `geoip` = `{"enabled":true}`; `geoip_state` (Task 2 only) = `{"month":"","file":"","sha256":"","size":0,"built_unix":0,"fetched_unix":0,"checked_unix":0,"error":""}`; `admin_hosts` (Task 3 only) = `[{"host":"","last_seen_unix":0}]`.

### Events, audit, capabilities

- Node events: `diagnostics_run`, `geoip_stored`, `geoip_loaded`, `geoip_missing`, `edge_roll_requested`. Panel events: `check.failed`, `check.warning`, `check.recovered` (≤ 1 per node, check and target per 10 min), `probe.failed`, `probe.recovered`, `diagnostics.regressed`, `diagnostics.fix_applied`, `geoip.updated`, `geoip.failed`. Audit actions: `settings.update`, `geoip.upload`, `geoip.refresh`, `geoip.enabled`, `public_page.update`, `diagnostics.run`, `diagnostics.fix`, `probe.run`.
- New capabilities: `restart-nonce`, `edge-roll-nonce` (Task 4), `stats-v2` (Task 5: countries, member minutes, edge refusals, IP retention, send-time filters, `UploadGeoIP`), `diagnostics` (Task 9a), `web-diagnostics` (Task 13), `probe-sources` (Task 14, reported only while the running edge's version equals the agent's). The panel offers a fix only to a node that reports its capability, and sends GeoIP only to `stats-v2` nodes.

### UI

- Charts: `@mantine/charts` 8.3.18 on `recharts` 3.10.1 as installed (peer `recharts >=2.13.3`, React 18/19); use `AreaChart`, `BarChart`, `LineChart`, `CompositeChart`, `DonutChart`, `Sparkline` (verified 2026-10-05, https://v8.mantine.dev/charts/getting-started/ and `web/node_modules/@mantine/charts/package.json`). Charts stay in lazily loaded chunks, as `TrafficChart` is.
- Ranges everywhere: `1h`, `24h`, `7d`, `30d`, `90d`, `1y`; minutes while the span fits the minutes retention, then hours, then days.

---

### Task 1: Panel store: schema, settings, ingest, rollups and privacy

**Start:** now — `lane/s6` from `dev` · **Model:** opus

**Files:** Create `internal/panel/store/migrations/<next>_insights.sql` (the next free number on the base; renumbered at merge), `internal/panel/store/{statssettings.go,countries.go,egresshealth.go,probes.go,sightings.go}` (their write, rollup and prune parts) + tests; modify `internal/panel/store/store.go` (`secure_delete` on every connection, scrubbed backups), `stats.go` (retention argument, refusal columns, `IngestMinute`, rollups and prune of the new tables; `UpsertMinutes` stays until Task 6 moves its caller), `nodes.go`, `proxies.go` (new columns), `internal/panel/server/maintenance.go` (retention read from the settings at every round), tests.

**Interfaces (Produces):**

```go
package store
type Retention struct{ Minutes, Hours, IPs time.Duration }
type StatsSettings struct {
  MinutesHours, HoursDays, IPDays uint32
  IPPolicy string                                          // "full" | "countries" | "off"
  ProbeIntervalMinutes uint32; ExtraProbeSources []string  // single IP addresses
}
func DefaultStatsSettings() StatsSettings   // 48, 90, 7, "countries", 5, none
func (s StatsSettings) Validate() error     // ranges of Global Constraints; known policy; ≤ 16 sources, each one IP address (a prefix is refused)
func (s StatsSettings) Retention() Retention
func (db *DB) StatsSettings(ctx context.Context) (s StatsSettings, stored bool, err error) // stored: an ip_policy key exists
type Deleted struct{ Sightings, CountryRows int64 }
func (db *DB) ApplyStatsSettings(ctx context.Context, s StatsSettings) (Deleted, error)    // one transaction, see Requirements
func (db *DB) RollupStats(ctx context.Context, now time.Time, r Retention) error
func (db *DB) PruneStats(ctx context.Context, now time.Time, r Retention) error
// NodeStat gains RefusedPreHello, RefusedTotal, EvictedPreHello uint64 (per period; summed in rollups).
type CountryStat struct{ ProxyID, Country string; IPs uint32; Bytes uint64 }
type MemberStat struct{ ChainID, MemberKey, Status string; LatencyMS uint32; ExitIP string }
type Sighting struct{ ProxyID, IP, Country string; FirstSeen, LastSeen time.Time; Bytes uint64 }
type Probe struct{ ProxyID string; TS time.Time; Vantage, Kind string; OK bool; LatencyMS uint32; Error string }
type MinuteBatch struct {
  NodeID string; Minute time.Time
  Proxies []ProxyStat; Node *NodeStat
  Countries []CountryStat; Members []MemberStat; Sightings []Sighting; Probes []Probe
}
func (db *DB) IngestMinute(ctx context.Context, b MinuteBatch) (gone []string, err error)
func (db *DB) InsertProbe(ctx context.Context, p Probe) error   // one that is there already is no error
// Node gains PanelAddrs []string (JSON), EdgeRollNonce uint64; Proxy gains RestartNonce, CertReissueNonce uint64.
```

**Requirements:**
- Migration, exactly:
  - `ALTER TABLE stats_node_{1m,1h,1d} ADD COLUMN {refused_prehello,refused_total,evicted_prehello} INTEGER NOT NULL DEFAULT 0` (nine statements);
  - `stats_country_1m`, `stats_country_1h`, `stats_country_1d`, each `(proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE, ts INTEGER NOT NULL, country TEXT NOT NULL, ips INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (proxy_id, ts, country)) STRICT, WITHOUT ROWID` + an index on `ts`;
  - `egress_health_1m (node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, chain_id TEXT NOT NULL, member_key TEXT NOT NULL, ts INTEGER NOT NULL, status TEXT NOT NULL, latency_ms INTEGER NOT NULL DEFAULT 0, exit_ip TEXT NOT NULL DEFAULT '', PRIMARY KEY (node_id, chain_id, member_key, ts)) STRICT, WITHOUT ROWID` + an index on `ts`;
  - `egress_health (node_id … nodes CASCADE, chain_id TEXT NOT NULL, member_key TEXT NOT NULL, ts INTEGER NOT NULL, minutes_up, minutes_down, minutes_unknown, latency_avg_ms, latency_max_ms INTEGER NOT NULL DEFAULT 0, exit_ip TEXT NOT NULL DEFAULT '', PRIMARY KEY (node_id, chain_id, member_key, ts)) STRICT, WITHOUT ROWID` + an index on `ts`;
  - `stats_batches (node_id … nodes CASCADE, minute INTEGER NOT NULL, PRIMARY KEY (node_id, minute)) STRICT, WITHOUT ROWID` + an index on `minute`;
  - `probes (proxy_id … proxies CASCADE, ts INTEGER NOT NULL, vantage TEXT NOT NULL, kind TEXT NOT NULL, ok INTEGER NOT NULL CHECK (ok IN (0,1)), latency_ms INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', PRIMARY KEY (proxy_id, vantage, kind, ts)) STRICT, WITHOUT ROWID` + an index on `ts`;
  - `CREATE INDEX ip_sightings_proxy_last_idx ON ip_sightings (proxy_id, last_seen DESC)`;
  - `ALTER TABLE nodes ADD COLUMN panel_addrs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(panel_addrs))`, `… edge_roll_nonce INTEGER NOT NULL DEFAULT 0`; `ALTER TABLE proxies ADD COLUMN restart_nonce INTEGER NOT NULL DEFAULT 0`, `… cert_reissue_nonce INTEGER NOT NULL DEFAULT 0`;
  - `diagnostic_runs (id TEXT PRIMARY KEY, node_id … nodes CASCADE, scope TEXT NOT NULL, reason TEXT NOT NULL, change TEXT NOT NULL DEFAULT '', related_run_id TEXT NOT NULL DEFAULT '', admin_id TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', regressed INTEGER NOT NULL DEFAULT 0 CHECK (regressed IN (0,1)), ok, warn, fail, skip INTEGER NOT NULL DEFAULT 0, started_at INTEGER NOT NULL, finished_at INTEGER) STRICT` + an index `(node_id, started_at DESC)` (`state` ∈ running, done, partial, skipped, failed; `reason` ∈ manual, before_change, after_change); `diagnostic_results (run_id … diagnostic_runs CASCADE, seq INTEGER NOT NULL, check_id, layer TEXT NOT NULL, target, status, summary, evidence, hint, fix TEXT NOT NULL DEFAULT '', vantage TEXT NOT NULL DEFAULT 'node', checked_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (run_id, seq)) STRICT, WITHOUT ROWID`; `node_checks (node_id … nodes CASCADE, check_id TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', layer, status, summary, evidence, hint, fix TEXT NOT NULL DEFAULT '', since INTEGER NOT NULL, checked_at INTEGER NOT NULL, PRIMARY KEY (node_id, check_id, target)) STRICT, WITHOUT ROWID`;
  - `public_page (id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)), host TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '', body_md TEXT NOT NULL DEFAULT '', unavailable TEXT NOT NULL DEFAULT 'mark', noindex INTEGER NOT NULL DEFAULT 1 CHECK (noindex IN (0,1)), default_locale TEXT NOT NULL DEFAULT 'ru', updated_at INTEGER NOT NULL DEFAULT 0) STRICT` with `INSERT INTO public_page (id) VALUES (1)`; `public_page_items (proxy_id TEXT PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE, position INTEGER NOT NULL, public_name TEXT NOT NULL DEFAULT '', public_note TEXT NOT NULL DEFAULT '') STRICT` + a unique index on `position`.
- Privacy (R6-5): every connection runs `PRAGMA secure_delete = ON` (a DSN pragma, so the pool never hands out a connection without it); after `ApplyStatsSettings` deleted rows and after a prune that deleted sightings, `PRAGMA wal_checkpoint(TRUNCATE)`. The pre-migration backup is made, then opened, `DELETE FROM ip_sightings`, `VACUUM`, closed, before it is kept; slice 5's `store.Backup`, when on the base, goes through the same function.
- `ApplyStatsSettings` validates, then in one transaction writes the keys `stats`, `ip_policy`, `probes`, deletes every `ip_sightings` row when the policy is no longer `full`, and every row of `stats_country_1m/1h/1d` when it is `off`; a failure leaves the policy and the data as they were; the checkpoint follows the commit. `StatsSettings` returns the defaults and `stored = false` until an `ip_policy` key exists.
- `IngestMinute`, one transaction (R6-6):
  - proxy minutes, the node minute (with the refusal counters), country minutes and member minutes are upserted with replace semantics: a minute delivered again, or emitted again with other values, replaces;
  - countries: codes stored as two upper-case letters A–Z, anything else as `''`; at most 50 countries per proxy and minute by bytes, the rest summed under `''`;
  - probes are inserted or ignored;
  - sightings are additive (`first_seen = MIN`, `last_seen = MAX`, `bytes +=`, country replaced when the new one is not empty), applied only when the marker `(node, minute)` is new, and dropped for a minute older than 8 days (its marker would be gone);
  - gone proxies are skipped and named in `gone`; a gone node makes the call a no-op; counters keep the existing 2^50 clamp.
- Rollups, with today's "whole" rules (a coarse row is replaced only while all its finer rows still exist):
  - minutes → hours, "whole" from `r.Minutes`: proxies and nodes as today (refusal counters summed); countries (`ips = MAX`, `bytes = SUM`, at most 50 countries per proxy and hour by bytes, the rest summed under `''`); members → `egress_health` (one minute per status into `minutes_up`, `minutes_down`, `minutes_unknown`; latency average and maximum over the up minutes that have one; exit IP the last non-empty of the hour);
  - hours → days: proxies and nodes ("whole" from `r.Hours`); countries (`bytes = SUM`, `ips = MAX`; "whole" from the fixed 30 days of country hours, so a day is final before any of its hours is deleted).
- Prune (rolls up first what it is about to delete, as today): minute tables past `r.Minutes`; markers past 8 days; proxy and node hours past `r.Hours`; country hours and `egress_health` past 30 days; probes past 7 days; sightings with `last_seen` past `r.IPs`, and beyond 100,000 per proxy (oldest `last_seen` first); runs older than 30 days and beyond the newest 100 of a node.

**Tests:**
- migration on a database with slice-1 data, and the public page row with its defaults;
- `StatsSettings` defaults and `stored`; `Validate` bounds, a prefix refused;
- `ApplyStatsSettings` deletes on leaving `full` and on `off`; a failure injected inside the transaction leaves policy and rows unchanged;
- `IngestMinute`: the same batch twice changes nothing; after the markers of a minute are pruned, a replay of it changes no proxy, node, country or member row and adds no sighting bytes; a second emit of the same minute with a larger increment replaces the proxy, node, country and member minutes, and their hours after the rollup;
- three minutes of an hour aggregate as specified; the 50-country caps at minute and hour;
- a rollup after the hour cut leaves the country day as it was; prune boundaries of every table with fixed clocks; a shorter retention rolls up first; the 100,000 sightings cap;
- secure delete: after leaving `full` and the checkpoint, the bytes of a planted address (`198.51.100.77`) are absent from the database file, its `-wal` and the backups directory; a backup made while sightings existed contains none;
- cascades on proxy and node delete; new columns round-trip; maintenance uses a stored retention, and the defaults without one.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/store/... ./internal/panel/server/...'` → PASS → commit `feat(panel): store for statistics, probes, member health, diagnostics and the public page`.

---

### Task 1b: Panel store: read API

**Start:** after Task 1 — `lane/s6` · **Model:** sonnet

**Files:** Modify `internal/panel/store/{stats.go,countries.go,egresshealth.go,probes.go,sightings.go}`, create `internal/panel/store/storage.go`; modify `internal/panel/proxies/service.go` (its `ProxySeries` call passes the stored retention); tests.

**Interfaces (Produces):**

```go
package store
func (db *DB) ProxySeries(ctx context.Context, proxyID string, from, to time.Time, r Retention) ([]ProxyStat, error) // resolution from r
func (db *DB) NodeSeries(ctx context.Context, nodeID string, from, to time.Time, r Retention) ([]NodeStat, error)
type NodeTraffic struct{ TS time.Time; Up, Down uint64; DevicesSum uint32 }          // per period, summed over the node's proxies
func (db *DB) NodeTraffic(ctx context.Context, nodeID string, from, to time.Time, r Retention) ([]NodeTraffic, error)
type CountryFilter struct{ ProxyID, NodeID string }                                 // both empty: every proxy
type CountryTotal struct{ Country string; Bytes uint64; IPsPeak uint32 }
func (db *DB) CountryTotals(ctx context.Context, f CountryFilter, from, to time.Time) ([]CountryTotal, error)
func (db *DB) ListSightings(ctx context.Context, proxyID, country string, limit, offset int) ([]Sighting, int, error)
type MemberHour struct{ ChainID, MemberKey string; TS time.Time; Up, Down, Unknown, LatencyAvgMS, LatencyMaxMS uint32; ExitIP string }
func (db *DB) EgressHistory(ctx context.Context, nodeID string, from, to time.Time) ([]MemberHour, error)
func (db *DB) Probes(ctx context.Context, proxyID, vantage string, from, to time.Time) ([]Probe, error)
func (db *DB) LastProbes(ctx context.Context, vantage string, n int) (map[string][]Probe, error) // newest first, per proxy
type ProxyTotal struct{ ProxyID string; Up, Down, ConnsNew uint64; DevicesPeak uint32 }
func (db *DB) TopProxies(ctx context.Context, nodeID string, from, to time.Time, limit int) ([]ProxyTotal, error)
func (db *DB) TrafficSince(ctx context.Context, since, now time.Time) (map[string]ProxyTotal, error) // by node id
func (db *DB) LatestNodeMinutes(ctx context.Context, now time.Time, within time.Duration) (map[string]NodeStat, error)
type StorageInfo struct{ FileBytes, FreeBytes int64; Rows map[string]int64 }
func (db *DB) Storage(ctx context.Context) (StorageInfo, error)
```

**Requirements:**
- Series resolution from `r`: minutes while the span fits `r.Minutes`, hours while it fits `r.Hours`, days beyond (the fixed `resolution()` goes).
- `TrafficSince`, `TopProxies` and `CountryTotals` read whole hours (days beyond the hours retention; for countries beyond 30 days) and add the minutes of the partial hours at both ends: from `from` to the next whole hour, and after the last rolled-up hour.
- `NodeTraffic`: per period, `up` and `down` summed over the node's proxies and `DevicesSum` the sum of their `devices` (the UI label is "Unique IPs, sum of proxies").
- Orderings: `TopProxies` by `up + down` descending; `ListSightings` by `last_seen` descending, with a country filter and a total.
- `Storage`: `page_count × page_size`, `freelist_count × page_size`, and `count(*)` of the statistics, probe, sighting, event and run tables.

**Tests:** every function against seeded rows with fixed clocks; partial hours at both ends, and a `since` at local midnight of UTC+03:30 (20:30 UTC); resolution switch with a shorter retention; `Storage` row counts equal what the test inserted; paging and filters; `NodeTraffic` sums.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/store/... ./internal/panel/proxies/...'` → PASS → commit `feat(panel): read API of the statistics store`.

---

### Task 2: Country database (DB-IP) for the panel

**Start:** now — `lane/s6-geoip` from `dev` (parallel with Task 1) · **Model:** sonnet

**Files:** Create `internal/geoip/geoip.go` (+ test), `internal/geoip/geoiptest/geoiptest.go` (writes small databases for tests of any package), `internal/panel/geodb/{manager.go,service.go,upload.go}` (+ tests), `proto/postern/panel/v1/geoip.proto` (+ regen Go and TS); modify `internal/panel/server/{server.go,api.go}` (manager, service, `PUT /api/geoip`, `/data/geoip`, `Config.GeoIPBaseURL`), `cmd/panel/serve.go` (env `POSTERN_GEOIP_BASE_URL`), `README.md`, `README.ru.md` (attribution line), `go.mod`. Shipping the database to nodes is Task 6 on the panel and Task 5 on the node.

**Interfaces (Produces):**

```go
package geoip
const Attribution, AttributionURL, Licence = "IP Geolocation by DB-IP", "https://db-ip.com", "CC BY 4.0"
type Info struct{ DatabaseType string; Built time.Time; IPVersion uint }
type DB struct{ /* *maxminddb.Reader over bytes */ }
func Open(path string) (*DB, error)        // reads the file (≤ 256 MiB) and uses OpenBytes; Verify(); refuses anything but an IPv6-tree country database
func (d *DB) Info() Info
func (d *DB) Country(ip netip.Addr) string  // "DE"; "" when not found, for a nil *DB, or a value that is not two letters

package geoiptest
func Write(path string, networks map[string]string) error // "198.51.100.0/24" → "DE", "127.0.0.0/8" → "ZZ"

package geodb
func NewManager(db *store.DB, dir string, log *slog.Logger, opts ...Option) *Manager // WithHTTPClient, WithBaseURL, WithNow
func (m *Manager) Start(ctx context.Context)                       // loads the installed file; refreshes now (in the background) and every 24 h
func (m *Manager) Refresh(ctx context.Context) (Status, error)
func (m *Manager) Install(ctx context.Context, r io.Reader) (Status, error) // raw or gzip MMDB
func (m *Manager) SetEnabled(ctx context.Context, on bool) (Status, error)
func (m *Manager) Status(ctx context.Context) (Status, error)
func (m *Manager) Country(ip netip.Addr) string                    // "" when disabled or no database
type Current struct{ Month, SHA256, Path string; Size int64 }
func (m *Manager) Current() (Current, bool)                        // false when disabled or no database
func (m *Manager) OnChange(fn func())                              // after an install or a change of enabled
func (m *Manager) UploadHandler() http.Handler                     // PUT /api/geoip, behind auth.RequireAdmin
```

`geodb` imports `store`, `geoip` and `auth` (for `RequireAdmin`), never `proxies` or `nodes`.

```proto
service GeoIPService {
  rpc GetGeoIP(GetGeoIPRequest) returns (GeoIPStatus);
  rpc RefreshGeoIP(RefreshGeoIPRequest) returns (GeoIPStatus);
  rpc SetGeoIPEnabled(SetGeoIPEnabledRequest) returns (GeoIPStatus); // { bool enabled }
}
message GeoIPStatus {
  bool enabled = 1; bool present = 2; string month = 3; int64 built_unix = 4; int64 size = 5; string sha256 = 6;
  int64 fetched_unix = 7; int64 checked_unix = 8; string error = 9;
  string attribution = 10; string attribution_url = 11; string licence = 12;
}
```

**Requirements:** Global Constraints (GeoIP; settings `geoip`, `geoip_state`). Refresh: nothing while disabled; month = the current UTC month, then the previous one on 404; no download when that month is installed; GET with `User-Agent: postern/<version>`, 30 s to connect, 5 min overall, gzip ≤ 64 MiB, unpacked ≤ 256 MiB; written to a temp file in the directory, opened and verified, sha256 computed, renamed to `dbip-country-lite-<YYYY-MM>.mmdb` (0644: public data); the previous file is kept, older ones deleted; the reader (in memory) is swapped atomically, the old one simply dropped; a failure keeps the old database and records the error in `geoip_state` and as event `geoip.failed` (one per distinct error); a new database records event `geoip.updated`. Upload: body ≤ 256 MiB, gzip by its magic bytes, month taken from the database's build time; audit `geoip.upload`; refresh and enable calls audited. `POSTERN_GEOIP_BASE_URL`, when set, is the download base (the e2e points it at a closed port). `geoiptest.Write` builds an IPv6 tree with IPv4 aliasing left on and admits reserved networks (loopback and the documentation ranges are reserved; the option `IncludeReservedNetworks`: implementer verifies against upstream). README gains "Country data: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0".

**Tests:** `geoip` against databases from `geoiptest` (documentation networks and loopback → countries, IPv4 and IPv6, not found, nil DB, a database of another type refused, a file that is not MMDB refused); manager against an `httptest` server: current-month 404 then previous month, a month already installed (no download), size caps, corrupt gzip, invalid database (the old one stays, error recorded), disabled (no request), the base URL from the option, upload raw and gzip, keep-previous cleanup, `OnChange` calls, `Current` before and after an install and when disabled; upload route refuses a non-admin and an oversize body; service status fields.

**Steps:** proto + regen (`bash scripts/wsl 'bash scripts/gen.sh'`, `npm run gen` in `web/`) → tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/geoip/... ./internal/panel/... ./cmd/panel/...'` → PASS → commit `feat(panel): DB-IP country database`.

---

### Task 3: Public page: backend

**Start:** after Task 1b — `lane/s6` · **Model:** opus

**Files:** Create `proto/postern/panel/v1/publicpage.proto` (+ regen Go and TS), `internal/panel/store/publicpage.go` (+ test), `internal/panel/publicpage/{service.go,handler.go,render.go,markdown.go,i18n.go,availability.go,adminhosts.go}`, `internal/panel/publicpage/templates/page.html.tmpl`, `internal/panel/publicpage/assets/{page.css,copy.js}`, tests, fuzz tests and `testdata/*.html` goldens; modify `internal/panel/proxies/service.go` (extract the link computation of `GetProxyLinks` into an exported `LinksOf`, which `GetProxyLinks` then uses; at slice 3's merge its WEB links go through `LinksOf` too), `internal/panel/server/{api.go,server.go,headers.go}` (host routing ahead of the admin chain, admin-host recording, env `POSTERN_PUBLIC_PAGE`), `go.mod` (goldmark, newest release).

**Interfaces:**
- Consumes: store tables of Task 1, `internal/links` (`FakeTLS`, `Web`), `proxies.QRSVG`, `auth.AdminFrom`.
- Produces:

```go
package proxies
type Links struct{ TG, HTTPS, QRSVG, Server, Port, Secret string } // Server/Port/Secret: the manual parameters as in the link (Port "" for WEB)
func LinksOf(ctx context.Context, db *store.DB, key seal.Key, p *store.Proxy) (Links, error) // fake TLS as GetProxyLinks; WEB with links.Web and the base path

package publicpage
type Option func(*Service)
func WithProbeDown(down func(proxyID string) bool) Option // Task 8 wires the probes' availability; nil: never down
func NewService(db *store.DB, key seal.Key, log *slog.Logger, opts ...Option) *Service
func (s *Service) Handler() http.Handler                    // the public site, with its own headers
func (s *Service) Serves(r *http.Request) bool               // the request is for the configured host (enabled or not)
func (s *Service) RecordAdminHosts(next http.Handler) http.Handler // inside auth.Middleware: records the Host of authenticated admin requests
func HostOf(r *http.Request) string                          // lower case, port and one trailing dot dropped
```

```proto
service PublicPageService {
  rpc GetPublicPage(GetPublicPageRequest) returns (PublicPage);
  rpc UpdatePublicPage(UpdatePublicPageRequest) returns (PublicPage); // { PublicPage page }, the whole page
}
message PublicPage {
  bool enabled = 1; string host = 2; string title = 3; string body_md = 4;
  string unavailable = 5;    // "hide" | "mark"
  bool noindex = 6; string default_locale = 7; repeated PublicPageItem items = 8; // in order
}
message PublicPageItem { string proxy_id = 1; string public_name = 2; string public_note = 3; }
```

**Requirements:**
- Global Constraints (Public page) in full: routing, headers, robots both ways, `mark`/`hide`, chrome-only cache, admin hosts, asset allowlist, escape hatch, `template.HTML` rule.
- Routing in `api.go`: unless `POSTERN_PUBLIC_PAGE=off`, a request for the configured host goes to `Handler()`, never through the admin mux, `auth.Middleware` or the admin `securityHeaders`; every other host is unchanged. The configuration is cached in memory and replaced on update.
- At most 64 requests at a time on the public host, else 503 with `Retry-After: 5`.
- Markdown with goldmark (newest release; no raw HTML, dangerous URLs filtered; that `tg:` links pass and that `javascript:` is refused also entity-encoded, `[x](javascript&colon;alert(1))` — reported as CVE-2026-5160, fixed in 1.17.6: implementer verifies against upstream); images rendered as their alt text; links get `rel="nofollow noopener noreferrer"`; headings shifted one level down (the title is the only `h1`); title plain text.
- Links and manual parameters come from `proxies.LinksOf`; an item whose proxy has no link host is left out and logged. Availability: paused (`enabled = 0`), node not `online`, or `WithProbeDown`.
- Update: admin only; host a DNS name (lower case, ≤ 253 bytes, labels 1–63 of letters, digits and hyphens, at least one dot), not an IP literal, no port, not a recorded admin host and not the host of the request (`InvalidArgument`: "the admin pages are served on this name"); enabling needs a host; title ≤ 120 bytes, body ≤ 16 KiB, ≤ 100 items, proxies existing and unique, names ≤ 64, notes ≤ 280; items replaced in one statement sequence inside one transaction (delete, then insert in order: the unique index on `position` refuses a row-by-row reorder); audit `public_page.update`.
- Admin hosts: the canonical `Host` of authenticated admin requests, ≤ 32 newest, stored in setting `admin_hosts` at most once an hour per name.

**Tests:**
- routing: public host → page; `/api/...`, `/setup`, `/login` and SPA files on that host → 404; other hosts → admin as before; host configured but disabled → 404 there; `Host` with port, upper case, trailing dot; `POSTERN_PUBLIC_PAGE=off` serves the admin on that host;
- headers on page, assets, 404 and robots (`CDN-Cache-Control` included); robots both ways;
- goldens RU and EN for a fixture with a fake-TLS item, a WEB item, a marked item and a hidden one; the marked item holds no `tg://`, no `t.me` and no secret;
- Markdown golden with `<script>`, `javascript:`, `[x](javascript&colon;alert(1))`, an image and a `#` heading, all neutralised;
- fuzz `FuzzHostOf`, `FuzzLanguage` (`?lang=` and `Accept-Language`), `FuzzMarkdown` (the output never contains `<script`, `javascript:`, an `on…=` attribute, `<img`, or raw HTML from the input);
- a pause, an offline node, a probe-down and an item removal show on the next request (no stale item);
- a host refused because an earlier admin request used it (not the current one);
- asset allowlist (an unknown name, `..`, an encoded slash → 404); 503 over the cap; nothing of a proxy that is not listed, no node name or id in the output; validation errors.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/...'` and `bash scripts/wsl 'go test -run=^$ -fuzz=^FuzzMarkdown$ -fuzztime=20s ./internal/panel/publicpage/'` (and the other two targets, one anchored run each) → PASS → commit `feat(panel): public page on a domain of its own`.

---

### Task 3b: Public page: admin UI

**Start:** after Task 3 — `lane/s6` · **Model:** sonnet

**Files:** Create `web/src/components/PublicPageForm.tsx` (+ test), `web/src/api/hooks/publicpage.ts`, `web/src/i18n/insights.en.json`, `web/src/i18n/insights.ru.json`; modify `web/src/pages/Settings.tsx` (a section), `web/src/i18n/index.ts` (merge), `web/src/i18n/i18n.test.ts` (parity covers the new files), `web/src/i18n/i18next.d.ts` (`typeof en & typeof insightsEn`).

**Interfaces:** Consumes `PublicPageService` (TS client). Produces the form and the string files the later UI tasks extend.

**Requirements:** enable switch, host, title, Markdown text, unavailable mode (help: "mark shows the name, the note and 'unavailable' only; hide leaves the item out"), noindex switch (help: search engines are asked neither to crawl nor to index), default language, items (add from all proxies, reorder, remove, public name and note); a warning that everything on the page is public, including the secrets in the links; the server's refusal of an admin host shown in place; a link to `https://<host>/` once enabled.

**Tests:** form validation, reorder, confirm on enable, the refusal message, i18n parity including the new files; `npm run typecheck` proves the typing.

**Steps:** tests → FAIL → implement → in `web/` `npm run lint && npm run typecheck && npm test -- --run && npm run build` → PASS → commit `feat(web): public page settings`.

---

### Task 4: Node contracts of the slice and the restart and edge-roll knobs

**Start:** after slice 2 is merged into `dev` and `dev` into `lane/s6` · **Model:** opus

**Files:** Modify `proto/postern/node/v1/node.proto` (+ regen Go), `internal/node/state/{validate.go,runtime.go}`, `internal/node/reconcile/{instances.go,edgemgr.go}`, `internal/node/agent/server.go`; create `internal/node/agent/proxylistener.go` (+ tests); panel test fakes of `NodeService` (compile).

**Interfaces (Produces):** the numbers of `GetInfoResponse` and `NodeSettings` are fixed (R6-7); the others are the next free ones at implementation time.

```proto
service NodeService {
  /* … */
  rpc RunDiagnostics(RunDiagnosticsRequest) returns (stream DiagnosticResult);
  rpc UploadGeoIP(stream UploadGeoIPRequest) returns (UploadGeoIPResponse);
}
message GetInfoResponse { /* … */
  string peer_addr = 14;              // the address the call came from, as the node sees it, IP only
  repeated string geoip_stored = 15;  // sha256 of every country database the node holds
}
message NodeSettings { /* … 7 is reserved */
  uint32 ip_retention_hours = 8;      // client addresses kept in the node's buffer; 0 = 168
  GeoIPRef geoip = 9;                 // the country database to use
  repeated string probe_sources = 10; // exact IP addresses whose connections are the panel's probes
  uint64 edge_roll_nonce = 11;        // a new value rolls the edge
}
message GeoIPRef { string month = 1; string sha256 = 2; }
message UploadGeoIPRequest { oneof part { GeoIPRef meta = 1; bytes chunk = 2; } }
message UploadGeoIPResponse { bool stored = 1; string sha256 = 2; }
message WatchRequest { uint64 cursor = 1; IpPolicy ip_policy = N; }  // the panel's policy; unset = the node's own
message Proxy { /* … */ uint64 restart_nonce = N; }                 // a new value rolls the engine instance
message WatchResponse { oneof payload { /* … */ DiagnosticsReport diagnostics = N; } }
message StatsBatch { /* … */ repeated CountryMinute countries = N; repeated MemberMinute members = N; repeated ProbeResult probes = N; }
message NodeMinute { /* … */ uint64 refused_prehello = N; uint64 refused_total = N; uint64 evicted_prehello = N; }
message CountryMinute { string proxy_id = 1; string country = 2; uint32 ips = 3; uint64 bytes = 4; }
message MemberMinute { string chain_id = 1; string member_key = 2; string status = 3; uint32 latency_ms = 4; string exit_ip = 5; }
message ProbeResult { string proxy_id = 1; string kind = 2; bool ok = 3; uint32 latency_ms = 4; string error = 5; int64 at_unix = 6; }
message RunDiagnosticsRequest { string scope = 1; }   // "node" | "proxy:<id>"
message DiagnosticResult {
  string id = 1; string layer = 2; string target = 3; CheckStatus status = 4; string summary = 5;
  string evidence = 6; string hint = 7; string fix = 8; int64 checked_unix = 9; uint32 duration_ms = 10;
}
enum CheckStatus { CHECK_STATUS_UNSPECIFIED = 0; CHECK_STATUS_OK = 1; CHECK_STATUS_WARN = 2; CHECK_STATUS_FAIL = 3; CHECK_STATUS_SKIP = 4; }
message DiagnosticsReport { repeated DiagnosticResult results = 1; }
```

```go
package agent
func newProxyV2Listener(ln net.Listener, timeout time.Duration) net.Listener // for the hidden management listener (spec §5.3)
```

**Requirements:**
- Validation (one validator for node and panel): `ip_policy` known (unspecified = off); `ip_retention_hours` 0 or 1–720; `geoip` only with policy full or countries, month `YYYY-MM`, sha256 64 hex; `probe_sources` ≤ 32 entries, each a single IPv4 or IPv6 address (a prefix is refused; v4-mapped unmapped); nonces free.
- Engine: the instance hash gains a field `restart <n>` at its end only when `restart_nonce != 0`, so an update of the agent rolls no engine (as the resolv.conf field of slice 2 does); a new value rolls the proxy by blue-green with the gate.
- Edge: `Runtime.EdgeRollNonce` (JSON `edge_roll_nonce`); a pass whose desired nonce differs takes it like the operator's roll file (Ruling 44 path: a new generation beside the running one, the old drains) and records the nonce when the roll starts, whatever its outcome, so a failed roll is not retried in a loop (the operator clicks again); event `edge_roll_requested`; with no running edge, the nonce is recorded without a roll. The roll uses the agent's own binary, as the file roll does; when slice 5's `UpdateEdge` and `Runtime.EdgeBinaries` are on the base, that is still the rule, and it brings an outdated edge to the agent's version.
- Panel address (R6-1): `GetInfo.peer_addr` = the IP of the caller, unmapped, without port, `""` when it is not a unicast address. On the plain management listener that is the TCP source. `newProxyV2Listener` reads a PROXY v2 header (`proxyproto.ReadV2`, 10 s read deadline, through a `bufio.Reader` the connection keeps reading from), closes a connection without one, and reports the header's source as `RemoteAddr`; the hidden management listener of spec §5.3 must use it (no slice plan wires that listener yet; when one does, `peer_addr` is the panel's address from its first call).
- Agent: capabilities gain `edge-roll-nonce` and `restart-nonce`; `UploadGeoIP` answers `Unimplemented` until Task 5 and `RunDiagnostics` until Task 9a (which report `stats-v2` and `diagnostics`).
- `buf breaking` passes (additions only).

**Tests:** validation table for every rule; hash of an instance unchanged with nonce 0 (golden from before) and different with 1; reconcile harness: a nonce change starts a new edge generation beside the running one and records the nonce, a failed roll records it and does not loop, a fresh node records without rolling, a restart nonce rolls an engine by blue-green and a failing gate keeps the old generation; `peer_addr` over the real mTLS test server: plain listener (TCP peer 127.0.0.1 → `127.0.0.1`), and the hidden-mode test (TCP peer 127.0.0.1 with a PROXY v2 source 203.0.113.10 → `203.0.113.10`; source 2001:db8::10 → `2001:db8::10`; no header → closed); capabilities sorted; panel packages compile and pass.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/... ./internal/panel/nodes/...'` → PASS → commit `feat(node): slice 6 contracts, the panel's address and the restart and edge roll knobs`.

---

### Task 5: Node statistics and privacy: countries, member minutes, edge refusals, IP retention

**Start:** after Task 4 — `lane/s6` (Task 2 merged in) · **Model:** opus

**Files:** Modify `internal/node/agent/{stats.go,buffer.go,server.go,info.go,run.go}`, `internal/node/state/store.go` (`Paths.GeoIPDir()` = `data/geoip`); create `internal/node/agent/geoip.go` (`UploadGeoIP`, store, loader); tests (+ `stats_test.go`, `buffer_test.go`, `server_test.go` additions).

**Interfaces:**
- Consumes: `geoip.Open`, `(*geoip.DB).Country`, `geoiptest.Write` (tests), the Task 4 messages (`WatchRequest.ip_policy`, `UploadGeoIP`, `GeoIPRef`).
- Produces: the `UploadGeoIP` handler and `GetInfo.geoip_stored`; `(*statsCollector).addProbe(*nodev1.ProbeResult)` (used by Task 9c); `(*Buffer).ScrubIPsBefore(t time.Time) (int, error)`; capability `stats-v2`.

**Requirements:**
- IP mode from `NodeSettings.ip_policy`: `off` → the edge is not asked for client IPs; `countries` → asked, `CountryMinute` only; `full` → asked, `CountryMinute` and `IpSighting`. One baseline for `full` and `countries` (R6-5): the per-IP byte counters are taken as increments only after a snapshot in which they were received (`ipBaseline` = IP counters wanted and not received the last time), so switching between the two never turns absolute counters into a spike.
- Send time (R6-5): `forPanel` keeps a record's sightings only when the node's current policy and the stream's `WatchRequest.ip_policy` are both `full` (unset = the node's own), and its country minutes only when neither is `off`; this applies to buffered records replayed before the new state arrives.
- Leaving `full` (`ApplyState`): before it returns, the open minute's sightings are dropped and the buffer is scrubbed (exists), then `PRAGMA wal_checkpoint(TRUNCATE)`.
- `CountryMinute` per (proxy, country) of the minute: `ips` = distinct addresses sighted in the minute (the predicate of `sight`), `bytes` = their byte increments; country from the loaded database, `""` without one; at most 50 per proxy (by bytes, the rest summed under `""`); sorted. The addresses stay in memory for the minute and are never buffered or logged.
- `MemberMinute` per (chain, member) from the health of the newest edge generation: last status, latency when up, last non-empty exit IP; sorted.
- `NodeMinute` refusal counters as increments per edge generation, with the baseline rules of the proxy counters.
- `addProbe` appends to the current minute (≤ 1,000 a minute).
- `UploadGeoIP`: the first message is `meta`, then chunks, ≤ 256 MiB in all (else `ResourceExhausted`); streamed to a temp file in `data/geoip/` (directory 0700, files 0644), sha256 checked against `meta.sha256` (`InvalidArgument` on a mismatch), opened with `geoip.Open` (refused when it is not a country database), renamed to `<sha256>.mmdb`; a file that is there already is answered `stored` at once; every file but the one named by the desired state and the one loaded before it is deleted; event `geoip_stored` per stored file. `GetInfo.geoip_stored` lists the sha256 of every stored file.
- GeoIP loader: at every `ApplyState` and every 60 s, when `NodeSettings.geoip` names a stored file that is not loaded, open it (in memory) and swap it in atomically; none named → unload; event `geoip_loaded` once per sha256; a named file that stays missing for 10 min → event `geoip_missing` (warn) once.
- Buffer: `PRAGMA secure_delete = ON` on its connection; `ScrubIPsBefore` removes the sightings of statistics records older than `t` and remembers how far it went (meta table) so the hourly run reads only new records; the hourly prune calls it with now − `ip_retention_hours` (0 → 168 h); then, while `SUM(length(payload))` > 256 MiB, it scrubs the oldest statistics records, then deletes the oldest records; `wal_checkpoint(TRUNCATE)` after any scrub or delete; counts logged.
- State reports: the journal compares a report with the last buffered one ignoring the members' `latency_ms`; a report that differs only there goes to the open streams only.
- Capability `stats-v2`.

**Tests:** aggregator with fake snapshots — countries under `countries` (no sightings; the edge asked for IPs), `full` (both), `off` (neither, not asked); two countries and an unknown address; byte increments; switching `full` ↔ `countries` produces no spike; edge generation change; member minutes; refusal counters with a preexisting generation and a restart; probes appended and capped; send-time filter (node `full` but stream `countries` → no sighting; stream `off` → no country minute; a buffered `full` record replayed after the switch → no sighting); leaving `full` drops the open minute's sightings; `UploadGeoIP` over the real mTLS test server (good file, sha256 mismatch, not a database, chunk before meta, oversize, repeated upload, cleanup, event) and `GetInfo.geoip_stored`; loader with databases from `geoiptest` (load, swap, unload, missing event after 10 min with a fake clock); `ScrubIPsBefore` and its resume point; payload budget with a small budget; secure delete: a planted address is absent from `stats.db` and its `-wal` after a scrub and the checkpoint; dedupe ignoring latency; `Watch` delivers a minute with countries and members.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/agent/...'` → PASS → commit `feat(node): client countries, member health, edge refusals and IP privacy in the minute statistics`.

---

### Task 6: Panel ingest, statistics settings and the new node settings

**Start:** after Task 4 — `lane/s6-panel` (beside Task 5) · **Model:** opus

**Files:** Create `proto/postern/panel/v1/settings.proto` (+ regen Go and TS), `internal/panel/insights/{settings.go,geoipsync.go}` (+ tests), `internal/panel/nodes/ensure.go` (`MultiEnsurer`); modify `proto/postern/panel/v1/nodes.proto` (`repeated string panel_addrs = 30`, read-only) + regen, `internal/panel/proxies/{ingest.go,statebuilder.go}`, `internal/panel/nodes/{connmgr.go,service.go}`, `internal/panel/server/{server.go,api.go}`, tests.

**Interfaces:**
- Consumes: `store.IngestMinute`, `store.StatsSettings`/`ApplyStatsSettings`, `store.Storage` (Tasks 1, 1b); `geodb.Manager` `Country`, `Current`, `OnChange` (Task 2), handed to `proxies` as function values at wiring; Task 4 messages.
- Produces:

```proto
service SettingsService {
  rpc GetStatsSettings(GetStatsSettingsRequest) returns (GetStatsSettingsResponse);   // { StatsSettings settings; repeated PanelAddress panel_addresses }
  rpc UpdateStatsSettings(UpdateStatsSettingsRequest) returns (GetStatsSettingsResponse); // { StatsSettings settings }
  rpc GetStorage(GetStorageRequest) returns (Storage);
}
message StatsSettings {
  uint32 minutes_hours = 1; uint32 hours_days = 2; uint32 ip_days = 3;
  string ip_policy = 4;                 // "full" | "countries" | "off"
  uint32 probe_interval_minutes = 5; repeated string extra_probe_sources = 6; // single addresses
}
message PanelAddress { string node_id = 1; string addr = 2; bool shared = 3; } // shared: private, ULA, link-local or 100.64.0.0/10
message Storage { int64 file_bytes = 1; int64 free_bytes = 2; map<string, int64> rows = 3; }
```

```go
package insights
func NewSettingsService(db *store.DB, n Notifier, log *slog.Logger) *SettingsService
func (s *SettingsService) EnsureDefaults(ctx context.Context) error                        // first start: store the defaults, bump every node once
func (s *SettingsService) BumpNodes(ctx context.Context, match func(*store.Node) bool) error // NextNodeGeneration + Notify for each match
type GeoIPSync struct{ /* geodb.Current, chunk size, timeout, retry memory */ }            // a nodes.ArtifactEnsurer
func (g *GeoIPSync) EnsureArtifacts(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse, st *nodev1.NodeState, c nodev1connect.NodeServiceClient) error
package nodes
func MultiEnsurer(es ...ArtifactEnsurer) ArtifactEnsurer // runs each, joins the errors (wired as MultiEnsurer(catalog, geoipSync))
package proxies
type GeoIP struct{ Country func(netip.Addr) string; Ref func() *nodev1.GeoIPRef } // nil funcs: no GeoIP
func (b *StateBuilder) SetGeoIP(g GeoIP); func (in *Ingestor) SetGeoIP(g GeoIP)
func (in *Ingestor) OnDiagnostics(fn func(ctx context.Context, nodeID string, at time.Time, rep *nodev1.DiagnosticsReport) error)
func (in *Ingestor) OnServingChange(fn func(nodeID, proxyID string, fromGen, toGen uint64)) // a serving proxy moved to another instance generation
```

**Requirements:**
- Settings through `store.ApplyStatsSettings` (one transaction, R6-5); `UpdateStatsSettings` validates (extra sources single addresses, R6-1), stores, audits `settings.update`; a change of `ip_policy`, `ip_days` or `extra_probe_sources` bumps every node; `EnsureDefaults` at start stores the defaults when no `ip_policy` key exists and bumps every node once (M9); GeoIP `OnChange` bumps, while the policy is `full` or `countries`, the nodes that report `stats-v2`. `GetStatsSettings` returns every node's learned addresses with `shared` set for private (RFC 1918), ULA, link-local and 100.64.0.0/10 addresses (the Settings warning, R6-1).
- GeoIP to nodes: `GeoIPSync` uploads the file of `Current()` (64 KiB chunks, 10 min) when the state names a database whose sha256 is not in the node's `GetInfo.geoip_stored`, before `ApplyState` (the ensurer contract); a failing (node, sha256) is tried again at most every 30 min.
- State builder: `NodeSettings.ip_policy` from the setting; `ip_retention_hours` = `ip_days × 24`; `geoip` = `Ref()` (month and sha256 of `Current()`) only for a node whose stored capabilities include `stats-v2` and while the policy is full or countries; `probe_sources` = `nodes.panel_addrs` + `extra_probe_sources` (exact addresses); `edge_roll_nonce`, `Proxy.restart_nonce` from the store. The state goldens are updated.
- Panel addresses: `GetInfo.peer_addr` is kept only when it parses as a unicast IP address; `nodes.panel_addrs` holds the last IPv4 and the last IPv6 seen; a change bumps that node; `Node.panel_addrs` shows them.
- Watch: the manager opens every `Watch` with `WatchRequest.ip_policy` = the panel's current policy (R6-5).
- Ingest (`StatsBatch` → `store.MinuteBatch` → `IngestMinute`): proxies and node as today plus the refusal counters; countries of owned proxies (≤ 10,000), dropped under `off`; members (≤ 2,000); sightings only under `full`, owned proxies only, country from the GeoIP function; node probes (vantage `node`, kinds `l2` and `web` only, error clipped to 256 bytes, owned proxies only). Bounds as today (minute age 8 days, 10 GiB/s).
- `WatchResponse.diagnostics` goes to the `OnDiagnostics` hook (none set: ignored); a state report in which a serving proxy's instance generation differs from the last known one calls `OnServingChange`.

**Tests:** settings validation (a prefix refused), defaults, `EnsureDefaults` bumps once and only once, bumps on changes (fake notifier), the transaction's effects through the service, audit; `shared` flags; `GeoIPSync` with a fake node client (uploads once, not when the sha256 is stored, not when the state names none, a failure retried only after 30 min with a fake clock); `MultiEnsurer` joins errors; state builder goldens (policy, retention hours, GeoIP only with `stats-v2`, probe sources, nonces); `panel_addrs` (non-unicast ignored, the last v4 and v6 kept, a change bumps); `WatchRequest` carries the policy; ingest with each policy (country minutes dropped under `off`, sightings only under `full`), duplicates idempotent, foreign proxy ids dropped, caps, probes stored (`l1` dropped); hooks called with the right arguments.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/...'` → PASS → commit `feat(panel): ingest of countries, member health and node probes; IP policy and retention settings`.

---

### Task 7: Statistics API

**Start:** after Task 6 — `lane/s6-panel` · **Model:** sonnet

**Files:** Create `proto/postern/panel/v1/metrics.proto` (+ regen Go and TS), `internal/panel/insights/metrics.go` + tests; modify `internal/panel/proxies/service.go` (`ProxySeries` ranges), `internal/panel/proxies/ingest.go` (exported `(*Ingestor).PhaseCounts(nodeID string) map[string]int`), `internal/panel/server/api.go`.

**Interfaces:** Consumes the read API of Task 1b, `store.StatsSettings`, `Ingestor.PhaseCounts`, `geoip.Attribution*`. Produces:

```proto
service MetricsService {
  rpc Overview(OverviewRequest) returns (OverviewResponse);            // { int64 since_unix } → per node
  rpc NodeSeries(NodeSeriesRequest) returns (NodeSeriesResponse);      // { node_id, range }
  rpc TopProxies(TopProxiesRequest) returns (TopProxiesResponse);      // { node_id (optional), range, limit ≤ 50 }
  rpc Countries(CountriesRequest) returns (CountriesResponse);         // { proxy_id | node_id | none, range }
  rpc ListIpSightings(ListIpSightingsRequest) returns (ListIpSightingsResponse); // { proxy_id, country, limit ≤ 200, offset }
  rpc EgressHistory(EgressHistoryRequest) returns (EgressHistoryResponse);       // { node_id, range ≤ 30d }
}
message NodeOverview {
  string node_id = 1; int64 minute_unix = 2; double cpu = 3; uint64 mem_used = 4; uint64 mem_total = 5; double load1 = 6;
  uint64 disk_used = 7; uint64 disk_total = 8; uint32 conns = 9; uint64 up = 10; uint64 down = 11;
  uint32 proxies = 12; uint32 serving = 13; uint32 failed = 14; uint32 paused = 15;
}
message NodePoint { int64 ts_unix = 1; double cpu = 2; uint64 mem_used = 3; uint64 mem_total = 4; double load1 = 5; uint64 disk_used = 6;
  uint64 disk_total = 7; uint64 net_rx = 8; uint64 net_tx = 9; uint32 conns = 10; uint64 refused_prehello = 11; uint64 refused_total = 12;
  uint64 evicted_prehello = 13; uint64 up = 14; uint64 down = 15; uint32 devices_sum = 16; }
message ProxyTotal { string proxy_id = 1; string name = 2; string node_id = 3; uint64 up = 4; uint64 down = 5; uint64 conns_new = 6; uint32 devices_peak = 7; }
message CountryTotal { string country = 1; uint64 bytes = 2; uint32 ips_peak = 3; }
message CountriesResponse { repeated CountryTotal countries = 1; string policy = 2; string geoip_month = 3; string attribution = 4; string attribution_url = 5; }
message IpSighting { string ip = 1; string country = 2; int64 first_seen_unix = 3; int64 last_seen_unix = 4; uint64 bytes = 5; }
message MemberHour { int64 ts_unix = 1; uint32 up_minutes = 2; uint32 down_minutes = 3; uint32 unknown_minutes = 4; uint32 latency_avg_ms = 5; uint32 latency_max_ms = 6; string exit_ip = 7; }
message MemberHistory { string chain_id = 1; string member_key = 2; repeated MemberHour hours = 3; }
```

**Requirements:** admin only; ranges and resolutions per Global Constraints (UI) with the stored retention; `NodeSeries` and `ProxySeries` return `step_seconds`, `from_unix`, `to_unix` like `ProxySeries` today, and `ProxySeries` accepts `90d` and `1y`; `NodeSeries` merges `NodeTraffic` into its points (`up`, `down`, `devices_sum`); `Overview` combines `LatestNodeMinutes` (within 3 min), `TrafficSince` (which includes partial hours) and `PhaseCounts` (paused = disabled proxies); `ListIpSightings` answers `FailedPrecondition` ("the IP policy keeps no addresses") unless the policy is `full`; `Countries` returns the attribution and the policy; `EgressHistory` hours from `egress_health`.

**Tests:** every RPC against a seeded store with fixed clocks; range validation; resolution switch with a shorter stored retention; node points with traffic and `devices_sum`; policy refusal of `ListIpSightings`; unauthenticated calls refused.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/...'` → PASS → commit `feat(panel): statistics API for nodes, top proxies, countries, IP history and egress history`.

---

### Task 8: Probes from the panel

**Start:** after slice 2 is merged into `dev` (needs `probe.L2`) — `lane/s6-probes`, beside Tasks 4–7 · **Model:** sonnet

**Files:** Create `proto/postern/panel/v1/probes.proto` (+ regen Go and TS), `internal/panel/probes/{scheduler.go,prober.go,availability.go,service.go}` + tests; modify `internal/panel/server/{server.go,api.go}` (scheduler start and stop, `publicpage.WithProbeDown`).

**Interfaces:**
- Consumes: `store.InsertProbe` (Task 1), `store.Probes`/`LastProbes` (Task 1b), `store.StatsSettings`, `probe.L2`, `probe.FakeTLS`, `publicpage.WithProbeDown` (Task 3).
- Produces:

```go
package probes
type Target struct{ ProxyID, Type, Addr, SNI string; Secret []byte } // Addr = link host:port
type ProbeFunc func(ctx context.Context, t Target) (p store.Probe, l1OK bool) // the real one runs probe.L2, then probe.FakeTLS on failure
func NewScheduler(db *store.DB, key seal.Key, log *slog.Logger, opts ...Option) *Scheduler // WithProbe, WithNow, WithRand (tests)
func (s *Scheduler) Start(ctx context.Context)
func (s *Scheduler) Probe(ctx context.Context, proxyID string) (store.Probe, bool /* l1 ok */, error) // runs and stores one probe now; no rate limit, no audit
func (s *Scheduler) Down(proxyID string) bool
func (s *Scheduler) OnResult(fn func(p store.Probe))   // Task 10c: problem feed
```

```proto
service ProbeService {
  rpc ProbeNow(ProbeNowRequest) returns (ProbeNowResponse);            // { proxy_id } → { kind, ok, latency_ms, error, l1_ok }
  rpc ProbeHistory(ProbeHistoryRequest) returns (ProbeHistoryResponse); // { proxy_id, range "24h" | "7d" } → points, uptime per vantage
}
```

**Requirements:** Global Constraints (Probes); the interval from `store.StatsSettings`, read at every round. Scheduler: enabled proxies of online nodes with a link host; WEB proxies are skipped until Task 13; each round's time = the proxy's offset moved by a random ±20 % of the interval; an interval change applies at the next round; results stored with `InsertProbe` (vantage `panel`, kind `l2`). Events: `probe.failed` (warn) at the second failure in a row, once a streak; `probe.recovered` (info). `ProbeNow` (the RPC): admin only, one per proxy per 5 s, audit `probe.run`, then `Probe`. `ProbeHistory`: points (time, vantage, ok, latency) and uptime = ok ÷ total per vantage over the range. The secret is opened with the master key at probe time and never logged; errors are the classes of Global Constraints. The public page's availability uses `Down`.

**Tests:** offsets, jitter bounds and spread with a fake clock and a fixed random source; interval 0 = off; change of interval; paused/offline/no-link-host skipped; classification with fake probe functions (L2 ok; L2 failed and L1 ok; both failed) and the real wrappers against fakes (`probe/probetest` for the DC side where it applies); concurrency cap; streak events once; `Down` rule at its bounds; `ProbeNow` rate limit and audit; uptime arithmetic; the scheduler stops with its context.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/probes/...'` → PASS → commit `feat(panel): probes of the proxies from the panel`.

---

### Task 9a: Node diagnostics: framework and host checks

**Start:** after Task 5 — `lane/s6` · **Model:** opus

**Files:** Create `internal/node/diag/{diag.go,catalogue.go,schedule.go,scrub.go,light.go,host.go,ingress.go}` + tests (incl. `FuzzDateSkew`); create `internal/node/agent/diag.go` (`RunDiagnostics`, light loop wiring); modify `internal/node/agent/{buffer.go,server.go,run.go,info.go}`, tests.

**Interfaces:**
- Consumes: Task 4 messages, the edge client (`Health`, `Snapshot`), `internal/doh` (slice 2), `dockerapi.Client`, `state.Store`.
- Produces:

```go
package diag
type Result struct{ ID, Layer, Target string; Status nodev1.CheckStatus; Summary, Evidence, Hint, Fix string; Checked time.Time; Duration time.Duration }
type Check struct{ ID, Layer string; Light bool; Every time.Duration; Run func(ctx context.Context, env *Env) []Result }
type SocketOwner struct{ Bind string; Port uint16; PID int; Owner string; Known bool } // one listening socket; Known false: its pid could not be read
type Env struct{ /* state store, docker, edge client, drivers, artifacts, HTTP client, DoH client, UDP dialer, proc FS, clock, scrubber,
                   PortOwners func(context.Context) []SocketOwner (the agent's lookup, passed in: diag must not import agent) */ }
type Runner struct{ /* … */ }
func NewRunner(env Env, checks []Check) *Runner                       // Tasks 9b and 9c add their checks to the catalogue
func (r *Runner) Run(ctx context.Context, scope string, emit func(Result)) error // full run; ErrBusy while one runs
func (r *Runner) Light(ctx context.Context, report func(rep *nodev1.DiagnosticsReport, buffered bool))
type Scrubber struct{ /* … */ }
func NewScrubber(st *nodev1.NodeState, rt *state.Runtime, keep []netip.Addr) *Scrubber // secrets and the IP redactor of Global Constraints
func (s *Scrubber) Clean(text string) string
```

**Requirements:**
- Global Constraints (Diagnostics: shape, evidence limits, scrubber and IP redactor, scheduling, hysteresis, scopes, the `host.*` and `ingress.bound` rows).
- Runner: full runs check up to 16 at a time, each check with its timeout (10 s; clock and DNS 15 s); 3 min overall; results emitted as they finish. Light: per (check, target) at its cadence with ±10 % jitter, at most 16 at a time, a check whose previous run is still going skips its turn; hysteresis; `DiagnosticsReport` buffered on change, live-only every 15 min.
- `RunDiagnostics`: scope `node` or `proxy:<id>` (unknown → `InvalidArgument`), a second run → `ResourceExhausted`, results streamed, node event `diagnostics_run` with the counts at the end; capability `diagnostics`.
- Buffer: `recordKind` knows the `diagnostics` payload; the journal drops a waiting live diagnostics report before buffering a newer one, as `dropLiveStatesLocked` does for state reports.
- Scrubber: rebuilt from the desired state and runtime for every run and light round; covers every form in Global Constraints; keeps only 127.0.0.1, 127.0.0.2, ::1, the node's public IPs, DC addresses, DoH endpoints and egress member addresses.
- `host.clock`: requests to the four DoH endpoints by IP literal, direct, TLS verified; `Date` taken from any completed response, 4xx included (the endpoints reportedly answer `HEAD` on `/dns-query` with 415 or 400: implementer verifies against upstream); skew = distance from the local time at the response to [`Date`, `Date` + 1 s], widened by RTT/2 on each side; median of ≥ 2; spec thresholds (warn > 2 s, fail > 30 s).
- `host.dns`: a fresh random `<16 hex>.telegram.org` asked over UDP straight to 1.1.1.1:53 and 8.8.8.8:53 (never the `resolv.conf` stub, which may be systemd-resolved at 127.0.0.53 and answer while UDP/53 is dropped) and over DoH; UDP counts as working when its answer matches DoH's (both NXDOMAIN, or the same addresses); a different answer is hijacked; a timeout or ICMP unreachable is blocked; the mode comes from the desired state and the forwarder's state from the edge's `Health.dns`.
- `host.ports`: per listener, `fail` when any listening socket on that bind and port belongs to a process that is not the edge container's; a socket whose owner cannot be read makes it `warn` ("owner unknown"), never `ok` through the expected-address fallback of `portOwners` (`info.go` exposes per-socket owners with a known/unknown flag).
- `host.public_ips`: the node's public IPs are known, every listener's specific bind IP (not `0.0.0.0`) is one of them; `warn` when the set changed within 24 h (evidence: old and new); `fail` when none is known or a bind IP is not among them.
- `host.disk`, `host.memory`, `host.reserved_ports`, `host.edge_caps` (refusal counters from `Snapshot`, compared with 10 min before), `ingress.bound` (`Health.bound`).

**Tests:** framework (scope filtering, busy refusal, overall deadline, streaming order, 16-slot limit, a slow light check skips its turn, hysteresis, report buffered on change only, live dedupe in the journal, `recordKind`); `RunDiagnostics` over the real mTLS test server; scrubber sentinel for every form (hex, `ee`, base64 forms, `dd`, both `0x70` forms, ad tag, API token, an egress password, a WARP token) and the IP redactor (a client IPv4, a client IPv6 and 127.0.0.3 → `<ip>`; 127.0.0.1, a DC address and a node public IP kept); `host.clock` against TLS servers that answer 415 with a `Date` 3 s and 40 s off, a slow handshake within the thresholds, too few answers; `host.dns` with fake UDP servers (agreeing, timing out, answering a forged A) and a fake DoH, in both modes; `host.ports` with two `SO_REUSEPORT` sockets on one port, one of them a foreign pid (fake proc FS), and an unreadable owner; `host.public_ips` set changes; disk, memory and reserved ports from a fake proc FS; `FuzzDateSkew` (never panics, skew never negative).

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/...'` and `bash scripts/wsl 'go test -run=^$ -fuzz=^FuzzDateSkew$ -fuzztime=20s ./internal/node/diag/'` → PASS → commit `feat(node): diagnostics framework, host checks and RunDiagnostics`.

---

### Task 9b: Node diagnostics: engine checks

**Start:** after Task 9a — `lane/s6` · **Model:** opus

**Files:** Create `internal/node/diag/engine.go` + tests (incl. `FuzzDCs`), `internal/node/diag/testdata/dcs_*.json`, `internal/engines/telemt/health.go` (+ test); modify `internal/engines/driver.go` (optional `HealthReporter`), `internal/engines/telemt/{telemt.go,integration_test.go}` (`RUST_LOG` in the container spec, the log-level proof), `internal/dockerapi/{types.go,client.go,fake.go}` (`RestartCount`), the catalogue registration in `internal/node/agent/diag.go`.

**Interfaces:**

```go
package engines
type DCHealth struct{ DC int; AvailableEndpoints int; AvailablePct, CoveragePct float64 }
type EngineHealth struct{ Ready bool; MiddleProxy bool; Reason string; DCs []DCHealth } // MiddleProxy false: ME off or no snapshot (Reason says which)
type HealthReporter interface{ Health(ctx context.Context, in Instance) (EngineHealth, error) } // telemt implements it; others: engine.dcs is skip
type LogLeveler interface{ LogEnv() []string } // container env that sets the engine's log level (telemt: RUST_LOG=…)
```

**Requirements:**
- `engine.container`: the serving generation's container (runtime record): `running` → ok; restarted within 10 min (`RestartCount` grew) → warn; `paused` (Docker reports `Running=true`, and the reconciler leaves a paused engine alone) → fail "paused"; exited, dead, restarting or a crash loop → fail with the last 20 log lines, scrubbed and IP-redacted; fix `recreate_instance`.
- `engine.ready`: telemt `GET /v1/health/ready` with the instance's API token.
- `engine.dcs`: telemt `GET /v1/stats/dcs`, decoded as `{ok, data: {middle_proxy_enabled, reason, dcs: [{dc, available_endpoints, available_pct, coverage_pct}]}}` (the shape a reviewer read in telemt's API doc: implementer verifies against upstream, telemt 3.5.13, and saves a captured body in testdata); `middle_proxy_enabled = false` → skip with the reason (`feature_disabled`, `source_unavailable`), never fail; every DC at 100 % available and covered → ok; some lower → warn; all 0 → fail.
- `engine.version`: running vs desired for more than 10 min → warn.
- `engine.log` (R6-2): light, 60 s; reads only the lines since its last read (Docker logs `since`), at most 64 KiB, scrubbed and IP-redacted; maps known lines to a cause, a hint and a fix through a table in code ("All ME servers for DC failed" → the middle-proxy path is down, hint `egress.me` and the NAT IP, fix `change_egress`; "proxy-secret is unavailable" → getProxySecret fails, same hint; the implementer completes the table from the telemt 3.5.13 sources); unknown error lines are counted in evidence, never quoted.
- Log level: the highest telemt 3.5.13 level that an integration test proves free of secrets (hex, base64 and link forms, the API token) and of client addresses (a PROXY-header source 198.51.100.77), through start-up, good and bad handshakes, a dead DC and a blocked getProxySecret. It is set through the container's `RUST_LOG` (`LogLeveler`); that `RUST_LOG` wins over the config's `log_level`: implementer verifies against upstream (telemt 3.5.13). The env is outside the instance hash, so the update rolls no engine; generations started before keep `silent` until their next roll, and `engine.log` reports skip for them. If the level has to go into the rendered config instead, the report says every engine rolls once. If no level qualifies, `engine.log` is skip ("engine logs are off") and the report records the deviation. Secrets stay out of the log through `[general.links] show = []`, which stays.

**Tests:** each check with fakes (`dockerapi.Fake` with `paused`, restart counts and states; an `httptest` telemt API with the captured body, ME off with each reason, partial and zero availability; a fake log stream with the `since` cursor, the 64 KiB cap, each known line, an unknown line and a planted secret and address that never reach a result); `FuzzDCs` (any JSON: no panic, ME-off never fails); integration (tag `integration`, real telemt 3.5.13): the log-level proof.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/diag/... ./internal/engines/... ./internal/dockerapi/...'`, `bash scripts/wsl 'go test -run=^$ -fuzz=^FuzzDCs$ -fuzztime=20s ./internal/node/diag/'` and `bash scripts/wsl 'go test -tags integration -run TestLogLevel ./internal/engines/telemt/'` → PASS → commit `feat(node): engine checks with telemt's API and log`.

---

### Task 9c: Node diagnostics: egress and e2e checks

**Start:** after Task 9b — `lane/s6` · **Model:** opus

**Files:** Create `internal/node/diag/{egress.go,e2e.go}` + tests; modify `internal/node/reconcile/gate.go` (export the DC ping and getProxySecret checks), the catalogue registration and the `addProbe` hand-off in `internal/node/agent/diag.go`.

**Interfaces:**
- Consumes: `addProbe` (Task 5), `probe.FakeTLS`, `probe.L2`, `state.TestListenerPortKey`, the edge's member health.
- Produces:

```go
package reconcile
func PingDC(ctx context.Context, socksAddr, dc string) error      // what the gate does, exported
func ProxySecretCheck(ctx context.Context, socksAddr string) error
```

**Requirements:** Global Constraints (catalogue rows `egress.*`, `e2e.*`). `egress.member` from the edge's health (status, latency, exit IP, last check age); `egress.dc` and `egress.me` through the serving instance's SOCKS port with the exported gate checks; `e2e.l1` and `e2e.l2` through the test listener of the proxy's listener without a PROXY header; `e2e.l2` (every 10 min per fake-TLS proxy) also hands a `ProbeResult` (kind `l2`) to `addProbe`. A per-member HTTPS check is a recorded deviation (it waits for an edge health field).

**Tests:** with fakes: `probetest` datacenters, a fake SOCKS member that acknowledges early and then closes, fake member health (up, down with a sibling up, all down, unknown); L1 and L2 through a fake test listener; probe results handed over; fixes per row.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/...'` → PASS → commit `feat(node): egress and end-to-end checks`.

---

### Task 10a: Panel diagnostics: runs and light checks

**Start:** after Tasks 6, 8 and 9a (merge `lane/s6-panel` and `lane/s6-probes` into `lane/s6` first) · **Model:** opus

**Files:** Create `proto/postern/panel/v1/diagnostics.proto` (every RPC of the service; + regen Go and TS), `internal/panel/diagnostics/{service.go,runner.go,panelchecks.go,lightreports.go}`, `internal/panel/store/diagnostics.go` + tests; wiring in `internal/panel/server`.

**Interfaces:**
- Consumes: `Manager.Client` and node capabilities, `Ingestor.OnDiagnostics` (Task 6), `Scheduler.Probe` (Task 8), `RunDiagnostics` (Task 9a), store tables (Task 1).
- Produces:

```proto
service DiagnosticsService {
  rpc StartRun(StartRunRequest) returns (StartRunResponse);      // { node_id, scope } → { run_id }; a run of that node in progress → its id
  rpc GetRun(GetRunRequest) returns (DiagnosticRun);              // the run, its results so far, state
  rpc ListRuns(ListRunsRequest) returns (ListRunsResponse);       // { node_id, proxy_id, limit ≤ 50 }
  rpc LatestChecks(LatestChecksRequest) returns (LatestChecksResponse); // light checks of a node (or a proxy's targets)
  rpc ApplyFix(ApplyFixRequest) returns (ApplyFixResponse);       // Task 10b: { node_id, check_id, target, fix, chain_id, offered_run_id }
  rpc ListProblems(ListProblemsRequest) returns (ListProblemsResponse); // Task 10c
  rpc ListJournal(ListJournalRequest) returns (ListJournalResponse);    // Task 10c
}
message CheckResult { string id = 1; string layer = 2; string target = 3; string status = 4; string summary = 5; string evidence = 6;
  string hint = 7; string fix = 8; bool fix_available = 9; string fix_unavailable_reason = 10; string vantage = 11; int64 checked_unix = 12; int64 since_unix = 13; }
message DiagnosticRun { string id = 1; string node_id = 2; string scope = 3; string reason = 4; string change = 5; string related_run_id = 6;
  string state = 7; string error = 8; int64 started_unix = 9; int64 finished_unix = 10; repeated CheckResult results = 11; bool regressed = 12; }
message Problem { string severity = 1; string kind = 2; string node_id = 3; string proxy_id = 4; string summary = 5; string hint = 6;
  int64 since_unix = 7; string check_id = 8; string target = 9; string fix = 10; bool fix_available = 11; }
```

```go
package diagnostics
func (r *Runner) Run(ctx context.Context, nodeID, scope, reason, change, relatedRunID string) (runID string, err error) // a busy node: waits for its run, bounded by ctx
func (r *Runner) Wait(ctx context.Context, runID string) (*store.DiagnosticRun, error)
func (r *Runner) CopyLight(ctx context.Context, nodeID, scope, change string) (runID string, err error) // a before_change run made of the current light checks
// The service embeds panelv1connect.UnimplementedDiagnosticsServiceHandler: Tasks 10b and 10c add ApplyFix, ListProblems and ListJournal.
```

**Requirements:**
- Runs: a goroutine per run; the panel rows of the catalogue first, then the node's stream when the node is connected and reports `diagnostics` (else one `panel.connection` result saying why, state `skipped`); results stored as they arrive (evidence only for warn and fail, ≤ 64 KiB a run); counts and state at the end (`done`; `partial` when ctx ended first; `failed` on an error); audit `diagnostics.run` for manual runs; one run per node at a time.
- An `after_change` run with a related run sets `regressed` when a check that was `ok` or `warn` in the related run is `fail` now, and records event `diagnostics.regressed` (error) naming the change.
- `panel.link_host` resolves names with the system resolver; `ingress.external` runs `Scheduler.Probe` (fake TLS) and is `skip` for WEB until Task 13.
- Light reports: `OnDiagnostics` replaces the node's `node_checks` rows (keeping `since` of unchanged statuses) and records transition events per Global Constraints.
- `fix_available` (shared with Task 10b): false with a reason when the node lacks the fix's capability or the target does not match the check.

**Tests:** run orchestration with a fake node stream (results stored in order, deadline → `partial`, node offline and node without capability → `skipped`, busy node: `Run` waits, `StartRun` returns the running id); `Wait`; regression detection on a related pair; `CopyLight`; panel checks with fakes (offline, rejection, behind, edge outdated, link host not a node address, GeoIP stale); evidence limits; light report replacement and transition events with their rate limit.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/...'` → PASS → commit `feat(panel): diagnostics runs and light checks`.

---

### Task 10b: Panel diagnostics: fixes and before/after runs

**Start:** after Task 10a — `lane/s6` (slice 2's panel on the base) · **Model:** opus

**Files:** Create `internal/panel/diagnostics/{fixes.go,changes.go,auto.go}` + tests; modify `internal/panel/proxies/service.go` (`RestartInstance`; `mutate` gains a pre-commit point and `SetChangeHooks`), `internal/panel/egress/{service.go,chains.go}` (`SetChangeHooks`; the hooks around `UpdateEgress`, `SetNodeDnsMode`, `SetNodeDefaultChain`), `internal/panel/nodes/service.go` (`RollEdge`), wiring in `internal/panel/server`.

**Interfaces:**
- Consumes: `Runner.Run`/`Wait`/`CopyLight` (Task 10a), `Ingestor.OnServingChange` (Task 6), slice 2's mutations `UpdateProxy` (`egress_chain_id`, `egress_scope_chains`), `SetNodeDefaultChain`, `UpdateEgress`, `RefreshSubscription`, `SetNodeDnsMode`.
- Produces:

```go
package proxies // and package egress, the same type and setter
type ChangeHooks struct {
  Before func(ctx context.Context, nodeID, scope, change string) (beforeRunID string) // full run of the scope, ≤ 90 s; never refuses the change
  After  func(nodeID, scope, change, beforeRunID string, generation uint64)          // after-run once the node applied generation (+ 60 s)
}
func (s *Service) SetChangeHooks(h ChangeHooks)
func (s *Service) RestartInstance(ctx context.Context, proxyID string) (generation uint64, err error) // restart_nonce + 1
package nodes
func (s *Service) RollEdge(ctx context.Context, nodeID string) (generation uint64, err error)        // edge_roll_nonce + 1
```

**Requirements:**
- `ApplyFix`: the fix catalogue of Global Constraints; capability gating (`FailedPrecondition` with the reason); `change_egress` requires a chain usable on the node; the before-run is the run named by `offered_run_id`, or a `CopyLight` of the light checks when the fix was offered from them; the change goes through the same mutation (and audit) as the UI's own edit; audit `diagnostics.fix`, event `diagnostics.fix_applied`; the after-run is related to the before-run.
- Operator edits (Global Constraints, Before and after changes): `mutate` plans and validates under the node-data lock, releases it, calls `Before` (which waits at most 90 s and returns a `skipped` or `partial` run when the node is offline, lacks `diagnostics` or the time is over), takes the lock again, plans and validates again against the current data (a change that no longer validates is refused: `FailedPrecondition` "the data changed meanwhile"), commits (generation, notify), then calls `After`. The same in the egress service for `UpdateEgress` (scope `node` on every node that uses the egress), `SetNodeDefaultChain` and `SetNodeDnsMode`, and for `UpdateProxy` changes of `egress_chain_id`, `egress_scope_chains` or `engine_version`. `RefreshSubscription` is not an edit (no before-run of its own unless it is a fix).
- Node-initiated changes: `OnServingChange` without a pending operator change, and member failover reported by the light checks, get a `CopyLight` before-run and a full after-run 60 s later; more than 3 proxies of a node within 60 s → one `node` run; at most one automatic after-run per node and scope per 5 min.

**Tests:** every fix (nonce bumped and node notified, chain change validated, capability gating, offered run as before-run, light copy otherwise, audit, event, related after-run); the edit flow with a fake runner (Before called outside the lock with the right scope, the 90-s cap, offline → `skipped`, a concurrent change between Before and commit refused, After with the generation); egress edits reach every node that uses the egress; automatic pairs, coalescing above 3 proxies, the 5-min limit.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/panel/...'` → PASS → commit `feat(panel): safe fixes and full diagnostics before and after changes`.

---

### Task 10c: Panel diagnostics: problem feed and journal

**Start:** after Task 10a — `lane/s6` · **Model:** sonnet

**Files:** Create `internal/panel/diagnostics/{problems.go,journal.go}`, `internal/panel/store/journal.go` + tests.

**Interfaces:** Consumes node rows, `node_checks`, the ingestor's statuses, `Scheduler.Down`/`OnResult` (Task 8), `geodb.Manager.Status` (Task 2), events and audit. Produces `ListProblems` and `ListJournal` on the service of Task 10a, and `store.ListEventsFiltered`, `store.ListAudit`.

**Requirements:**
- Problems, worst first then newest: nodes offline or in error, state rejections and `last_error`; failed proxies; `node_checks` in warn or fail (with their fix and `fix_available`); proxies down by the panel's probes; GeoIP missing or stale while a policy uses countries; outdated edges.
- Journal: events filtered by node, proxy, severity at least, kind prefix and time range; audit filtered by admin and action prefix; newest first; an opaque cursor of `(ts, id)`; ≤ 200 per page.

**Tests:** problem composition and order from seeded state; journal filters and cursor paging over equal timestamps.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/...'` → PASS → commit `feat(panel): problem feed and journal`.

---

### Task 11a: Web UI: proxy and node statistics

**Start:** after Task 7 — `lane/s6-panel` (Task 3b merged in) · **Model:** sonnet

**Files:** Create `web/src/components/{StatsSection,RangeSelect,TrafficPanel,ConnectionsPanel,DevicesPanel,CountriesPanel,IpHistoryTable,NodeStatsSection,EgressHistory}.tsx` (+ tests), `web/src/app/countries.ts` (`Intl.DisplayNames` helper, + test), `web/src/api/hooks/metrics.ts`; modify `web/src/pages/{ProxyDetail,NodeDetail}.tsx`, `web/src/i18n/insights.{en,ru}.json`; regenerate TS if needed (`npm run gen`).

**Interfaces:** Consumes `MetricsService`, `StatsService` (TS clients). Produces the components above.

**Requirements:**
- Proxy page: a statistics section with a range selector replacing the 24-h `TrafficChart`: traffic (area, down/up), connections (new per period, peak), unique IPs (peak), countries (bar or donut by traffic and a table with bytes and "peak unique IPs in a minute", caption "IP Geolocation by DB-IP" linking `https://db-ip.com`), IP history (policy `full` only: IP, country, "first seen", "last seen", "bytes since first seen"; paging; country filter; otherwise a note naming the policy).
- Node page: CPU, memory, load, disk, network, connections, traffic and "Unique IPs, sum of proxies", edge refusals when any; egress member history (uptime per hour as stacked bars, latency line, exit IP changes) beside the health table of slice 2.
- Country names from `Intl.DisplayNames` in the page's language (code shown when unknown, `''` as "unknown"); no flags or fonts from CDNs.
- Charts per Global Constraints (UI); byte and number formatting through `app/format.ts`; every string in the slice's string files.

**Tests:** each panel renders fixture data and its empty state; a range change refetches; the countries caption; IP table paging, filter and the policy note; country names in RU and EN; i18n parity.

**Steps:** tests → FAIL → implement → in `web/` `npm run lint && npm run typecheck && npm test -- --run && npm run build` → PASS → commit `feat(web): statistics of proxies and nodes`.

---

### Task 11b: Web UI: Overview, Settings sections and About

**Start:** after Task 11a — `lane/s6-panel` · **Model:** sonnet

**Files:** Create `web/src/components/{TopProxiesCard,CountriesCard,StatsSettingsForm,GeoIPSettings,StorageInfo,AboutDialog}.tsx` (+ tests), `web/src/api/hooks/{settings,geoip}.ts`; modify `web/src/pages/{Overview,Settings}.tsx`, `web/src/components/{NodeCard,AppShell}.tsx` (About), `web/src/i18n/insights.{en,ru}.json`.

**Interfaces:** Consumes `MetricsService`, `SettingsService`, `GeoIPService`, `PUT /api/geoip`. Produces the components above.

**Requirements:**
- Overview: node tiles show CPU, RAM, connections and traffic since local midnight (`since_unix` from the browser); cards "top proxies (24 h)" and "countries (24 h)" (with the attribution caption).
- Settings: retention fields with their ranges; IP policy with the privacy text of §8.6, a confirmation when leaving `full` ("the IP history is deleted") and when choosing `off` ("the country history is deleted"); probe interval (help: panel probes reveal the fleet to anyone who can observe the panel's traffic); extra probe sources (single addresses); the learned panel addresses per node with a warning on each `shared` one ("everyone behind this address is exempt from the limits of every proxy"); GeoIP status, refresh, upload, enable switch, attribution; storage (database size, rows per table).
- About dialog in the shell: versions, AGPL-3.0, DB-IP attribution and licence.

**Tests:** overview tile values and the midnight computation; cards; settings validation, both confirmations, the shared-address warning, the GeoIP upload flow with a fake API; About attribution; i18n parity.

**Steps:** tests → FAIL → implement → in `web/` `npm run lint && npm run typecheck && npm test -- --run && npm run build` → PASS → commit `feat(web): overview cards, statistics settings and About`.

---

### Task 12: Web UI: diagnostics, probes, problem feed, journal

**Start:** after Tasks 10b, 10c and 11b — `lane/s6` · **Model:** sonnet

**Files:** Create `web/src/components/{DiagnosticsSection,CheckList,CheckRow,FixDialog,RunHistory,AvailabilitySection,ProblemFeed,ChangeCheckNotice}.tsx`, `web/src/pages/Journal.tsx` (+ tests), `web/src/api/hooks/{diagnostics,probes}.ts`; modify `web/src/pages/{NodeDetail,ProxyDetail,Overview}.tsx`, `web/src/app/router.tsx`, `web/src/components/AppShell.tsx` (Journal in the navigation), the forms whose saves run a before-check (`ProxyForm.tsx` and slice 2's egress, chain and DNS-mode forms), `web/src/i18n/insights.{en,ru}.json`.

**Interfaces:** Consumes `DiagnosticsService`, `ProbeService`. Produces the components and the `/journal` route.

**Requirements:** Node page: latest light checks grouped by layer (status badge, summary, expandable evidence and hint, since); "Run full check" → live results (poll `GetRun` every 1 s until done); "Fix" per result with `fix_available` (a confirmation that says what will change, e.g. "starts a new engine generation; the old one drains"; for `roll_edge` also "the edge runs the agent's version afterwards"; disabled with the reason otherwise); run history with before/after pairs and a "regressed" badge. Proxy page: availability (probe now, last result with its class, uptime 24 h / 7 d per vantage, latency chart), "check this proxy" (scope `proxy:<id>`). Overview: the problem feed (severity, summary, since, link to the node or proxy, fix button when available). Journal page: events and audit tabs, filters, "load more" by cursor. Forms that trigger a before-run show "checking the node before the change (up to 90 s)…" while saving and link the before and after runs afterwards.

**Tests:** run flow with fake timers (polling stops when done and on unmount); fix confirmation, disabled fix with its reason; problem feed links and fix; probe now result rendering; the change notice on a slow save; journal filters and paging; router and navigation; i18n parity.

**Steps:** tests → FAIL → implement → in `web/` `npm run lint && npm run typecheck && npm test -- --run && npm run build` → PASS → commit `feat(web): diagnostics, probes, problem feed and journal`.

---

### Task 13: WEB proxies in the diagnostics, and the certificate fix

**Start:** after slice 3 is merged into `dev` (and into `lane/s6` if it is still open); after Tasks 9c and 10b · **Model:** opus

**Files:** Modify `proto/postern/node/v1/node.proto` (`WebSettings.reissue_nonce`, next free) + regen, `internal/node/acme` (reissue when the nonce changes), `internal/node/state/validate.go`, create `internal/node/diag/web.go` + light wiring, `internal/panel/probes` (kind `web`), `internal/panel/diagnostics` (panel web checks, fix `reissue_cert`), `internal/panel/proxies/statebuilder.go` (`reissue_nonce` from `cert_reissue_nonce`), `internal/node/agent/server.go` (capability `web-diagnostics`), web: availability and fix texts; tests.

**Interfaces:** Consumes slice 3: `acme.Manager.Issue/Status`, the node precheck (`internal/node/acme/precheck.go`), the panel preflight (`internal/panel/preflight`), `links.Web`, WEB routes and certificates of the edge. Produces the `web.*` checks and the fix.

**Requirements:**
- Node checks (target `proxy:<id>` of a WEB proxy): `web.cert` (ok ≥ 14 days left; warn < 14; fail < 3, expired, missing, or not valid for the domain; evidence: expiry, issuer, last ACME error; fix `reissue_cert` for `acme-dns01` only), `web.dns` (A record by DoH equals the listener's public address and is not a Cloudflare address; fail otherwise), `web.http2` (light, 10 min: TLS to the test listener with SNI = domain and ALPN `h2`, the served certificate equals the stored fullchain, `GET /` → 200 over HTTP/2; also a node `ProbeResult` of kind `web`), `web.decoy` (full: the decoy index exists in the instance directory).
- Panel: probes of kind `web` for WEB proxies: `GET https://<domain>/` (or `/<base_path>/`) with the system roots → 200 and HTTP/2; `ingress.external` uses it; panel check `web.base_path` for the `http-upstream` placement: `GET https://<domain>/<base_path>` without the slash must not be a redirect. This is the HTTP/2 + decoy level only (a recorded deviation: no MTProto-level WEB probe).
- `reissue_cert`: `proxies.cert_reissue_nonce` + 1 → `WebSettings.reissue_nonce`; the node issues again when the nonce differs from the one recorded with the certificate (`meta.json`), even when the certificate is valid, under the per-domain lock; refused (validation) for `imported` and `external` modes.
- Capability `web-diagnostics`; the panel offers the fix only to such nodes.

**Tests:** each check against slice 3's test helpers (test CA, fakes of the ACME status); reissue on nonce change (fake ACME) and not on restart; validation refuses reissue for imported; panel web probe against an `httptest` TLS server (HTTP/2 on, a redirect on the no-slash path detected); fix gating.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/... ./internal/panel/...'` → PASS → commit `feat: diagnostics of WEB proxies and the certificate reissue fix`.

---

### Task 14: The panel's probes at the edge (probe sources)

**Start:** after slice 3 is merged into `dev` (the edge's WEB routes); after Tasks 4 and 6 · **Model:** opus

**Files:** Modify `proto/postern/edge/v1/edge.proto` (`repeated string probe_sources`, next free in `EdgeConfig`) + regen, `internal/edge/{edge.go,table.go,conn.go,limits.go,counters.go,web.go}`, `internal/node/reconcile/edgecfg.go`, `internal/node/agent/server.go` (capability `probe-sources`), tests.

**Interfaces:** Consumes `NodeSettings.probe_sources` (Task 4, filled by Task 6). Produces the exemption (Global Constraints: Probes, R6-1).

**Requirements:** the agent copies `NodeSettings.probe_sources` into `EdgeConfig.probe_sources`; the edge parses each entry as one IP address (unmapped; an entry it cannot parse is ignored and logged once) into a set swapped atomically with the table. A connection accepted on a public listener (never a test listener) whose source address equals an entry is exempt while its proxy has fewer than 4 exempt connections open (a fifth from a probe source is an ordinary client): no device slot, no device, total or per-IP limit, no IP counter (fake TLS and WEB routes alike); its bytes and its connection count in the proxy's totals; it is closed 30 s after accept. The blacklist and the pre-hello caps (slices 0–1 Task 25) still apply. The agent reports `probe-sources` only while the running edge's version equals its own (the edge enforces the exemption, Ruling 38).

**Tests:** a proxy with `devices = 1` and a client connected from one address: a connection from a probe source passes and takes no device slot, one from another address is refused; a fifth simultaneous exempt connection is limited like a client; an exempt connection is closed at 30 s (fake clock); its bytes are counted, its address never appears in the IP counters; WEB route alike; a probe source on a test listener changes nothing; a blacklisted probe source is still dropped; a table swap changes the set; the capability follows the edge version; edge config golden.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/edge/... ./internal/node/...'` → PASS → commit `feat(edge): the panel's probes take no device slot, bounded`.

---

### Task 15: Diagnostics around rollout steps (slice 5 hooks)

**Start:** after slice 5's rollout runner (its Task 10, with the hook amendments of slice 5's revision) is merged into `dev`; after Tasks 10a and 10b · **Model:** sonnet

**Files:** Create `internal/panel/diagnostics/rollout.go` (+ tests); modify the server wiring of the rollout runner (`rollout.Config.Hooks`), the rollout view of the Versions page (links to the runs), `web/src/i18n/insights.{en,ru}.json`.

**Interfaces:** Consumes slice 5's `rollout.Hooks{BeforeStep, AfterStep func(ctx, *store.Rollout, *store.RolloutStep) error}` ("a hook error fails the step") as amended by slice 5's revision — `AfterStep` also runs after a failed step was reverted (`s.Status` = `reverted`, its error ignored) and the step timeout starts after `BeforeStep` returns — its step items and nodes; `Runner.Run` and `Runner.Wait` (Task 10a); the automatic-pair suppression of Task 10b. Produces the hooks and the pair of runs per step.

**Requirements:** `BeforeStep`: for every node of the step, one full run of scope `node` (one run per node at a time, Task 10a), reason `before_change`, change "rollout <id> step <n>", the nodes in parallel; it waits at most 3 min in all and never fails: a run that cannot run is recorded `skipped` or `partial`. From `BeforeStep` the automatic pairs of Task 10b are suppressed for the step's nodes; `AfterStep` (after a successful check or a revert) lifts the suppression — or it lifts itself 60 min after `BeforeStep` at the latest — and starts the same runs with reason `after_change`, related to the before runs (regressions marked by the runner). Both hooks always return nil: diagnostics inform, slice 5's checks decide (§0.2). The rollout view links each step's before and after runs with the regression badge.

**Tests:** fake runner and fake rollout records: one run per node of the step, in parallel; before/after linked; after-runs also after a reverted step; regression marked; hooks return nil when runs fail or time out; the 3-min bound and the 60-min self-lift with a fake clock; no automatic pair inside a step.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/panel/...'`, slice 5's `TestVersions` end-to-end test (the hooks add up to 6 min per step), and the web checks → PASS → commit `feat(panel): diagnostics before and after every rollout step`.

---

### Task 16: Slice 6 end-to-end

**Start:** after Tasks 1–12; the Task-14 assertion of step 4 runs when Task 14 is merged (skipped with a message naming it otherwise) · **Model:** opus

**Files:** Create `test/e2e/insights_test.go` (tag `e2e`); modify `test/e2e/helpers.go` (extract the setup of steps 1–3 of `TestPanelToNodeFakeTLS` into a helper without changing that test), `docs/testing/e2e.md` (what the new test covers, that it needs Telegram reachable as slice 2's e2e does, and its duration).

**Requirements:** one test on the existing harness (panel process, agent container, edge and telemt, all on the Docker host network; Telegram's datacenters reachable, as in slice 2's e2e, since slice 2's gate needs one). The panel reaches the node from `127.0.0.1`, which becomes its probe source; the test's own clients therefore dial from `127.0.0.3` (`net.Dialer.LocalAddr`, then `probe.Handshake` on the connection), so that the exemption of Task 14 never hides them.
1. Panel started with `POSTERN_GEOIP_BASE_URL=http://127.0.0.1:1/` (no download can replace the test database); node; a TLS listener on 127.0.0.1 with `link_host_override` = 127.0.0.1 (so panel probes and page links reach it); a fake-TLS proxy serving (helper); `GetNode` shows `panel_addrs` `[127.0.0.1]`.
2. GeoIP: a database written with `geoiptest` (`127.0.0.0/8` → `ZZ`, `203.0.113.0/24` → `DE`) uploaded through `PUT /api/geoip`; `GetGeoIP` shows it; policy `full`; the node's `data/geoip/<sha256>.mmdb` appears (the test shares the node's directory).
3. Traffic: several fake-TLS handshakes from `127.0.0.3`; within 3 min `ProxySeries` (1 h) shows `conns_new` and `devices` ≥ 1, `NodeSeries` a minute with memory and traffic, `Countries` (proxy, 1 h) `ZZ` with `ips_peak` ≥ 1, `ListIpSightings` `127.0.0.3` with `ZZ`.
4. Probes (policy still `full`): `ProbeNow` → L2 passes; `ProbeHistory` has the row. With Task 14 merged (capability `probe-sources`): the IP history of the following minutes lists `127.0.0.3` and never `127.0.0.1`.
5. The failure class and its fix: the proxy is moved (slice 2's `UpdateProxy`) to a new chain whose only member is socks5 `192.0.2.1:1080`; the edit records a before-run; within 3 min `egress.dc` and `e2e.l2` fail on the node and `ProbeNow` reports "no datacenter answered through the proxy (L1 ok)"; `ApplyFix(change_egress)` back to the old chain, offered from that run, heals it (`e2e.l2` ok, `ProbeNow` ok) and a before/after pair is recorded.
6. Catch-up (§5.8): the panel is stopped for at least 2 min while a client keeps making handshakes every 10 s; after the restart (same data), the gap's minutes, country rows and member hours appear, each minute exactly once (the gap's `conns_new` sum equals the handshakes made; no country row doubled).
7. Policy `countries`: the IP history is empty at once; the panel's database file, its `-wal` and its backups directory hold no `127.0.0.3` (after the checkpoint); `Countries` keeps counting; policy `off`: the country tables are emptied and no new country row comes; back to `countries`.
8. Diagnostics: a node run ends `done` with `host.docker`, `ingress.bound`, `engine.container`, `engine.ready`, `e2e.l1`, `e2e.l2`, `panel.connection` ok. Pause the engine container with the Docker API: the reconciler leaves it (no new generation while paused), and within 3 min the problem feed lists `engine.container` ("paused") of the proxy; unpause → it goes within 2 min. `ApplyFix(recreate_instance)` → a new instance generation serves, an `after_change` run is recorded without regression, the audit log has `diagnostics.fix`.
9. Public page: enabled for `proxies.example.test` with a body holding `<script>`, a `javascript:` link, `[x](javascript&colon;alert(1))` and an image, and the proxy as an item → `GET /` with that `Host` is 200 with `X-Robots-Tag: noindex, nofollow, noarchive`, the `tg://` link of the proxy and its QR, none of the body's script, links or image; `/robots.txt` disallows; `/api/postern.panel.v1.HealthService/Check` on that host is 404 while it is 200 on `127.0.0.1`; the paused proxy, with `mark`, shows its name and "unavailable" and no `tg://`, no `t.me` and no secret on the very next request; with `hide` it is gone.
10. The existing log check finds no secret of the run (the GeoIP upload, the public page and the diagnostics included).

**Steps:** write test → `bash scripts/wsl 'bash scripts/e2e.sh'` → iterate until PASS (≤ 20 min) → commit `test(e2e): statistics, countries, probes, diagnostics and the public page`.

---

### Task 17: Diagnostics reference and the manual acceptance checklist

**Start:** after Task 16 · **Model:** sonnet

**Files:** Create `docs/diagnostics.md` and `docs/diagnostics.ru.md` (for operators: every check with what ok/warn/fail mean and what to do, every fix with what it changes, before/after runs, the IP policies, retention and what is deleted when, the probes, their exemption and that they reveal the fleet to anyone who can observe the panel's traffic, the GeoIP source and attribution, the env switches `POSTERN_PUBLIC_PAGE` and `POSTERN_GEOIP_BASE_URL`), `docs/testing/acceptance-slice-6.md` (placeholders `<SERVER_IP>`, `<PANEL_IP>`, `<PORT>`, `<PUBLIC_HOST>`; no real address or domain).

**Requirements:** the checklist, step by step on the test servers with real Telegram clients, each step with its expected result:
- statistics: a known download through the proxy shows up in the traffic chart within 2 min; unique IPs with two clients; node load plausible against `top`; top proxies; a panel restart with traffic flowing loses no minute.
- countries and IP policy: the real DB-IP database downloads; clients from two networks show two countries; `full` lists their addresses; switching to `countries` empties the list, and `grep -c` for a client address over the panel database, its `-wal` and its backups, and over the node's `data/stats.db` and its `-wal`, finds nothing; `off` empties the country tables.
- diagnostics: a full run on a healthy node; pausing the engine container → `engine.container` fails → unpause, then `recreate_instance` on a healthy proxy; dropping the DC addresses on the egress (`iptables`) → `egress.dc` fails → `change_egress` to another chain heals it, with a before/after pair; clock moved by 40 s with NTP off → `host.clock` fails (restore NTP afterwards); UDP/53 blocked with `dns_mode system` → `host.dns` fails → `set_dns_mode_doh` heals it; `roll_edge` starts a new edge generation without dropping a held connection; an egress edit waits for its before-run.
- probes: the panel's probes from outside pass; a proxy with `limit_devices = 1` and a client connected is still probed fine and the client stays connected (Task 14); a blocked port makes the proxy "down" after two probes and the public page marks it without its link.
- public page: behind Cloudflare on a test subdomain of the owner's test zone (do not clean the zone), `curl -sI` shows the headers, `robots.txt` disallows, the page reads without JavaScript, "Connect" opens Telegram on a phone and connects, a paused proxy is marked (no link) or hidden at once, `/api/...` and `/setup` on the public host are 404, the admin works on its own address, and a public host equal to the admin's name is refused.
- the problem feed and the journal show each of the above with its fix and audit entry.

The controller runs the checklist on the test servers after this task (not CI) and puts the results into the final report.

**Steps:** write → review against the implemented UI and API → commit `docs: diagnostics reference and the slice 6 acceptance checklist`.
