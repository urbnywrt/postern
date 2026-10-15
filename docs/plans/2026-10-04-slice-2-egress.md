# Postern Slice 2 (Egress) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Proxies reach Telegram through configurable egress chains — VLESS/VMess/Trojan/SS (URIs and subscriptions via Xray), WARP (Xray WireGuard), Psiphon (warp-plus), external SOCKS5/HTTP, direct with interface binding — with health checks that exchange real MTProto data, automatic failover, per-scope chains, middle-proxy NAT handling, and DNS that works on nodes where UDP/53 is blocked.

**Architecture:** Protocol clients run as `postern-egr-*` containers (stock alpine + verified Xray / warp-plus binaries) exposing one SOCKS5 port per egress member on `127.0.0.1`. The edge (slice 1, `internal/edge/egress`) dials members and fails over; this slice makes its checks exchange MTProto data with the datacenters, gives the edge a DoH-backed DNS forwarder for every container of the node, adds the providers, the agent-side lifecycle (render, run, health-gate, subscription refresh, middle-proxy addresses), exit-IP-driven ME updates, and panel management of egresses and chains.

**Tech Stack:** Go 1.27, Xray-core release binaries, warp-plus release binaries, `golang.org/x/net/dns/dnsmessage`, existing slice-1 packages.

**Spec:** `docs/design/2026-10-04-postern-design.md` §5.5 (ME/NAT), §5.6 (egress), §5.7 (diagnostics, synthetic probe L1/L2), §7 (artifacts).

## Findings carried into this slice (from slices 0–1)

- **F1 — checks must exchange data.** Xray's SOCKS inbound acknowledges a CONNECT before its outbound has connected, so "CONNECT succeeded" says nothing about an Xray member. A member check must get an answer from a datacenter: an obfuscated2 `req_pq_multi` → `resPQ` exchange (the spec's L2 transport). → Task 2, Task 4.
- **F2 — DNS on UDP/53-blocked nodes.** Production nodes block UDP/53. telemt resolves its TLS front and mask host with the system resolver (not through SOCKS), Xray resolves server names, the agent fetches subscriptions and middle-proxy lists. → Task 3: an edge DNS forwarder on `127.0.0.2:53` backed by DoH, a bind-mounted `resolv.conf` for engine and egress containers, the same resolver inside the edge and the agent.
- **F3 — telemt does not tag middle-proxy traffic.** telemt 3.5.13 tags its TLS-front fetch with scope `fetch` and its middle-proxy connections with nothing, so scope `me` never reaches the edge. → Task 6: the edge classifies a CONNECT as scope `me` by destination (middle-proxy addresses from `getProxyConfig`, pushed by the agent).
- **F4 — warp-plus is stale** (v1.2.6, June 2025). → WARP runs on Xray's WireGuard outbound with a node-side WARP registration (Task 5); warp-plus is used for Psiphon only, verified on a real server in Task 8 and marked experimental in the UI if it fails there.
- **F5 — edge egress minors deferred from slice 1 Task 9** (listed in Task 4).

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply verbatim (module, WSL runner, commits without trailers, hygiene, runner image digest, labels, port ranges, timeouts).
- Egress member SOCKS ports come from the range 35000–39999.
- Xray default version `v26.3.27`; artifacts `Xray-linux-64.zip` (amd64) and `Xray-linux-arm64-v8a.zip` (arm64); checksum source: the release `.dgst` file (`SHA2-256=` line); URL `https://github.com/XTLS/Xray-core/releases/download/<tag>/<file>`; binary name inside the zip: `xray`.
- warp-plus default version `v1.2.6`; artifacts `warp-plus_linux-amd64.zip`, `warp-plus_linux-arm64.zip`; checksum from `.dgst`; binary name inside the zip: `warp-plus`. Used for PSIPHON only. Flags: `-b 127.0.0.1:<port>`, `--cache-dir <dir>`, `--cfon --country <CC>`.
- Health defaults: interval 30 s, timeout 4 s, fail threshold 3, recover threshold 2, DC targets `149.154.175.50:443` (DC1), `149.154.167.51:443` (DC2), `149.154.175.100:443` (DC3), `149.154.167.91:443` (DC4), `91.108.56.130:443` (DC5); echo URLs `https://api.ipify.org`, `https://ifconfig.me/ip`, `https://icanhazip.com`. A member is `down` only from DC failures, and a DC check passes only on a valid `resPQ` (F1).
- MTProto constants: `req_pq_multi#be7e8ef1`, `resPQ#05162463`; transport tags `0xeeeeeeee` (intermediate, direct DC pings) and `0xdddddddd` (padded intermediate, through a proxy secret); obfuscated2 header 64 bytes, forbidden first-4-byte values `HEAD`, `POST`, `GET `, `OPTI`, `0x02010316`, `0xdddddddd`, `0xeeeeeeee`, first byte `0xef` forbidden, bytes 4..8 not all zero.
- DNS: forwarder address `127.0.0.2:53` (UDP and TCP); DoH endpoints by IP literal, no bootstrap lookup: `https://1.1.1.1/dns-query`, `https://1.0.0.1/dns-query`, `https://8.8.8.8/dns-query`, `https://8.8.4.4/dns-query` (RFC 8484, `application/dns-message`, POST); per-query timeout 3 s, at most 2 endpoints tried per query; cache ≤ 4096 entries, TTL capped at 300 s, negative answers cached 30 s; fallback: the host's own nameservers from `/etc/resolv.conf` (anything but `127.0.0.2`) over UDP then TCP. Node setting `dns_mode`: `doh` (default) or `system` (no forwarder, containers keep the host's resolver).
- Egress params are secrets at rest in the panel (`params_enc`, sealed with AAD `egress:<id>`) and never logged.
- Subscription fetch: User-Agent `Mozilla/5.0`, timeout 15 s, body ≤ 1 MiB, refresh every 6 h and on demand; first try direct, then through each healthy member of the node's default chain.
- Middle-proxy list: `https://core.telegram.org/getProxyConfig` and `https://core.telegram.org/getProxyConfigV6`, fetched by the agent every 6 h (and at start), timeout 15 s, body ≤ 256 KiB, lines `proxy_for <dc> <ip>:<port>;`; the last good list is kept on disk (`data/state/me-addrs.json`) and used until a new one parses.

---

### Task 1: Share-URI and subscription parser

**Model:** sonnet

**Files:** Create `internal/egressuri/uri.go`, `internal/egressuri/subscription.go`, `internal/egressuri/uri_test.go`, `internal/egressuri/fuzz_test.go`

**Interfaces (Produces):**

```go
package egressuri
type Server struct {
  Protocol string            // vless | vmess | trojan | shadowsocks
  Name     string            // fragment (#name), URL-decoded
  Address  string; Port uint16
  ID       string            // vless/vmess uuid
  Password string            // trojan / shadowsocks
  Method   string            // shadowsocks cipher
  Flow     string            // vless flow, e.g. xtls-rprx-vision
  Network  string            // tcp | ws | grpc | xhttp | httpupgrade
  Security string            // none | tls | reality
  SNI, Fingerprint, PublicKey, ShortID, SpiderX, Path, Host, ServiceName, Mode, ALPN string
  Extra    string            // xhttp "extra" JSON, raw
  AllowInsecure bool
}
func Parse(uri string) (*Server, error)                 // one URI
func ParseSubscription(body []byte) ([]*Server, []error) // base64 (std/url, padded or not) or plain text list; skips blank/comment lines; per-line errors returned, valid servers kept
func (s *Server) Key() string                            // stable member key: first 12 hex digits of sha256(protocol|address|port|id), address folded (ASCII lower case, IPs canonical), no password (keys are logged)
```

**Requirements:** `vless://uuid@host:port?type=&security=&sni=&fp=&pbk=&sid=&spx=&flow=&path=&host=&serviceName=&mode=&alpn=&extra=#name` (also accept `peer`/`servername` as SNI aliases, `headerType` ignored); `vmess://base64(json)` with fields `add, port, id, net, path, host, tls, sni, fp, alpn, ps, scy` (`aid` must be 0 or absent, else error "alterId not supported"); `trojan://password@host:port?sni=&type=&path=&host=&security=#name` (default security tls); `ss://` SIP002 (`ss://base64(method:password)@host:port#name` and `ss://method:password@host:port`, plugin param → error "plugins not supported"). IPv6 literals in brackets. Ports default 443 when absent for vless/trojan, required for ss. Unknown scheme → error. Errors never echo the password, UUID or the whole URI (they name the field and the scheme only).

**Tests:** table tests per scheme with documentation addresses; reality+vision VLESS; ws with host; grpc serviceName; xhttp with extra; vmess JSON variants; ss both forms; subscription base64 with mixed valid/invalid lines; plain list; an error-message test proving no credential appears in any error; fuzz `FuzzParse`, `FuzzParseSubscription` (no panic).

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/egressuri/... && go test -run=^$ -fuzz=^FuzzParse$ -fuzztime=15s ./internal/egressuri/ && go test -run=^$ -fuzz=^FuzzParseSubscription$ -fuzztime=15s ./internal/egressuri/'` (one anchored run per target: an unanchored `-fuzz=FuzzParse` matches both targets, and Go then refuses to fuzz) → PASS → commit `feat(egress): share-URI and subscription parser`.

---

### Task 2: MTProto L2 probe and datacenter ping

**Model:** opus

**Files:** Create `internal/probe/obfuscated2.go`, `internal/probe/mtproto.go`, `internal/probe/l2.go`, tests (`obfuscated2_test.go`, `mtproto_test.go`, `l2_test.go`, `fakedc_test.go` — an in-process fake datacenter/proxy), extend `internal/probe/integration_test.go` (tag `integration`; online parts only when `POSTERN_E2E_ONLINE=1`). Uses `probe.Handshake` from slice 1 Task 23.

**Interfaces (Produces):**

```go
package probe
// DCPing runs obfuscated2 (no secret, tag 0xeeeeeeee) + req_pq_multi over conn,
// which is already connected to a datacenter (directly or through an egress member),
// and returns when a resPQ with the same nonce arrives. It sets and clears deadlines on conn.
func DCPing(ctx context.Context, conn net.Conn) error
// L2 dials addr, does the fake-TLS handshake with sni and secret (as FakeTLS), then
// speaks obfuscated2 with the secret (tag 0xdddddddd, dc) inside TLS application-data
// records and returns when the datacenter's resPQ comes back through the proxy.
func L2(ctx context.Context, addr, sni string, secret []byte, dc int16, opt Options) error
```

**Requirements:** obfuscated2 per Global Constraints: 64-byte header, `init[56:60]` tag, `init[60:62]` dc (int16 LE), keys `encKey=init[8:40] encIV=init[40:56]`, decrypt keys from `reverse(init[8:56])` (`[0:32]` key, `[32:48]` IV); with a secret both keys become `sha256(key || secret)`; AES-256-CTR; the header is sent as `init[0:56] || enc(init)[56:64]`. Padded intermediate frames: 4-byte LE length (payload + 0–15 random padding bytes), payload multiple of 4. `req_pq_multi`: auth_key_id 0, message_id = unix time << 32 rounded down to a multiple of 4, length 20, constructor + 16-byte random nonce. Response checks: auth_key_id 0, constructor `resPQ`, nonce equal; anything else (or a TLS alert, a close, a timeout) is an error that says which. Inside fake TLS: after the handshake send `14 03 03 00 01 01`, then `17 03 03 <len BE>` records of at most 16 384 payload bytes; read the server's `17 03 03` records and feed their payloads to the decryptor; any other record type is an error. Every read bounded (frame length ≤ 64 KiB). No secret, key or nonce in errors or logs.

**Tests:** derivation vectors (fixed header + secret → keys; cross-checked against an independent computation written in the test with `crypto/aes` + `crypto/sha256` step by step); header constraints over 10 000 generated headers; fake DC (server side of obfuscated2 + resPQ responder) for DCPing; fake fake-TLS proxy (server side of the fake-TLS handshake as slice-1 tests do + obfuscated2 with secret) for L2; wrong nonce, wrong constructor, short frame, oversized frame, TLS alert, timeout. Integration (`integration` tag): L2 through a real telemt container from the slice-1 harness to a real DC when `POSTERN_E2E_ONLINE=1`; DCPing directly to DC2 when online.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'go test ./internal/probe/...'` (+ `-tags integration` with `POSTERN_E2E_ONLINE=1` once) → PASS → commit `feat(probe): MTProto L2 probe and datacenter ping`.

---

### Task 3: DoH client and the edge DNS forwarder

**Model:** opus

**Files:** Create `internal/doh/doh.go` (RFC 8484 client with endpoint failover; `Exchange`, `LookupIP`, `LookupTXT`), `internal/doh/doh_test.go`, `internal/edge/dns/forwarder.go` (UDP+TCP server on `127.0.0.2:53`, cache, fallback), `internal/edge/dns/forwarder_test.go`; modify `proto/postern/edge/v1/edge.proto` (`message Dns { bool enabled = 1; repeated string doh_urls = 2; repeated string fallback = 3; }` as `Dns dns = 12;` in `EdgeConfig` — field 11 stays reserved for slice 3's `certs`) + regen; `proto/postern/node/v1/node.proto` (`string dns_mode = 6;` in `NodeSettings`) + regen; `internal/edge` wiring (start/stop the forwarder with the config, the edge's own resolver for direct members and echo URLs uses it when enabled); `internal/node/reconcile` (EdgeConfig.dns from `dns_mode`; write `data/run/resolv.conf` = `nameserver 127.0.0.2\noptions timeout:2 attempts:2\n` 0644 and bind-mount it read-only at `/etc/resolv.conf` into engine and egress containers when `dns_mode=doh`); `internal/node/agent` (the agent's own HTTP clients use a resolver pointed at `127.0.0.2:53` once the edge reports the forwarder up, else the system's); `internal/node/state/validate.go` (`dns_mode` ∈ {"", "doh", "system"}).

**Interfaces (Produces):**

```go
package doh
type Client struct{ /* endpoints, http client with 3 s timeouts, no proxy from env */ }
func New(endpoints []string) *Client
func (c *Client) Exchange(ctx context.Context, query []byte) ([]byte, error) // wire format in/out; ID zeroed upstream, restored
func (c *Client) LookupIP(ctx context.Context, name string) ([]netip.Addr, error) // A + AAAA
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, error)
```

**Requirements:** Global Constraints (DNS). The forwarder accepts only well-formed queries with exactly one question (others → FORMERR), never recurses itself, answers SERVFAIL when DoH and fallback both fail, truncates UDP answers above the client's EDNS0 size (512 without EDNS0) by setting TC and dropping records so the client retries over TCP, limits TCP to 16 concurrent connections with 10 s idle, and caps in-flight upstream queries at 256 (excess → SERVFAIL). DoH HTTP client: TLS 1.2+, verifies the IP-literal certificates, ignores proxy environment variables. Binding `127.0.0.2:53` must work in the edge container (it already holds `CAP_NET_BIND_SERVICE` for 443; verify). Check with real Docker that a bind mount at `/etc/resolv.conf` is honoured for host-network containers (Docker refuses `--dns` with host networking) and record the result in the report.

**Tests:** doh against an `httptest` TLS server speaking RFC 8484 (failover to the second endpoint, ID restore, oversize body refused, timeout); forwarder: UDP and TCP round trip, cache hit (upstream called once), TTL cap, negative caching, truncation, FORMERR for two questions, SERVFAIL path, fallback to a local UDP stub; reconcile: resolv.conf written and mounted only in `doh` mode; integration (`integration`): a real engine container resolves a name through the forwarder with UDP/53 to the outside blocked by pointing fallback at nothing.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/doh/... ./internal/edge/... ./internal/node/...'` → PASS → commit `feat(edge): DoH-backed DNS forwarder for node containers`.

---

### Task 4: Edge egress checks with data exchange and slice-1 egress minors

**Model:** opus

**Files:** Modify `internal/edge/egress/health.go`, `member.go`, `member_linux.go`, `router.go`, `socksports.go` (+ tests); edge container spec in `internal/node/reconcile` (capabilities).

**Requirements:**
- A DC check dials the DC through the member and runs `probe.DCPing` on the connection (F1); latency is the time to `resPQ`. A member is up only on a valid `resPQ`.
- Direct members and echo URLs resolve names with the edge's DNS forwarder when enabled (Task 3), else the system resolver.
- `bind_ip` and `bind_device` apply to the dial of every member kind (direct, socks5, http). `bind_device` needs `CAP_NET_RAW`: add it to the edge container only when some member uses `bind_device`.
- A chain dial has an overall budget of 2 × timeout across members; a policy refusal (blacklist, refused destination) short-circuits the chain instead of trying the next member.
- The SOCKS server answers with the member's SOCKS5 reply code when a socks5 member refuses (pass-through incl. `0x02`), else `0x01`/`0x04`/`0x05` by cause.
- Health bookkeeping: the status is recorded before the echo phase; a successful probe clears the previous error; `RunHealth` refuses a second concurrent call.

**Tests:** fake DC behind a fake SOCKS member that acks CONNECT early and then closes (the Xray failure mode) → member goes down; a member that answers resPQ → up with latency; DNS resolver injection; bind options for socks5/http members (Linux test with `SO_BINDTODEVICE` skipped without the capability); budget; short-circuit; reply-code pass-through; second `RunHealth` refused.

**Steps:** tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/edge/...'` → PASS → commit `feat(edge): egress checks exchange MTProto data with the datacenters`.

---

### Task 5: Xray (URI, subscription, WARP) and warp-plus (Psiphon) provider drivers

**Model:** opus

**Files:** Create `internal/providers/provider.go` (interface), `internal/providers/xray/xray.go`, `internal/providers/xray/config.go`, `internal/providers/xray/xray_test.go`, `internal/providers/xray/testdata/*.json`, `internal/providers/warp/register.go` (WARP account registration), `internal/providers/warp/register_test.go`, `internal/providers/warpplus/warpplus.go`, `internal/providers/warpplus/warpplus_test.go`, `internal/providers/integration_test.go` (tag `integration`); modify `internal/artifacts/store.go` to extract `.zip` archives (add `archive/zip` path; keep tar.gz).

**Interfaces (Produces):**

```go
package providers
type Member struct { Key string; Port uint16; Server *egressuri.Server; WARP *warp.Account }
type Instance struct {
  EgressID string; Generation uint64; Kind nodev1.EgressKind
  Members []Member              // xray: one per server (XRAY_URI one, SUBSCRIPTION many, WARP one with WARP set); psiphon: exactly one (Server nil)
  Country string                // psiphon
  InstanceDir, BinaryPath, RunnerImage, ResolvConf string // ResolvConf "" = no mount
}
type Driver interface {
  Kinds() []nodev1.EgressKind
  ArtifactFile(arch string) (string, error)
  BinaryName() string
  Render(in Instance) (map[string][]byte, error)
  Container(in Instance) dockerapi.ContainerSpec
  Ready(ctx context.Context, in Instance) error   // every member port accepts TCP and answers the SOCKS5 greeting
}

package warp
type Account struct { PrivateKey, PeerPublicKey, Endpoint string; AddrV4, AddrV6 string; Reserved [3]byte; ID, Token string }
func Register(ctx context.Context, hc *http.Client) (*Account, error)   // stored by the agent at data/instances/egr-<id>/warp-account.json (0600), reused
```

**Requirements:** Xray config: `log.loglevel = "warning"`; per member an inbound `{tag:"in-<key>", listen:"127.0.0.1", port, protocol:"socks", settings:{auth:"noauth", udp:false}}`, an outbound `out-<key>` built from the Server (vless `vnext`/`users{id,encryption:"none",flow}`, vmess `users{id,security:"auto"}`, trojan `servers{address,port,password}`, shadowsocks `servers{address,port,method,password}`) with `streamSettings` (network-specific settings; `security` tls → `tlsSettings{serverName,fingerprint,alpn,allowInsecure}`, reality → `realitySettings{serverName,fingerprint,publicKey,shortId,spiderX}`), or for WARP a `wireguard` outbound (`secretKey`, `address` [v4/32, v6/128], `peers[{publicKey, endpoint, allowedIPs:["0.0.0.0/0","::/0"]}]`, `reserved`, `mtu: 1280`); routing rules `inboundTag:["in-<key>"] → outboundTag:"out-<key>"`, no geoip/geosite rules (no data files needed). Check every field name against the Xray docs of the pinned version; golden JSON per protocol. WARP registration: the endpoint, headers and JSON fields as used by the current release of ViRb3/wgcf (verify at implementation time and cite the source version in a comment); X25519 key pair generated locally; HTTP timeout 15 s; the account file is 0600 and never logged; registration happens only when no account file exists. Containers: user 65534, read-only, cap_drop ALL, binds binary + instance dir (+ `ResolvConf` read-only at `/etc/resolv.conf` when set), Xray entrypoint `/opt/engine/xray run -c /etc/egress/config.json`; warp-plus entrypoint `/opt/engine/warp-plus -b 127.0.0.1:<port> --cache-dir /etc/egress/cache --cfon --country <CC>`, instance dir bind rw. Artifact store gains zip extraction (single named binary, path traversal rejected, size bounded) with tests.

**Tests:** golden configs (vless reality vision, vless ws tls, trojan, vmess grpc, ss, warp wireguard); container specs; zip extraction good/bad; WARP registration against an `httptest` server (request shape, key handling, response parsing, error without secrets). Integration: run real Xray (pinned) with a member pointing at a local Xray VLESS **server** container (also from the pinned binary with a generated server config, no TLS) → SOCKS CONNECT through the member to a local TCP echo server succeeds; with `POSTERN_E2E_ONLINE=1` additionally a WARP member registers and `probe.DCPing` through it succeeds.

**Steps:** tests → FAIL → implement → PASS (unit + integration) → commit `feat(egress): Xray, WARP and Psiphon provider drivers`.

---

### Task 6: Agent egress lifecycle, chain gating, middle-proxy routing and ME NAT

**Model:** opus

**Files:** Modify `internal/node/state/validate.go` (allow XRAY_URI, XRAY_SUBSCRIPTION, WARP, PSIPHON; validate params JSON per kind), `internal/node/reconcile/` (new files `egress.go`, `subscriptions.go`, `natip.go`, `meaddrs.go`; modify `edgecfg.go`, `instances.go`, `reconciler.go`), `proto/postern/edge/v1/edge.proto` (`repeated string me_addrs = 13;` in `EdgeConfig`) + regen, `internal/edge/egress/router.go` (scope `me` by destination), tests.

**Requirements:**
- Egress params JSON per kind: `DIRECT {"interface":"","bind_ip":""}`, `SOCKS5`/`HTTP {"addr":"host:port","username":"","password":""}`, `XRAY_URI {"uri":"..."}`, `XRAY_SUBSCRIPTION {"url":"...","select":"all"|"name:<substr>"}`, `WARP {}`, `PSIPHON {"country":"DE"}`.
- Provider instances: one per egress that is referenced by any chain used by an enabled proxy or by the node default chain; instance hash over rendered files; blue-green like engines (new gen ready → edge SetConfig switches member addrs → old gen drained after 2 min).
- Subscriptions are fetched by the agent (rules in Global Constraints), cached at `data/instances/egr-<id>/subscription.txt`, parsed with `egressuri`, filtered by `select`; members keyed by `Server.Key()` so ports stay stable across refreshes.
- EdgeConfig chains: member per server/instance in chain order (subscription members expand in subscription order), kinds `socks5` with `addr 127.0.0.1:<port>` for providers, `direct`/`socks5`/`http` for built-ins.
- Middle-proxy routing (F3): the agent keeps the middle-proxy address list (Global Constraints) and sends it as `EdgeConfig.me_addrs`; the edge treats a CONNECT with no scope whose destination IP is in `me_addrs` as scope `me`. An explicit scope from the engine wins.
- Engine blue-green readiness additionally requires: `probe.DCPing` to one DC through the new instance's SOCKS port (via the edge), and, when DCs are reachable that way, `probe.L2` through the edge's test listener to the new instance; when `use_middle_proxy`, HTTPS GET `https://core.telegram.org/getProxySecret` through the same SOCKS port returns 200.
- ME NAT: for proxies with `use_middle_proxy` and no `nat_ip`, `middle_proxy_nat_ip` = exit IP of the first `up` member of the chain that middle-proxy traffic takes (the proxy's `me` scope chain when set, else its default chain), from edge health; a change of that IP triggers engine blue-green; unknown exit IP → no NAT line.
- Events: `egress_member_down`, `egress_member_up`, `egress_failover` (active member changed), `subscription_refreshed`, `subscription_failed`, `me_addrs_refreshed`, `me_addrs_failed`.

**Tests:** validation per kind; reconcile with fakes: chain with XRAY_SUBSCRIPTION expands members with stable ports across refresh; provider blue-green; engine gate fails when DCPing through the instance fails (fake edge dial); L2 gate; exit IP change triggers engine regeneration; `me_addrs` parsing (IPv4 and IPv6 configs, malformed lines skipped, last good list kept) and the edge's destination classification; events emitted.

**Steps:** proto + regen → tests → FAIL → implement → `bash scripts/wsl 'bash scripts/race.sh ./internal/node/... ./internal/edge/...'` → PASS → commit `feat(node): egress providers lifecycle, chain gating, middle-proxy routing and ME NAT`.

---

### Task 7: Panel egress management and catalog

**Model:** opus

**Files:** Create `proto/postern/panel/v1/egress.proto` (+ regen Go and TS), `internal/panel/egress/service.go`, tests; modify `internal/panel/proxies/statebuilder.go` (egresses, chains, scope chains, `dns_mode`, artifacts for providers), `internal/panel/proxies/catalog.go` (Xray, warp-plus pinned versions with `.dgst` verification), `internal/panel/store` (repositories for egresses/egress_chains if not present), web pages `web/src/pages/Egress.tsx`, `web/src/components/{EgressForm,ChainEditor,EgressHealth}.tsx`, proxy form gains chain + scope chains, node detail gains default chain, DNS mode and the health table; i18n keys RU/EN.

**Requirements:** `EgressService` CRUD for egresses (kinds and params per Task 6; secrets sealed; responses never include passwords/UUIDs/private keys in full — show masked), `ChainService` CRUD (ordered members, node scope or global), `SetNodeDefaultChain`, `ValidateEgress(egress)` (panel-side parse/validation only; live checks come from node health reports — an on-demand node-side test is deferred to slice 6 diagnostics). Health view from `StateReport.egress` (status, latency, exit IP, last check). Catalog downloads Xray/warp-plus archives, verifies `.dgst` SHA2-256, uploads to nodes like telemt. PSIPHON is labelled experimental in the UI until Task 8 confirms it on a real server.

**Tests:** service validation, sealing (DB contains no plaintext UUID/password), state builder golden with chains, scope chains and dns_mode, catalog `.dgst` parsing, UI tests for ChainEditor ordering and EgressForm per-kind fields.

**Steps:** tests → FAIL → implement → PASS → commit `feat(panel): egress profiles, chains and provider catalog`.

---

### Task 8: Egress end-to-end and real-server check

**Model:** opus

**Files:** Extend `test/e2e/` with `egress_test.go` (tag `e2e`); `docs/testing/smoke-remote.md` (egress section).

**Requirements:** Using the slice-1 harness: start a local "remote" VLESS server container (pinned Xray, no TLS) and a second one; create an XRAY_URI egress for each and a chain [A, B]; create a proxy using the chain; wait SERVING; L1 probe OK; stop server A → within `fail_threshold × interval` (configure 5 s interval in the test via node settings) the edge marks A down and new SOCKS CONNECTs go through B (assert via edge Snapshot health + a CONNECT through the proxy's SOCKS port reaching a local echo server whose access shows B's container IP). With `POSTERN_E2E_ONLINE=1`: L2 through the proxy to a real DC over the chain, a WARP egress member up, DCPing through it. The real-server check (controller, not CI): a VLESS+Reality server on the second test server as the egress of a proxy on the first, a WARP egress, a PSIPHON egress (experimental flag removed only if it passes), with UDP/53 blocked on the node (`iptables -A OUTPUT -p udp --dport 53 -j DROP`, removed afterwards) — proxies keep serving and L2 passes.

**Steps:** write test → iterate until PASS → commit `test(e2e): egress failover and L2`.
