# Statistics, privacy and diagnostics

[Русская версия](diagnostics.ru.md)

For the operator of a Postern panel: what the statistics keep and for how long, what happens
to client addresses, what every check says and what to do about it, what every one-click fix
changes, how the probes work, and how the public page is switched off. The manual test of all
this on real servers is [acceptance-slice-6.md](testing/acceptance-slice-6.md).

## Where things are

| In the panel | What it has |
|---|---|
| Overview | node load, traffic since midnight, top proxies and countries (24 h), the **problem feed** |
| A proxy | traffic, connections and unique IPs charts, countries, IP history (policy `full` only), probes and availability, **Check this proxy** |
| A node | load, traffic, unique IPs, edge refusals, egress history, **Run full check**, run history, light checks |
| Journal | events (what happened to nodes and proxies) and the audit log (what admins did), newest first, with filters |
| Settings | statistics and privacy (retention, IP policy, probes), the country database, storage, the public page |

Every chart has the ranges 1 h, 24 h, 7 d, 30 d, 90 d and 1 y; minutes are used while the range
fits the minutes retention, then hours, then days. "Unique IPs" is the number of distinct client
addresses seen in a minute; a chart point over a longer period shows the peak, and the label
says "Unique IPs (peak)". A node's figure is the sum over its proxies.

## Retention: what is kept and what is deleted when

| Data | Kept | Setting (range) |
|---|---|---|
| Minutes (per proxy, per node, per country, egress members) | 48 h | minutes, 6 to 168 hours |
| Hours (per proxy, per node) | 90 d | hours, 7 to 730 days |
| Hours per country, hours of egress members | 30 d | fixed |
| Days | for good | none |
| Where each client address was seen (`ip_sightings`) | 7 d | IP history, 1 to 30 days; policy `full` only |
| Probes | 7 d | fixed |
| Full-check runs | 30 d, at most 100 a node | fixed |

All of it is in **Settings, Statistics and privacy**. Settings, Storage shows the real size of
the database and its tables. A panel with 10 proxies on 3 nodes needs about 30 MB; 100 proxies
on 20 nodes with 100 egress members, about 300 MB and 17 MB a year more.

The nodes keep their own buffer of records in `data/stats.db` (7 days, at most 1,000,000 records
and 256 MiB of payload; over the limit the oldest statistics lose their client addresses first,
then the oldest records go). It lets the panel read what it missed during a disconnection.
Client addresses in it are scrubbed after the IP history setting.

## The IP policy

Settings, Statistics and privacy, **IP policy**. The addresses of users in countries that block
Telegram are sensitive data, so the default keeps no address at all.

| Policy | What the nodes send | What the panel keeps |
|---|---|---|
| `full` | where each address was seen, with its country, and the country totals | IP history (first and last visit, country, bytes) and the country totals |
| `countries` (default) | country totals only: per minute, the number of addresses and the bytes of each country | country totals; no address anywhere |
| `off` | nothing about addresses | nothing (device counts stay: they are numbers) |

The country of an address is looked up **on the node**, in the database the panel sends it, so
under `countries` no client address leaves the node.

Changing the policy asks for confirmation when it deletes something, and deletes at once:

- leaving `full` deletes the IP history from the panel in the same transaction that stores the
  policy, and every node scrubs its buffer and the minute it has open before it sends anything
  else;
- `off` also deletes every statistic by country.

Both databases (the panel's and the node's) overwrite what they delete (`secure_delete`) and
empty the write-ahead log after it, and the panel's backups are made without the IP history, so a
client address does not stay in a free page, in `postern.db-wal` or in `backups/`. Diagnostic
text passes a redactor that replaces every IP address that is not the node's own service
address, a public address of the node, a datacenter, a DoH endpoint or an egress member, with
`<ip>`, and a scrubber that takes proxy secrets, ad tags, API tokens and egress parameters out.

## The country database and its attribution

The countries come from the free **IP to Country Lite** database of [DB-IP](https://db-ip.com)
(about 8 MB, monthly, licence CC BY 4.0). It holds no address of a client. The panel downloads
`dbip-country-lite-<YYYY-MM>.mmdb.gz` when it starts and looks again every day, takes the current
month or the one before, checks the file before using it, and sends it to every node that
reports the `stats-v2` capability while the policy is `full` or `countries`.

DB-IP asks for a link back wherever its data is shown, so every view of countries has the caption
**IP Geolocation by DB-IP** linking to <https://db-ip.com>, and so has About. Country names come
from the browser (`Intl.DisplayNames`); nothing is loaded from outside.

- **Settings, Country database** shows the month, size and checksum, and can look for a newer
  file, upload one (for a panel that cannot reach `download.db-ip.com`) or turn lookups off
  (then the panel makes no request to DB-IP).
- `POSTERN_GEOIP_BASE_URL` points the panel at a mirror (a directory with the same file names).
  More in [deploy/panel/README.md](../deploy/panel/README.md#the-country-database).
- The check `panel.geoip` (below) warns when the file is older than 62 days and fails when there
  is none while the policy uses countries.

## Probes

A probe connects to a proxy the way a client does. The panel probes every enabled proxy of an
online node every **5 minutes** (Settings, "Probe every proxy every, minutes": 0 to 60, 0 turns
them off), each proxy at its own offset with a random move of up to 20 % of the interval, at most
8 at a time, 10 s each. A fake-TLS proxy gets a handshake with its secret and a question to a
Telegram datacenter through it; when that fails, a plain TLS probe tells **unreachable**,
**refused the secret** or **no datacenter answered through the proxy** (the proxy is fine, its
egress is not). A WEB proxy is probed at the HTTP/2 and decoy-site level, not with MTProto. Each
node also probes its own proxies through the edge's test listener every 10 minutes (the check
`e2e.l2`). Results are kept 7 days and drive the proxy's uptime, the problem feed and the public
page.

A proxy is **down** when its last two panel probes failed and the newer one is at most three
intervals old. Recovery is at once. Events `probe.failed` and `probe.recovered` go to the Journal.

**The probes reveal the fleet.** They come from the panel's address to every proxy's address and
port, on schedule. Anyone who can observe the traffic of the panel (its provider, its network, a
censor watching its address) sees a list of the proxies it checks. If that matters, run the panel
somewhere that is not tied to you, or set the interval to 0 (the node's own probe and the
diagnostics remain).

**The exemption.** A probe must not take the only device slot of a proxy with
`limit_devices = 1`, nor count as a client. Each edge therefore exempts the panel's probe
addresses, exactly (`/32` and `/128`, never a prefix), on public listeners only: a connection
from such an address takes no device slot, no limit and no IP counter, at most 4 of them are open
per proxy at once (the rest are ordinary clients), each is closed after 30 s, and its bytes are
still counted in the traffic. The addresses are the last IPv4 and IPv6 address each node saw the
panel connect from, plus the **Extra probe sources** of Settings (single addresses, at most 16,
for a panel behind several addresses). Settings lists what each node learned and warns when an
address is shared (private or in 100.64.0.0/10): everyone behind a shared address would be
exempt from the limits.

## Diagnostics

The node checks itself all the time: **light checks** (every 1 or 10 minutes, jittered by 10 %,
at most 16 at a time). A light check does not report a worsening on one bad run: when a run
finds a check (for a target) worse than last reported (`ok`/`skip` < `warn` < `fail`), the
node keeps the reported result and runs the check again 60 s later (or at its own turn if that
is sooner). The rerun reports the better of the two bad statuses, in its own words, if it is
still worse; otherwise nothing worse is reported. Recovery is reported at once, and so is the
first result after the node starts, except that a check that runs every minute reports a first
failure as `warn` ("failed once") and `fail` only when the next run fails too. Full checks
report what they find. The node tells the panel
when a status changes. A **full check** runs every check of a scope: `node` (everything on it) or
`proxy:<id>` (the host, the proxy's listener and engine, the members of its chain). It takes at
most 3 minutes, and one runs per node at a time. Start one with **Run full check** on a node
or **Check this proxy**; results arrive as they finish and the run is kept in the history.

Statuses: `ok`, `warn` (works, but look), `fail` (broken), `skip` (could not be checked, with the
reason). Every result has a summary, evidence (for warn and fail, plain text, scrubbed), a hint
and sometimes a fix. The checks are listed along the path **client, listener, engine, egress,
Telegram**; the first failing link is the one to repair.

### Host (node)

| Check | ok | warn | fail | What to do |
|---|---|---|---|---|
| `host.docker` | Docker answers | | no answer | `systemctl status docker` on the node |
| `host.clock` | off by 2 s or less | over 2 s | over 30 s | the median over the four DoH endpoints (needs two answers, else skip). Fix NTP (chrony, systemd-timesyncd): TLS and the MTProto handshake need the clock |
| `host.dns` | UDP DNS agrees with DoH (asked of all four DoH endpoints at once, 3 s each; the first answer wins, the endpoints that failed are named in the evidence and counted in the summary) | UDP blocked or hijacked while DNS mode is `doh`; no DoH endpoint answers | the DoH forwarder is down in mode `doh`; UDP blocked or hijacked in mode `system` | fix `set_dns_mode_doh` (below) when the mode is `system` |
| `host.disk` | 1 GiB and 5 % free | less | under 256 MiB | free space: the record buffer, artifacts and Docker images live there |
| `host.memory` | 10 % available | less | under 64 MiB | engines may be killed by the OOM killer |
| `host.ports` (per listener) | only the edge listens there | the owner cannot be read | another process listens | stop it or move the listener |
| `host.public_ips` | known, and every bind address is one of them | the set changed in the last 24 h | none known, or a listener binds an address that is not the node's | links with an old address no longer reach the node |
| `host.reserved_ports` (full runs) | 20000-40999 are in `ip_local_reserved_ports` | they are not | | run `install.sh` again; it reserves them |
| `host.edge_caps` | no refusal in 10 minutes | the edge refused or evicted connections at its caps (counts in evidence) | | a flood, or caps too low for the load |
| `host.stats` | every client address of a minute fit the statistics | addresses of a minute were left out of its countries | | the country totals of that minute are short |

### Listener and engine

| Check | ok | warn | fail | Fix |
|---|---|---|---|---|
| `ingress.bound` (per listener) | the edge listens on the address | | it does not (see `host.ports`, `host.public_ips`) | |
| `ingress.external` (from the panel) | a datacenter answered through the proxy | the proxy answered, no datacenter did (L1 only) | unreachable | link host, `ingress.bound`, the node's firewall |
| `engine.container` | the serving container runs | restarted in the last 10 minutes | missing, **paused**, exited, dead, restarting, or 3 restarts in 10 minutes (the last 20 log lines are in evidence) | `recreate_instance` |
| `engine.ready` | the engine is ready | | not ready | `recreate_instance` |
| `engine.dcs` | the writers of every datacenter 100 % covered (`coverage_pct`; middle-proxy mode only) | some lower | all 0 | look at the egress; skip when the proxy does not use middle proxies. Endpoints without a writer (`available_pct` below 100) are idle, not broken, and `fresh_coverage_pct` is evidence only: neither changes the status |
| `engine.log` | no known problem line | a known warning | a known error, with its cause | the fix of the line (`change_egress` for middle-proxy and upstream errors, `recreate_instance` for a port that cannot bind) |
| `engine.version` (full) | running = desired | differs for over 10 minutes | | the roll did not complete: see the proxy's status and the node's events |
| `e2e.l1` | a fake-TLS handshake through the edge's test listener passes | | fails | `recreate_instance` |
| `e2e.l2` (10 min) | a datacenter answers through the test listener | | fails while L1 passes: the way out does not reach Telegram | `change_egress` |

### Egress

| Check | ok | warn | fail | Fix |
|---|---|---|---|---|
| `egress.member` (per chain member) | up, with latency and exit IP | down, but another member of the chain is up and carries the traffic | no member of the chain is up | `refresh_subscription` for a subscription member |
| `egress.dc` (full) | a datacenter answers through the proxy's SOCKS port | | none does | `change_egress` |
| `egress.me` (full, middle proxies) | `getProxySecret` answers 200 through the SOCKS port | | fails | `change_egress` |

### WEB proxies

`web.cert` (the certificate is valid for the domain, at least 14 days left; warn under 14, fail
under 3; warn too when the chain is not publicly trusted: a private CA or ACME staging), `web.dns` (the domain's A records point at this node only, and not at Cloudflare),
`web.http2` (the node serves the stored certificate and answers `GET /` with 200 over HTTP/2),
`web.decoy` (the decoy page exists), `web.base_path` (behind a web server, the base path answers
without a redirect). The fix of `web.cert` is `reissue_cert`. A certificate is removed from the node 5 minutes after
no proxy uses its domain, so re-creating an ACME proxy after that issues a new certificate (mind
the Let's Encrypt rate limits). The panel's own probe of a WEB
proxy is checked at the HTTP/2 level and shown as `ingress.external`.

### The panel's checks

| Check | ok | warn | fail |
|---|---|---|---|
| `panel.connection` | the node is online | it refused its desired state, or its last reconcile pass failed | offline |
| `panel.state` | applied equals desired | behind for 5 minutes or more | |
| `panel.versions` | the edge runs the agent's version | it differs (fix `roll_edge`) | |
| `panel.link_host` | the link host resolves to a public address of the node | it resolves elsewhere | it does not resolve, or none is set |
| `panel.geoip` | the database is fresh, or not needed | older than 62 days | missing while the policy uses countries |

## The fixes

A fix is offered by a check, never applied by itself: you confirm it in a dialog that says what it
changes. It is a change of the desired state (so it is validated, survives restarts, and is
audited as `diagnostics.fix` with the event `diagnostics.fix_applied`), not a command. A node is
offered a fix only when it reports the capability.

| Fix | Target | What it changes |
|---|---|---|
| `recreate_instance` | proxy | starts a new engine generation next to the running one and switches over by blue-green (the old one drains); a failing gate keeps the old one |
| `roll_edge` | node | starts a new edge generation next to the running one, running the agent's version; connections held by the old one stay until they end |
| `change_egress` | proxy, with a chain to choose | moves the proxy to another egress chain, as an edit of the proxy |
| `refresh_subscription` | egress member | fetches the subscription of the member again |
| `set_dns_mode_doh` | node | the DNS mode of the node becomes DoH: the edge's forwarder serves the containers |
| `reissue_cert` | WEB proxy | has ACME issue the certificate again; the node keeps serving the current one meanwhile |

**Before and after.** A fix is followed by a full run of its scope once the node has applied the
change, shown beside the run the fix was offered from, so you see what it healed. The same
happens around changes you make: rollout steps and edits of a proxy's
egress chain, a node's default chain, an egress or the DNS mode. The panel validates, runs a full
check first (up to 90 s; offline or old nodes get a "skipped" or "partial" one), commits, and runs
a check again 60 seconds after the node applied it. A check that was ok or warn before and fails
after marks the run **regressed** and writes the event `diagnostics.regressed` (error). Nothing
is rolled back and no rollout step fails because of it; it informs. Changes a node makes by
itself (a blue-green it starts, a member failover) are compared with the light checks of that
moment, at most once in 5 minutes per node.

## The problem feed and the journal

The feed on Overview lists what is wrong now: offline nodes, a node's error or rejection, failed
proxies, proxies that are down, failing light checks (with the fix button where there is one), a
missing or old country database, an edge that differs from the agent. Errors come first. It is
computed from the current state, so a problem leaves it when it is gone.

The Journal keeps the history. **Events** (30 days) include `check.failed`, `check.warning`,
`check.recovered` (at most one per node, check and target per 10 minutes), `probe.failed`,
`probe.recovered`, `diagnostics.regressed`, `diagnostics.fix_applied`, `geoip.updated` and
`geoip.failed`, and the node's own (`geoip_stored`, `edge_roll_requested`, `mgmt.fallback`). The
**audit log** names the admin and the action: `settings.update`, `geoip.upload`, `geoip.refresh`,
`geoip.enabled`, `public_page.update`, `diagnostics.run`, `diagnostics.fix`, `probe.run`.

## The public page

An optional page on a domain of its own (Settings, Public page) that lists the proxies you choose
as a departure board, so you hand out one address. **It is public, secrets included: list only
proxies meant for everyone.**

- The look: dark, monospaced, one row per proxy in the order of the list. The title has one line,
  or two (the second shown in amber); under it your text (Markdown), or a default line that says
  to tap a row. A row is the proxy's **code**, its public name and note, and its address
  (`server:port` for fake TLS, the server of a WEB proxy); the whole row is the `tg://` link.
  Under the rows, **Enter manually** (closed) has the server, port and secret of each proxy, each
  with a copy button, and its `https://t.me/...` link. The **footer** is your plain text (at most
  300 bytes, line breaks kept), or a default line. There is no QR code on the page (the admin
  still shows them).
- The code of an item is up to 4 letters and digits (stored in upper case). Empty, the page shows
  the country of the server by the panel's country database: of the link's address when that is
  an IP, else of the node's public IP. Without the database, or without an answer, the code stays
  empty. The form shows that country as the placeholder of the field. So an empty code tells a
  visitor the country of the node, nothing more.

- The panel serves it for exactly one host, and only `/`, `/robots.txt` and two embedded assets;
  everything else there (`/api/...`, `/setup`, the admin) is a 404, also while the page is off.
  The one exception is `/api/tls/ask`, the on-demand TLS question of the reverse proxy, which
  answers the proxy alone (see
  [Behind a reverse proxy](../deploy/panel/README.md#behind-a-reverse-proxy)). The panel
  refuses a host that is equal to a name the admin has been reached on.
- Point the domain at the panel (behind your reverse proxy or Cloudflare). The reverse proxy
  needs a certificate for it: with the Caddyfile of the README, Caddy gets one on the first
  visit; nginx needs the host added by hand. **Check**, under the host, says where the name
  points and whether HTTPS works, and with which certificate. Every answer of the page carries
  `X-Postern-Page: 1`, so the check can tell it from another site. The page is
  `Cache-Control: no-store`, readable without JavaScript, with a strict CSP, `noindex` and
  `robots.txt` `Disallow: /` unless you allow indexing.
- An unavailable proxy (paused, its node offline, or probes down) is **marked** (a muted row with
  its code, name, note and "unavailable", no link, no address, no secret, and not under Enter
  manually) or **hidden**, at once: the items are rendered for every request.
- Nothing else of the panel shows: no node names, addresses (except link hosts) or versions.

## Environment switches

| Variable | Effect |
|---|---|
| `POSTERN_PUBLIC_PAGE=off` | Host routing is off: the admin answers on every host, including the public page's own, and the page on none. The way back in when the public page was given the name you reach the panel by. Remove it and restart to bring the page back. |
| `POSTERN_GEOIP_BASE_URL` | Where the country database is downloaded from, instead of `https://download.db-ip.com/free`: an `http://` or `https://` directory with the same file names (a mirror), without a user name or password. |

Both are set in the panel's environment (see [deploy/panel/README.md](../deploy/panel/README.md#configuration)).
