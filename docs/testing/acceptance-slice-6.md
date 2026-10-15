# Acceptance of statistics, diagnostics and the public page

A manual check with real servers and real Telegram clients, of what the automated tests cannot
see: that the numbers match a known load, that no client address survives a change of the IP
policy, that every check fails when its link breaks and is healed by its fix, and that the
public page behaves behind Cloudflare. It builds on [smoke-remote.md](smoke-remote.md): do its
steps 1 to 10.2 first (the panel, the node `smoke` online, a TLS listener on `<PORT>`, a proxy
`main` that a Telegram client uses, a second test server with a VLESS server, and the chain
`reality` that goes out through it). What the checks and fixes mean is in
[../diagnostics.md](../diagnostics.md).

| Placeholder | What it is |
|---|---|
| `<SERVER_IP>` | the public IPv4 address of the test server (the node) |
| `<SERVER_B_IP>` | the public address of the second test server, which is the egress |
| `<PANEL_IP>` | the address the panel connects from, as the node sees it (`ssh root@<SERVER_IP> 'echo $SSH_CLIENT'`) |
| `<PORT>` | the port of the proxy's listener |
| `<PUBLIC_HOST>` | a test subdomain of your test zone at Cloudflare for the public page, such as `proxies.example.com`; do not clean the zone afterwards |
| `<ADMIN_HOST>` | the name or address the admin is reached on, which is not `<PUBLIC_HOST>` |
| `<CLIENT_A_IP>`, `<CLIENT_B_IP>` | the public addresses of the two clients, from two networks in two countries (look them up on the device, not in the panel) |
| `<PROXY_ID>` | the id of the proxy `main`, in lower case, as in the container name `postern-eng-<PROXY_ID>-g<N>` |

Needs: two Telegram clients on two networks in different countries (a phone on mobile data and a
computer on another network, or a VPN exit in another country; the address the **server** sees is
what counts), a phone for the public page, a way to read `<PUBLIC_HOST>` from outside, and a
panel that reaches `download.db-ip.com`. Keep a note of every result; "expected" lines are the
pass criteria.

Tick or note each line. At the end, each failure and its fix must be in the Journal (step 6).

## 1. Statistics

1. Set Settings, Statistics and privacy: IP policy `full`, probes every 5 minutes. Save.
2. **A known download.** With client A connected through `main`, download a file of a known size
   from a chat (for example 200 MB, saved to the device). Note the start time.
   Expected: within 2 minutes the traffic chart of the proxy (range 1 h) shows the minutes with
   the download, and the sum of "Download" over them is the file size within 10 % (Telegram's own
   overhead). The node's page shows the same traffic of its proxies.
3. **Unique IPs.** With clients A and B both connected and active: within 2 minutes the chart
   "Unique IPs (peak)" of the proxy reaches 2 and the live figure says 2. Disconnect B: the live
   figure falls to 1, the peak of that period stays 2.
4. **Node load.** During the download, the node's CPU, memory and load (1 min) in the panel are
   close to `top` and `free -m` on `<SERVER_IP>` taken at the same time (CPU within 10 points,
   memory within 5 %).
5. **Top proxies.** Create a second proxy `second` on the listener and let it carry a little
   traffic. Overview, "Top proxies (24 h)" lists `main` above `second`, with traffic, new
   connections and unique IPs.
6. **A panel restart loses no minute.** While client A downloads another large file, restart the
   panel for about 30 seconds (stop it, wait, start it; the node keeps its records for the panel).
   Expected: the traffic chart has no empty minute in the gap, and the minutes are not doubled
   (the sum over the gap is still the file size within 10 %).

## 2. Countries and the IP policy

On the panel host, `<DATA>` is the panel's data directory (`smoke/data`, or the volume of the
container); on the node, `/opt/postern/data`.

1. **The database.** Settings, Country database: the panel has fetched a database (the month, a
   size near 8 MB, a SHA-256, no error). `ls <DATA>/geoip/` has `dbip-country-lite-<YYYY-MM>.mmdb`,
   `ls /opt/postern/data/geoip/` on the node has `<sha256>.mmdb` with the same SHA-256, and the
   Journal has `geoip.updated` and the node's `geoip_stored`. "About Postern" and the countries
   views carry "IP Geolocation by DB-IP".
2. **Two countries.** Policy `full`. With clients A and B connected and active for 2 minutes: the
   proxy's Countries card shows two countries (the right ones), each with traffic and "peak unique
   IPs in a minute" of 1; Overview, "Countries (24 h)" shows them too.
3. **`full` lists the addresses.** IP history of the proxy lists `<CLIENT_A_IP>` and
   `<CLIENT_B_IP>` with their countries, first and last seen and bytes.
   Control (the grep finds what it should), as root:

   ```sh
   grep -a -c -F '<CLIENT_A_IP>' <DATA>/postern.db <DATA>/postern.db-wal
   grep -a -c -F '<CLIENT_A_IP>' /opt/postern/data/stats.db /opt/postern/data/stats.db-wal
   ```

   Expected: a count above 0 in at least one file of each pair. If both are 0 in both, the
   address is stored in a form the grep does not find: stop and report it, the next check would
   prove nothing.
4. **`countries` empties the list.** Disconnect the clients, set the policy to `countries`
   (the dialog warns that the IP history is deleted; confirm). Expected: IP history of the proxy
   is empty and says the policy is `countries`; the Countries card keeps its totals. Then
   reconnect and use both clients for 2 minutes, and run the four greps:

   ```sh
   grep -a -c -F '<CLIENT_A_IP>' <DATA>/postern.db <DATA>/postern.db-wal <DATA>/backups/* 2>/dev/null
   grep -a -c -F '<CLIENT_B_IP>' <DATA>/postern.db <DATA>/postern.db-wal <DATA>/backups/* 2>/dev/null
   grep -a -c -F '<CLIENT_A_IP>' /opt/postern/data/stats.db /opt/postern/data/stats.db-wal
   grep -a -c -F '<CLIENT_B_IP>' /opt/postern/data/stats.db /opt/postern/data/stats.db-wal
   ```

   Expected: every count is 0. Do the same with the IPv6 form of an address when a client has one.
   If `<DATA>/backups/` is empty (no migration yet), note that there was nothing to grep there.
   Clients on `countries` still show two countries.
5. **`off` empties the country tables.** Set the policy `off` (confirm the dialog). Expected: the
   Countries card says the policy is off and has no rows, `sqlite3 <DATA>/postern.db 'select
   count(*) from stats_country_1m'` (and `_1h`, `_1d`) prints 0, device counts still show 2 for
   both clients, the greps of 4 still print 0.
6. Put the policy back to `countries`.

## 3. Diagnostics

Do these on proxy `main` of node `smoke` unless said otherwise. A run is **Run full check** on
the node's page, or **Check this proxy** on the proxy's. After each fix, the after-run appears
about a minute after the node applied it; open both runs from the history and compare.

1. **A full run on a healthy node.** Expected: every check ok or skip. `host.reserved_ports`,
   `engine.dcs` (a skip when the proxy does not use middle proxies) and similar may skip with a
   reason; nothing is `fail`, and a `warn` needs a reason you can explain (note it).
2. **A paused engine, `recreate_instance`.**
   `docker pause postern-eng-<PROXY_ID>-g<N>` on the node. Run the proxy's check: expected
   `engine.container` fails ("the serving container is paused", the last log lines in the
   evidence), with the fix "Recreate the engine". The light checks show the same within about
   2 minutes, and the problem feed lists it. Then `docker unpause postern-eng-<PROXY_ID>-g<N>`:
   within 2 minutes the light check is ok and the feed is clear. Apply "Recreate the engine" from
   the earlier run (it is still the node's latest, so it is offered), confirm. Expected: a new
   engine generation `g<N+1>` serves by blue-green and the old container goes after it drains,
   client A stays connected, the after-run is all ok and is shown beside the before-run, and the
   journal has the audit `diagnostics.fix` and the event `diagnostics.fix_applied`.
3. **No way to Telegram on the egress, `change_egress`.** Put the proxy `main` on the chain
   `reality`. On `<SERVER_B_IP>`, drop the datacenters:

   ```sh
   for ip in 149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 91.108.56.130; do
     iptables -I OUTPUT -d $ip -j DROP
   done
   ```

   Run the proxy's check. Expected: `egress.dc` fails ("no datacenter answered through the proxy's
   SOCKS port") with the fix "Change the egress", `e2e.l2` fails while `e2e.l1` passes, and
   `egress.member` may show the member of `reality` down (note which). Apply "Change the egress", choose a chain
   that goes out otherwise (the direct chain of the node, or `warp`), confirm. Expected: the
   before-run (the failing one) and the after-run (all of `egress.*` ok) form a before/after
   pair, the proxy works again, and the proxy's chain in the proxy form is the new one. Remove
   the rules on `<SERVER_B_IP>`: `iptables -D OUTPUT -d <ip> -j DROP` for each.
4. **The clock.** On the node: `timedatectl set-ntp false; date -s "@$(( $(date +%s) + 40 ))"`.
   Run the node's full check: expected `host.clock` fails ("the clock is off by 40 s ..."), with
   the hint about NTP and no fix. Restore afterwards, also if the step failed:
   `timedatectl set-ntp true`, then check `date` against another machine; a full run is ok again.
5. **DNS over UDP, `set_dns_mode_doh`.** On the node page, Egress, Name resolution: "The resolver
   of the host" (`system`), save (the edit waits for its before-run, see 8). On the node:
   `iptables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP`. Run the node's full check. Expected:
   `host.dns` fails ("UDP DNS is blocked while the containers use the host's resolver (DNS mode
   system)"), with the fix "Switch DNS to DoH". Apply it. Expected: the node's DNS mode is
   `doh`, the after-run has `host.dns` at most `warn` ("UDP DNS is blocked; the forwarder serves
   over DNS over HTTPS"), and the proxies keep serving. Remove the rule
   (`iptables -D OUTPUT ! -o lo -p udp --dport 53 -j DROP`).
6. **`roll_edge`.** The node's edge must run an older version than its agent: after an update of
   the agent through Versions (see [../releasing.md](../releasing.md)), the edge stays on the
   version it was started with, and `panel.versions` warns ("the edge runs ..., the agent ...")
   with the fix "Roll the edge". Hold a connection through the proxy (client A downloading a large
   file, or a call). Apply the fix. Expected: `docker ps` shows `postern-edge-g<N+1>` beside
   `postern-edge-g<N>`, the old one leaves when its connections have ended, the held connection
   is not dropped, `panel.versions` is ok, and the fix is audited. (When no node is behind, say
   so; the automated test of the roll is `docs/testing/e2e.md`.)
7. **Egress edit waits for its before-run.** Change the chain of proxy `second` in its form and
   save. Expected: the form says "Checking the node before the change (up to 90 s)..." and saves
   within 90 s; the run history of the node has a run "Before a change" and, about a minute after
   the node applied the change, "After a change", compared with each other. Stop the node's
   agent (`docker stop postern-agent`), edit again: the edit is saved within 90 s with a
   "skipped" or "partial" before-run. Start the agent again.

## 4. Probes

1. **From outside.** Proxy page, Availability: "Last probe from the panel" is recent and says
   "Through to Telegram"; uptime 24 h is 100 % after an hour; a full run has `ingress.external`
   ok. The probe came from `<PANEL_IP>`; Settings lists `<PANEL_IP>` among "The panel's
   addresses, as the nodes see them" for node `smoke`.
2. **The exemption with `limit_devices = 1`.** Edit `main`: Unique IPs (devices) 1. Connect
   client A and keep it active. Press "Probe now" three times and wait for a scheduled probe.
   Expected: each probe passes, client A stays connected (no "Connecting..."), and the proxy's
   devices still say 1. A second client B is refused or does not connect (the limit still holds
   for clients). Put the limit back.
3. **A blocked port makes the proxy down.** Set the probe interval to 1 minute. On the node:
   `iptables -I INPUT -p tcp --dport <PORT> -j DROP`. Expected: the first failing probe is
   shown as a failure ("Recent failures" lists it); after the second, within about 3 minutes,
   the problem feed says the proxy is down, the Journal has `probe.failed`, and the public page
   (step 5) marks the proxy without a link. Remove the rule: the next probe passes, the feed is
   clear (`probe.recovered`), the page lists the proxy again. Put the interval back to 5.

## 5. The public page

Point `<PUBLIC_HOST>` at the panel through Cloudflare (a proxied record to the host that serves
the panel or its reverse proxy; see [../../deploy/panel/README.md](../../deploy/panel/README.md)).
In Settings, Public page: host `<PUBLIC_HOST>`, `unavailable` = mark, add proxies `main` and
`second` with a public name and a note each, enable it (confirm the warning).

1. **Headers.** `curl -sI https://<PUBLIC_HOST>/` is 200 with `content-security-policy:
   default-src 'none'; ...`, `x-content-type-options: nosniff`, `x-frame-options: DENY`,
   `referrer-policy: no-referrer`, `cache-control: no-store`, `cdn-cache-control: no-store` and
   `x-robots-tag: noindex, nofollow, noarchive`; Cloudflare does not cache it
   (`cf-cache-status` is `DYNAMIC` or missing).
2. **robots.** `curl -s https://<PUBLIC_HOST>/robots.txt` prints `User-agent: *` and
   `Disallow: /`. With "Allow search engines" on, it prints `Allow: /`; turn it back off.
3. **Without JavaScript.** `curl -s https://<PUBLIC_HOST>/` (or a browser with JavaScript off)
   shows both proxies with their public names and notes, the "Connect" link, the manual
   parameters (server, port, secret) and a QR; `?lang=en` and `?lang=ru` switch the labels. The
   panel's names of the proxies, nodes and addresses other than the link host are not there.
4. **Connect on a phone.** Open the page on the phone, tap "Connect": Telegram opens with the
   proxy to add, and after adding it connects and chats load. The QR scanned from another screen
   does the same.
5. **Pause.** Pause `second` in the panel. Reload the page: `second` is shown as "unavailable"
   with no link, QR or parameters (`mark`); switch `unavailable` to `hide` and it is not there at
   all. Resume it and put `mark` back. Neither takes more than a reload.
6. **Nothing else on that host.** `curl -s -o /dev/null -w '%{http_code}\n'
   https://<PUBLIC_HOST>/api/` and `.../setup`, `.../login`, `.../assets/x`, and a `POST /`
   print 404 (405 for the `POST`).
7. **The admin on its own address.** `https://<ADMIN_HOST>/` is the admin (sign-in works), and
   `https://<ADMIN_HOST>/robots.txt` and `/` are not the public page.
8. **A host equal to the admin's name is refused.** Put `<ADMIN_HOST>` in the Host field and
   save: the panel refuses with a message. (Optional, lock-out: set `POSTERN_PUBLIC_PAGE=off`,
   restart the panel, and the admin answers on `<PUBLIC_HOST>` too; remove it and restart.)

## 6. The feed and the journal

For every failure made above (paused engine, dropped datacenters, clock, UDP/53, the old edge,
the blocked port, the stopped agent), check:

- the problem feed showed it while it lasted (a light check, `proxy.down`, `node.offline`) and
  was clear after the repair;
- the Journal, Events, has `check.failed` or `check.warning` and `check.recovered` for it,
  `diagnostics.fix_applied` for each fix, `probe.failed`/`probe.recovered` for the port, and a
  `diagnostics.regressed` for none of them (a regression would mean a fix broke something);
- the Journal, Audit log, has `diagnostics.fix` (one per fix, with your name), `diagnostics.run`
  for the manual runs, `settings.update` for the policy changes and `public_page.update`.

## Report

Write down, for each numbered check above: pass or fail, what you saw when it differs, the version
of the panel and of the node, the countries of the two networks and the date. A failure that
leaves traces (a firewall rule, a stopped agent, the clock, a paused container, the DNS mode)
is not a pass until you have restored it. Remove the public page host and its Cloudflare record
if it was only for this test, but leave the zone as it is.
