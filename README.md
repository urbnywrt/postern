# Postern

[Русская версия](README.ru.md)

Postern is a control panel and node agent for deploying, managing and monitoring MTProto proxies (fake TLS and Telegram WEB proxies) across a fleet of servers. The panel (Go, SQLite, embedded web UI) keeps the desired state and pushes it to the nodes over gRPC with mutual TLS; on every node an agent and a traffic edge manage proxy engines that run in Docker containers.

> **Status: pre-alpha, not ready for production.** Interfaces, data formats and the deployment layout may change without notice.

## What it does

- **Nodes and proxies.** Fake-TLS and Telegram WEB proxies on a fleet of nodes, a shared traffic edge per node, engines (telemt, mtg) in containers, switched without dropping connections (blue-green).
- **Egresses.** Proxies leave through chains of egresses: direct, SOCKS5 or HTTP, Xray (share links and subscriptions), WARP and Psiphon, with failover. Psiphon is still Experimental: it is being rebuilt on psiphon-tunnel-core and is not confirmed on a real server.
- **Hidden management.** The panel can reach a node's agent through the port of one of its proxies, by a management SNI that only the panel knows, so the node shows no management port of its own ([node deployment](deploy/node/README.md#hidden-management)).
- **Versions, rollouts and updates.** Engine and provider versions follow the `stable` or `latest` channel or are pinned; a channel moves by a rollout (canary first, one step at a time); the panel and the nodes update themselves from signed releases ([panel](deploy/panel/README.md#self-update), [node](deploy/node/README.md#self-update-updateself), [releasing](docs/releasing.md)).
- **Statistics, diagnostics and a public page.** Traffic, connections and unique IPs per proxy and node, countries (offline DB-IP database) under a [privacy policy](docs/diagnostics.md#the-ip-policy) that keeps no client address by default, probes, checks of every link from the client to Telegram with one-click fixes, a problem feed, a journal and an optional public page with proxy links.

## Documentation

- [Design specification](docs/design/2026-10-04-postern-design.md) (in Russian)
- [Statistics, privacy and diagnostics](docs/diagnostics.md): retention, IP policy, every check and fix, probes, the public page
- Deployment: [panel](deploy/panel/README.md), [node](deploy/node/README.md)
- [Releasing](docs/releasing.md)
- Testing: [end-to-end test in CI](docs/testing/e2e.md), [smoke test on a real server](docs/testing/smoke-remote.md), [acceptance of statistics, diagnostics and the public page](docs/testing/acceptance-slice-6.md)

## License

Postern is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

## Third-party engines

Postern does not bundle any MTProto engine. The engines it manages, [telemt](https://github.com/telemt/telemt) and [mtg](https://github.com/9seconds/mtg), are separate projects: Postern downloads their binaries from the upstream release pages and verifies them by checksum. So are the programs that run its egresses, [Xray-core](https://github.com/XTLS/Xray-core), whose archives are checked against the checksums that Postern pins and against the `.dgst` files of its releases, and Psiphon's client [psiphon-tunnel-core](https://github.com/Psiphon-Labs/psiphon-tunnel-core) (GPL-3.0), which each release of Postern builds from a pinned upstream commit and ships, signed, with the source offer of the GPL ([docs/third-party/psiphon-tunnel-core.md](docs/third-party/psiphon-tunnel-core.md)). They remain under their authors' licenses.

## Country data

Postern tells the country of an address with the free IP to Country Lite database of DB-IP, which the panel downloads once a month. Country data: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0
