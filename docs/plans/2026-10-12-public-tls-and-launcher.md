# HTTPS for the public page without SSH; a newer image wins — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** two problems the owner hit on 2026-10-12.

1. **The public page did not work by HTTPS.** He set its host in the UI and pointed DNS at the panel, but the browser got `ERR_SSL_PROTOCOL_ERROR`. The reverse proxy (Caddy) had no site for that name, and getting one needed SSH. The panel must make this work by itself.
2. **A newer image was ignored.** After a self-update, `/data/bin/current` points at the binary it installed. The panel launcher then keeps running that binary even when the container runs a newer image, so an image update did nothing until `bin/current` was removed by hand.

**Architecture:**
- **Task 1.** The panel answers Caddy's on-demand TLS `ask` endpoint. It approves only the names it serves: the enabled public page host, and the admin hosts it has recorded. The recommended Caddyfile gets a catch-all on-demand site, so a public page host set in the UI gets its certificate on the first visit, with no other change. The public page settings show whether the host resolves and answers by HTTPS. The README is updated.
- **Task 2.** A panel that runs a self-updated binary older than the image's binary steps aside at start: it removes `bin/current` and exits 75 to restart, so the launcher runs the image binary.

**Tech Stack:** Go 1.27, ConnectRPC (buf), React 19 + Mantine 8, Vitest.

**Spec:** this plan (the owner asked: "доделай", so the panel should do it by itself).

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply: Go in WSL, documentation addresses only (`example.com`, `192.0.2.0/24`…), `log/slog`, no secrets in logs.
- Commit author is `urbnywrt <14278436+urbnywrt@users.noreply.github.com>`. No trailer lines of any kind, never `--no-verify`.
- Proto fields take the next free number. Regenerate with `bash scripts/gen.sh` and `npm run gen` in `web/`.
- UI strings go into `web/src/i18n/ru.json` and `en.json`, or the `insights.*` files where the public page keeps its strings, with key parity. Russian is plain.
- Tests are robust on slow CI runners: no fixed-margin timing; poll with deadlines; the web async timeout is 5 s.

---

### Task 1: the panel approves its names for on-demand TLS; the public page shows its HTTPS state

**Files:**
- Create: a plain HTTP handler for the ask endpoint, in the server or public page package (follow how `nodes.BundleRoute` and `KitRoute` are mounted in `internal/panel/server/api.go`), with tests.
- Modify:
  - `proto/postern/panel/v1/` (the public page service: a new `CheckPublicPage` RPC), its Go service (`internal/panel/publicpage`), and the generated code;
  - the public page settings UI (find it from the strings «Публичная страница» / «Показывать страницу»);
  - `deploy/panel/README.md`, section "Behind a reverse proxy";
  - the panel's docs for the public page, if they mention TLS.

**Requirements:**
- [ ] **`GET /api/tls/ask?domain=<name>`.** Caddy calls it as `on_demand_tls { ask … }` with the query `domain`.
  - It answers **200** when the name, lowercased and without a final dot, is the public page's host while the page is enabled, or one of the admin hosts the panel has recorded (`store.DB.AdminHosts`).
  - It answers **404** for every other name, and **400** for a missing or invalid one.
  - It answers only peers on loopback or in `POSTERN_TRUSTED_PROXIES`, the reverse proxy itself; any other peer gets 404. Use the peer address, not `X-Forwarded-For`.
  - No auth, no body, no cache headers that keep a stale answer. Never log the name at a level above debug.
  - It must answer for the public page host although requests for that `Host` go to the public page site: the `/api/tls/ask` path must be reachable however the proxy sets `Host`. Caddy's ask request carries `Host: 127.0.0.1:8080`. Check how `api.go` routes by `Host` and make sure this works.
  - Tests cover each case and the peer rule.
- [ ] **`PublicPageService.CheckPublicPage`** (admin), for the configured host. It returns:
  - the host's A/AAAA records, resolved over DoH with the panel's existing DoH or DNS helper, else the system resolver;
  - whether `https://<host>/robots.txt` answers 200 with a certificate valid for the host, under a 10 s timeout, using the system roots, plus the error text if not;
  - the certificate's issuer and expiry;
  - whether the answer came from this panel's public page. Use a marker, for example a response header `X-Postern-Page: 1` that the public page sets on every answer; add the header if it is not there.

  Never follow a redirect to another host. Tests use an `httptest` TLS server and a fake resolver.
- [ ] **UI**, in the public page settings, under the host field: a «Проверить» button and the result.
  - DNS: «указывает на 203.0.113.10», or «не найден».
  - HTTPS: «работает, сертификат до DD.MM» or the error.
  - When HTTPS fails, a short hint: «Сертификат выдаёт reverse proxy перед панелью. Если используете Caddy, включите on-demand TLS по инструкции» with a link to the README section on GitHub (`https://github.com/urbnywrt/postern/blob/main/deploy/panel/README.md#behind-a-reverse-proxy`).
  - The check also runs once when the page settings open, if a host is set and the page is enabled.
- [ ] **README, "Behind a reverse proxy".** The recommended Caddyfile becomes:

  ```
  {
  	on_demand_tls {
  		ask http://127.0.0.1:8080/api/tls/ask
  	}
  }

  panel.example.com {
  	reverse_proxy 127.0.0.1:8080
  }

  https:// {
  	tls {
  		on_demand
  	}
  	reverse_proxy 127.0.0.1:8080
  }
  ```

  Explain why: the panel approves only its own names, and a public page host set in the UI gets its certificate on the first visit. Keep the nginx notes, saying that nginx needs the host added by hand. Mention `POSTERN_TRUSTED_PROXIES` for a proxy that is not on loopback.
- [ ] **Commit(s):**
  - `feat(panel): approve the panel's own names for on-demand TLS`;
  - `feat(panel): check the public page's DNS and HTTPS`;
  - `feat(web): the public page settings show their HTTPS state`;
  - `docs(panel): a Caddyfile that serves the public page by itself`.

---

### Task 2: a newer image wins over an older self-updated binary

**Files:**
- Modify: the panel's start-up path (`cmd/panel/serve.go` or `internal/panel/selfupdate`, wherever the panel learns that it runs under its launcher and knows `ImageBin`), with tests. Update the comment of `deploy/panel/launcher.sh` and `deploy/panel/README.md` (updates section).

**Requirements:**
- [ ] **At start, before serving.** A panel that runs from `$POSTERN_DATA/bin/postern-panel-<v>` (through `bin/current`, under the launcher) and finds an image binary (`ImageBin`) whose version is newer than its own, with semver including prereleases (reuse the module's comparison in `internal/release` or `internal/version`), steps aside:
  - it logs at warn: "the image carries vX, newer than the self-updated vY: going back to the image binary";
  - it removes `bin/current`, and `bin/previous` if it points at the image (keep the version files: GC handles them);
  - it records an event or update note if the panel keeps a last-update record;
  - it exits 75, so the launcher restarts and runs the image binary.

  Not the other way round: an image older than or equal to the running version changes nothing. A failure to read the image version is a warning, and the panel goes on.
- [ ] **Tests:**
  - a fake image binary (`version` prints a version) newer, older, equal and unreadable, with the expected file effects and exit decision;
  - nothing happens when the panel runs the image binary itself.
- [ ] **Commit:** `fix(panel): a newer image wins over an older self-updated binary`.
