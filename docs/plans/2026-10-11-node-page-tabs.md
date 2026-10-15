# Node page in tabs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the owner gets lost on the node page. It is one long column of 13 sections with buttons scattered among them. Split it into tabs, and surface the one action that matters now as a banner. The owner approved the layout on 2026-10-11.

**Architecture:** web only (`web/src`).
- The page `NodeDetail` becomes a header plus a context banner plus tabs. Each tab is a nested route.
- The existing section components are reused as they are and only moved; do not rewrite them unless the move needs it.
- New: the overview tiles, the context banner, and the provisioning mode.

**Tech Stack:** React 19, React Router (the app's router in `web/src/app/router.tsx`), Mantine 8 (`Tabs`, `Menu`), TanStack Query, react-i18next, Vitest + Testing Library.

**Spec:** this plan. The owner approved this layout:

| Tab (ru / en) | Route | Content, from the current `NodeDetail` sections |
|---|---|---|
| Обзор / Overview | `/nodes/:nodeId` | Tiles: proxies, devices now, traffic over 24 h, last seen. Then the node's proxies list, then the 24-h traffic chart (the main chart of `NodeStatsSection`, or its compact form). |
| Прокси и входы / Proxies and listeners | `/nodes/:nodeId/proxies` | `NodeProxies` with its add-proxy action, `ListenersTable`, `NodePorts`. |
| Выходы / Egress | `/nodes/:nodeId/egress` | `NodeEgressSettings` (default chain, DNS mode), `EgressHealth`, `EgressHistory`. |
| Диагностика / Diagnostics | `/nodes/:nodeId/diagnostics` | `DiagnosticsSection` (problems, full run, details). The tab label carries a count badge of the node's warn and fail problems. |
| Настройки / Settings | `/nodes/:nodeId/settings` | `NodeState` (facts), `NodeManagement`, `NodeVersionsCard`, `NodeArtifactSource`, and `NodeInstall` titled «Установка заново» / "Reinstall" (Docker command, SSH). Last, a danger zone with «Удалить ноду». |

## Global Constraints

- Commit author is `urbnywrt <14278436+urbnywrt@users.noreply.github.com>`. No trailer lines of any kind, never `--no-verify`.
- UI strings go into `web/src/i18n/ru.json` and `en.json` (or the `insights.*.json` files where a section already keeps its strings), with key parity. Russian is short and plain.
- Tests must be robust on slow CI runners. Use `findBy*`/`waitFor`; the global async timeout is 5 s and the test timeout 15 s (`web/src/test/setup.ts`, `vite.config.ts`).
- No new dependency.
- Keep the existing page `/nodes/:nodeId/install` (SSH wizard) as it is. Links into it keep working.

---

### Task 1: the tabbed node page

**Files:**
- Modify: `web/src/pages/NodeDetail.tsx` (split into a layout plus tab pages; new files under `web/src/pages/node/` are welcome), `web/src/app/router.tsx` (nested routes), the i18n files, and tests (`web/src/pages/NodeDetail.test.tsx` and new ones).
- Modify the links that should land on a tab:
  - the problem feed's link to a node goes to `/nodes/:id/diagnostics`;
  - a proxy's node link stays on the overview.
  - Look at `web/src/components/ProblemFeed*`, `NodeCard.tsx`, `ProxyTable.tsx`, `NodeVersionsTable.tsx`, `JobLog.tsx` and `NodeInstall.tsx`, and change only where a tab is the better target.

**Requirements:**
- [ ] **Header.**
  - The back link «Ноды», then the name and the status badge.
  - On the right, «Изменить» (opens the existing edit dialog) and a «⋯» `Menu`. The menu holds «Удалить ноду», opening the existing confirm dialog.
  - The no-address alert (`nodes.detail.noHost`) stays under the header.
- [ ] **Context banner**, above the tabs. It shows at most one, the first that applies:
  1. **provisioning:** the node was never seen. «Нода ещё не подключена. Установите её» with a button to the install section.
  2. **an agent update is offered:** «Агент vX, панель предлагает vY» with «Обновить ноду». Use the action the versions card uses today (`NodeVersionsCard`, `versions.node.updateAgent`).
  3. **the edge is outdated:** «Edge работает на старой версии» with «Перекатить edge». Reuse the existing roll action.
  4. **a node update needs a reinstall** (`needsInstall`): its existing hint.
  Take the conditions from the data the versions card and node facts already use; do not add an RPC.
- [ ] **Tabs.**
  - Mantine `Tabs` bound to the nested route: the URL is the state, and back and forward work.
  - Content per the Spec table. The overview tiles use data the page already has or fetches (proxies of the node, the node stats series, `lastSeen`). A tile without data shows «—», not an error.
- [ ] **Provisioning mode** (status `provisioning` and never seen).
  - The page opens on the install content in the overview position: the one-command install block (`NodeDockerInstall`) first, then the SSH button, and the kit fold.
  - The other tabs are shown but disabled, with a tooltip «Станет доступно, когда нода подключится».
  - Once the node is online, the normal layout appears without a reload (the query refetches as it does now).
- [ ] **Accessibility and phone width:** tab labels are text, the tab list scrolls horizontally on a phone, and the banner wraps.
- [ ] **Tests:**
  - each tab route renders its sections;
  - the banner picks the right message for each of its four cases and none when nothing applies;
  - the provisioning mode shows the install first and disabled tabs;
  - the «⋯» menu deletes through the confirm dialog;
  - the problem feed link goes to the diagnostics tab;
  - the old tests of `NodeDetail` are adjusted, not dropped: every behaviour they covered still has a test.
- [ ] `npm run lint`, `npm run typecheck`, and the full `npm test` pass in `web/`.
- [ ] **Commit(s):** `feat(web): the node page in tabs, with the action that matters on top`.
