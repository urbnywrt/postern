# Versions page: what can be updated, on top — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the owner could not find how to update the panel. The «Панель» card sits low on the long «Версии» page. With prereleases off it only said «Панель не знает более нового релиза Postern», although `v1.0.0-rc6` was out. The owner approved a new layout on 2026-10-11:
- a block «Можно обновить» on top: one line per update that can be done now, each with its button, and the rollouts in progress with their controls;
- the rest in tabs;
- a header badge when Postern itself can be updated;
- a clear switch for prereleases, offered right where it matters.

**Architecture:** web only (`web/src`). Reuse the existing components (`ComponentCard`, `NodeVersionsTable`, `PanelUpdateCard` logic, `ReleaseSourceForm`, the rollout section and the `RolloutDialog`), the existing hooks and the existing RPCs. No new RPC. The page `web/src/pages/Versions.tsx` becomes a header, the updates block, and the tabs as nested routes.

**Tech Stack:** React 19, React Router, Mantine 8, TanStack Query, react-i18next, Vitest + Testing Library.

**Spec:** this plan. The owner approved this layout:

| Part | Route | Content |
|---|---|---|
| Header | — | «Версии» and «Проверить релизы» (the existing refresh-all). |
| **Можно обновить** (always on top, above the tabs) | — | One line per update available now:<br>(1) **Панель Postern** `current → newest`, with a «пререлиз» badge when the target is one; button «Обновить панель», which runs the existing panel update flow with its confirmation.<br>(2) **Ноды**: "N из M на vX, панель vY", for nodes whose agent is older than the panel; button «Обновить ноды» (the existing node rollout).<br>(3) **Engine channels with a newer version and a follower** (the existing `channelUpdates` rule): «telemt, канал stable 3.5.13 → 3.5.14»; button «Обновить» (the existing version rollout for that channel).<br>(4) **Each active rollout**: its summary, step x of y and state; buttons «Продолжить», «Пауза», «Отменить», as on the rollout card, plus a link to its details.<br>With nothing to show: «Всё актуально».<br>When the only newer Postern release is a prerelease and prereleases are off: a line «Есть предварительная версия vX» with the button «Разрешить пререлизы». It turns the setting on through the existing release-source RPC, keeping the source and the tokens as they are, and refetches. |
| Tab «Движки и выходы» | `/versions` | The component cards (`ComponentCard`) of the engines and providers. |
| Tab «Ноды» | `/versions/nodes` | `NodeVersionsTable`. |
| Tab «История раскаток» | `/versions/history` | The rollouts list (active and recent). |
| Tab «Настройки» | `/versions/settings` | The default channel select, the panel's own details (running version, image version, kit signed, last update: what `PanelUpdateCard` shows today, without its update button now on top), `ReleaseSourceForm`, and the bundle upload. |

## Global Constraints

- Commit author is `urbnywrt <14278436+urbnywrt@users.noreply.github.com>`. No trailer lines of any kind, never `--no-verify`.
- UI strings go into `web/src/i18n/ru.json` and `en.json`, with key parity. Russian is short and plain.
- Rename the prerelease checkbox to «Предлагать предварительные версии (rc)» / "Offer prereleases (rc)", with a hint that it covers the panel, the nodes and the latest channel of the engines.
- Tests must be robust on slow CI runners: use `findBy*`/`waitFor`; the async timeout is 5 s and the test timeout 15 s.
- No new dependency, no new RPC.

---

### Task 1: the versions page with updates on top

**Files:**
- Modify: `web/src/pages/Versions.tsx` (split it; new files under `web/src/pages/versions/` are welcome), `web/src/app/router.tsx` (nested routes; an unknown child goes to `/versions`), `web/src/components/PanelUpdateCard.tsx` (split it into the details and the update action), `web/src/components/ReleaseSourceForm.tsx` (label), the header badge (`web/src/pages/Overview.tsx` has the engines' «Доступно обновление…» badge; add a Postern one next to it, or in the app shell if that is where such badges live), the i18n files, and the tests.

**Requirements:**
- [ ] **Layout and content exactly per the Spec table.** The updates block shows only actionable lines; its data comes from the hooks the page already uses:
  - the panel version info: `canUpdate`, `releases`, `cannotUpdateReason`;
  - the components with `followedChannels` and the existing `channelUpdates`;
  - the nodes' agent versions against the panel's version, using `compareVersions` in `web/src/app/node.ts`;
  - the rollouts.
- [ ] **Panel line.**
  - When `canUpdate` is false with a reason, show the reason in the line instead of the button.
  - The confirmation and restart notice behave as today.
- [ ] **«Разрешить пререлизы».**
  - It shows only when Postern has a newer prerelease and the setting is off. That needs the panel version info to tell about prereleases that are hidden: check what `GetPanelVersion` returns.
  - If the API cannot tell a hidden prerelease, use the releases the page can see. If none can see it, show the line from the newest release the release feed lists, and say in the report what you used.
  - Do not add an RPC. If no existing data can tell it, show a static hint «Предварительные версии выключены: Версии → Настройки» whenever the setting is off and Postern is up to date, and say so in the report.
- [ ] **Header badge «Доступно обновление Postern»** when the panel or the nodes can be updated. It links to `/versions`.
- [ ] **Tabs** bound to nested routes. Back and forward work, and deep links work.
- [ ] **Phone width:** the update lines wrap, and the tab list scrolls.
- [ ] **Tests:**
  - each tab route renders its parts;
  - the updates block for each line type, its "all up to date" state, the prerelease offer turning the setting on, and the active-rollout controls;
  - the badge on and off;
  - the renamed checkbox;
  - the tests of the old page are adjusted, not dropped.
- [ ] `npm run lint`, `npm run typecheck` and the full `npm test` pass in `web/`.
- [ ] **Commit:** `feat(web): the versions page with what can be updated on top`.
