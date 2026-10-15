# Owner feedback 1: middle-proxy alert, empty-channel updates, hiding problems — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the three things the owner hit on the live panel (2026-10-11):
- a warning that stayed for three days and could not be dismissed;
- a telemt update the UI offered but refused;
- no way to hide a problem.

**Architecture:** three independent tasks.
1. The node's `engine.dcs` check judges a datacenter by the writers' coverage, not by how many of its endpoints currently hold a writer.
2. A version rollout of a channel that no proxy follows moves the channel at once instead of refusing, and the "update available" badge counts only the channels that some proxy follows.
3. The problem feed of the panel gets "hide until it changes": a hidden problem comes back when its status or summary changes, or when it clears and appears again. This reverses Ruling S6-5 at the owner's request.

**Tech Stack:** Go 1.27, SQLite (panel store migrations), ConnectRPC protos (buf), React 19 + Mantine 8 + TanStack Query + react-i18next.

**Spec:** this plan is its own spec; it amends `docs/design/2026-10-04-postern-design.md` §5.7 (diagnostics: `engine.dcs`), §5.9 (versions and rollouts) and §8.3 (problem feed).

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply: Go in WSL, commits without trailers, documentation addresses only, `log/slog`, no secrets in logs.
- Commit author is `urbnywrt <14278436+urbnywrt@users.noreply.github.com>`. No trailer lines of any kind, never `--no-verify`.
- Proto fields and migrations take the next free number on the branch. The store is at `0018`, so the next migration is `0019`. Regenerate Go with `bash scripts/gen.sh` and TS with `npm run gen` in `web/`.
- UI strings go into `web/src/i18n/ru.json` and `en.json` with key parity. Russian is short and plain.
- Tests must be robust on slow CI runners: poll with a deadline, never assert right after an async action.

---

### Task 1: `engine.dcs` judges coverage

**Files:**
- Modify: `internal/node/diag/engine.go`, the function `DCsResult` and its doc comment, with tests.
- Modify, if they state the old rule: the checks catalogue in `docs/diagnostics.md`.

**Evidence from the live node.** telemt 3.5.13 `GET /v1/stats/dcs`:
- Every DC had `coverage_pct` 100 and `fresh_coverage_pct` 100, and `alive_writers` equal to `required_writers`.
- Some DCs had `available_pct` 50 or 70, because some endpoints had `active_writers` 0. For example, a DC with 2 endpoints and 3 required writers keeps 3 writers on one endpoint and 0 on the other.
- `available_pct` is the share of endpoints that hold a writer, not reachability. The old rule warned whenever `available_pct` was below 100, so it warned on a healthy engine.

**Requirements:**
- [ ] **Status comes from coverage.** Use `CoveragePct`, and `FreshCoveragePct` when the parser exposes it. Check `ParseDCs` in `internal/engines/telemt/health.go` and `engines.EngineHealth`. If the fresh coverage is not parsed yet, add it to the parser and the struct with tests, keeping old answers readable.
  - **OK:** every DC is at 100 % coverage. Summary: `the middle proxies of all N datacenters are covered`.
  - **Fail:** every DC is at 0 % coverage. Summary: `no middle proxy of any datacenter is available`.
  - **Warn:** anything between. Summary: `some datacenters are not fully covered`.
  - Endpoint availability never changes the status. The evidence still lists each DC (`DC n: x endpoints in use (y %), writers z % covered`) for warn and fail, and the hint stays `hintEgressME`.
- [ ] **Off or no snapshot stays Skip,** exactly as today.
- [ ] **Tests:**
  - the live shape above, with endpoints idle and full coverage, gives OK;
  - partial coverage in one DC gives Warn;
  - zero coverage everywhere gives Fail;
  - off gives Skip.
- [ ] **Commit:** `fix(node): engine.dcs judges the coverage of the writers, not the endpoints that hold one`.

---

### Task 2: an empty channel moves at once; the badge counts followed channels only

**Files:**
- Modify: `internal/panel/rollout/engines.go`, where it now refuses with "no proxy follows the %s channel of %s", with tests.
- Modify: wherever the panel computes "update available" for the header badge. Find it from the i18n key `updateAvailable` in `web/src/i18n/ru.json` and its component, and from the RPC that feeds it.
- Possibly modify: the versions page, so the "Обновить {channel} до {version}" button tells the truth.

**Requirements:**
- [ ] **A version rollout of a channel with no follower moves the channel.** Follower means the same filter as today: proxies whose node channel, or the panel's default channel, is that channel, whose engine is the component, and whose policy is `channel`.
  - Instead of refusing, the channel version of the component is set to the target version: the same store write that a completed rollout makes.
  - The rollout is recorded as `completed` with zero steps, if the store and the UI handle such a rollout cleanly; otherwise as an audited channel move without a rollout row. Pick one, say which, and make the UI show the result: the channel at the new version, and no error.
  - All other validation still applies: the version is in the channel's candidates, the channel is not already at it, and the other refusals stay.
  - Audit as today (`versions.rollout.start`, result ok).
- [ ] **The badge "Доступно обновление в {channel}: {components}"** counts a component and channel only when at least one proxy follows that channel for that component and a newer version is offered there. With no follower, there is no badge. The versions page still shows the newest versions.
- [ ] **Tests:**
  - a rollout with no follower moves the channel and leaves no running rollout;
  - with a follower, the behaviour is unchanged;
  - the badge with and without followers;
  - UI tests for the badge and the versions button.
- [ ] **Commit(s):** `fix(versions): a channel that no proxy follows moves at once`, `fix(web): the update badge counts the channels that proxies follow`.

---

### Task 3: hide a problem until it changes

**Files:**
- Create: `internal/panel/store/migrations/0019_problem_hides.sql`, with store methods and tests.
- Modify: `internal/panel/diagnostics/problems.go`, `service.go`, `proto/postern/panel/v1/diagnostics.proto`, the generated code, and the web problem feed component, which you find from the "Проблемы" section of the overview page. Add i18n keys and tests.

**Requirements:**
- [ ] **What a hide is.** A row `(problem key, fingerprint, hidden_at, admin_id)`.
  - The key identifies the problem across refreshes: its source, node, check id or kind, and target.
  - The fingerprint is a hash of the status and the summary at the time of hiding.
- [ ] **When a problem is hidden.** `ListProblems` leaves it out by default, or marks it hidden; choose what fits the existing API. It stays hidden while its current fingerprint equals the stored one.
- [ ] **When it comes back.** A changed status or summary shows the problem again and deletes the hide. A problem that clears loses its hide too, so if it reappears later it shows. Garbage-collect hides whose problem no longer exists.
- [ ] **RPCs** on `DiagnosticsService`: `HideProblem(key)` and `UnhideProblem(key)`.
  - Admin only, audited as `problem.hide` and `problem.unhide`.
  - Message caps as the other procedures, which the procedure and limit tests enforce.
- [ ] **UI.** Each problem gets a small "Скрыть" action. Under the feed, a "Скрытые: N" toggle shows the hidden ones, each with "Показать".
  - The overview's problem count and badges count visible problems only.
  - Russian: "Скрыть", "Показать", "Скрыто до изменения", "Скрытые: {{count}}".
- [ ] **Tests:**
  - store: hide, fingerprint match, change brings it back, clear deletes the hide;
  - service: hide and unhide, audit, admin check;
  - web: hide moves the item to the hidden list, the toggle, and the count.
- [ ] **Commit(s):** `feat(diagnostics): hide a problem until it changes`, `feat(web): hide problems in the feed`.
