# Owner feedback 2: no warning from a one-off blip — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a light check of the node must not raise a warning or a failure over a single bad run. The owner saw "DNS over HTTPS does not answer" on node L. One run of `host.dns`, at 17:24 while the agent restarted and the edge rolled, found Cloudflare's DoH silent. Five minutes later DoH answered in 0.1 s, but the warning stayed for the check's whole 10-minute cadence. The DoH probe of the check had also given up after the two Cloudflare endpoints, never asking Google.

**Architecture:** both changes are in the node's diagnostics (`internal/node/diag`).
1. **Confirm a worsening.** A light result whose status is worse than the last reported one for the same check and target is held. The check runs again for that unit about 60 s later, sooner than its cadence. The worse status is reported only when that rerun confirms it, as the better of the two worse statuses. Recovery is reported at once, as now.
2. **Probe every DoH endpoint.** The `host.dns` DoH probe asks every DoH endpoint within the check's timeout, with a short timeout for each, so that a silent Cloudflare does not hide a Google that answers.

**Tech Stack:** Go 1.27.

**Spec:** amends `docs/design/2026-10-04-postern-design.md` §5.7, the light-check hysteresis. This plan is the spec for the change.

## Global Constraints

- All Global Constraints of `docs/plans/2026-10-04-slices-0-1.md` apply: Go in WSL, documentation addresses only, `log/slog`, no secrets in logs.
- Commit author is `urbnywrt <14278436+urbnywrt@users.noreply.github.com>`. No trailer lines of any kind, never `--no-verify`.
- Tests are deterministic: inject the clock and the scheduler's timers, and never sleep for real. They must pass on slow CI runners.

---

### Task 1: confirm a worsening; probe every DoH endpoint

**Files:**
- Modify: `internal/node/diag/light.go` (the light set and its hysteresis) and `internal/node/diag/schedule.go` (the light scheduler), with their tests.
- Modify: `internal/node/diag/host.go` (`checkDNS`), possibly the DoH client it uses (find it from `env.DoH`), with tests.
- Modify: `docs/diagnostics.md`, the section on light checks and the `host.dns` row.

**Requirements:**
- [ ] **Confirmation, for every light check.**
  - When a unit's run gives a result whose status is worse than the last reported status of the same `(check id, target)` (order: ok/skip < warn < fail), the new result is not reported yet. The unit keeps its last reported results for that key, and the scheduler runs the unit again `confirmAfter` = 60 s later, or at its normal cadence if that is sooner.
  - The confirming run reports the better of the two worse statuses, with the newer run's summary, evidence and hint, if it is still worse than the last reported status. If it is not worse, nothing worse is reported and the streak resets.
  - A result for a key that had no reported status yet is reported at once: the first run after a start has nothing to confirm against.
  - The existing rule ("a 60-s check reports fail only after two failing runs in a row; one failing run is warn; recovery at once") must keep holding for 60-s checks. Fold it into the new rule if the two coincide, and say how in the report.
  - Recovery (a better status) is reported at once, as now.
  - The full runs (`RunDiagnostics`, scope node or proxy) are not affected: they report what they find.
- [ ] **The `host.dns` DoH probe asks every configured DoH endpoint** (by default `https://1.1.1.1/dns-query`, `https://1.0.0.1/dns-query`, `https://8.8.8.8/dns-query`, `https://8.8.4.4/dns-query`).
  - Each endpoint gets its own timeout (≈ 3 s), and the endpoints are tried in parallel or in sequence so that all four fit inside the check's `SlowTimeout`.
  - The first good answer wins.
  - The evidence lists the error of each endpoint that failed. If any endpoint answered, the result is not "DNS over HTTPS does not answer".
  - The DoH client of the edge's forwarder keeps its own behaviour, unless it shares the code and the change is an improvement there too; say which.
- [ ] **Tests:**
  - a single bad run followed by a good one reports nothing worse, and the rerun is scheduled at 60 s;
  - two bad runs report the worse status, as the better of the two;
  - recovery is reported at once;
  - a fresh start with a bad first run reports at once;
  - 60-s checks still pass the old hysteresis tests, adjusted only where the rule was folded;
  - `checkDNS` with Cloudflare silent and Google answering is OK, with the Cloudflare errors in the evidence;
  - all four silent gives Warn, with four errors in the evidence.
- [ ] **Commit(s):** `fix(node): a light check reports a worsening once a rerun confirms it`, `fix(node): host.dns asks every DoH endpoint`.
