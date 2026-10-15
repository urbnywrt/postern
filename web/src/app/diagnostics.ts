import { Code, ConnectError } from "@connectrpc/connect";
import type { TFunction } from "i18next";

import type { CheckResult, DiagnosticRun, Problem } from "../gen/postern/panel/v1/diagnostics_pb";

/**
 * The layers of the checks, in the order in which a client's connection goes
 * through them: the panel's view first, then the host, the listener, the engine,
 * the egress, the WEB front, and the whole path end to end.
 */
export const LAYERS = ["panel", "host", "ingress", "engine", "egress", "web", "e2e"] as const;
export type Layer = (typeof LAYERS)[number];

export const STATUSES = ["ok", "warn", "fail", "skip"] as const;
export type CheckStatus = (typeof STATUSES)[number];

export function isLayer(value: string): value is Layer {
  return (LAYERS as readonly string[]).includes(value);
}

export function isStatus(value: string): value is CheckStatus {
  return (STATUSES as readonly string[]).includes(value);
}

export type StatusCounts = Record<CheckStatus, number>;


/** The counts that the panel gives with a run, also in ListRuns, where the results are left out. */
export function runCounts(run: Pick<DiagnosticRun, "okCount" | "warnCount" | "failCount" | "skipCount">): StatusCounts {
  return { ok: run.okCount, warn: run.warnCount, fail: run.failCount, skip: run.skipCount };
}

export interface LayerGroup<T> {
  /** One of LAYERS, or a layer of a newer panel, shown after them as it is. */
  layer: string;
  results: T[];
}

/** The results by layer, in the order of LAYERS; within a layer in the order given. */
export function groupByLayer<T extends Pick<CheckResult, "layer">>(results: readonly T[]): LayerGroup<T>[] {
  const groups = new Map<string, T[]>();
  for (const result of results) {
    const group = groups.get(result.layer);
    if (group === undefined) {
      groups.set(result.layer, [result]);
    } else {
      group.push(result);
    }
  }
  const rank = (layer: string) => (isLayer(layer) ? LAYERS.indexOf(layer) : LAYERS.length);
  return [...groups.entries()]
    .map(([layer, list]) => ({ layer, results: list }))
    .sort((a, b) => rank(a.layer) - rank(b.layer) || a.layer.localeCompare(b.layer));
}

/** A run that is still going: GetRun is asked again until it is not. */
export function isRunning(run: Pick<DiagnosticRun, "state"> | undefined): boolean {
  return run?.state === "running";
}

/** How often a run in progress is asked for. */
export const RUN_POLL_MS = 1_000;

/** A result that a fix is for: warn or fail, with a fix named. */
export function offersFix(result: Pick<CheckResult, "status" | "fix">): boolean {
  return result.fix !== "" && (result.status === "warn" || result.status === "fail");
}

export interface RunPair {
  run: DiagnosticRun;
  /** The before-run that this after-run is compared with, when it is in the list. */
  before?: DiagnosticRun;
}

/** Each run with the before-run that it is related to. */
export function pairRuns(runs: readonly DiagnosticRun[]): RunPair[] {
  const byId = new Map(runs.map((run) => [run.id, run]));
  return runs.map((run) => {
    const before = run.relatedRunId === "" ? undefined : byId.get(run.relatedRunId);
    return before === undefined ? { run } : { run, before };
  });
}

/**
 * The runs of a saved change: its before-run, whose id the panel answered the
 * save with, and the after-run related to it, once the panel has started it.
 * Either is left out while it is not in `runs`.
 */
export function findChangeRuns(
  runs: readonly DiagnosticRun[],
  beforeRunId: string,
): { before?: DiagnosticRun; after?: DiagnosticRun } {
  if (beforeRunId === "") {
    return {};
  }
  const before = runs.find((run) => run.id === beforeRunId);
  const after = runs.find((run) => run.reason === "after_change" && run.relatedRunId === beforeRunId);
  return { ...(before === undefined ? {} : { before }), ...(after === undefined ? {} : { after }) };
}

/** The fixes that the panel knows, and the text of what each changes. */
export const FIXES = {
  recreate_instance: "insights.diagnostics.fix.effect.recreate_instance",
  roll_edge: "insights.diagnostics.fix.effect.roll_edge",
  change_egress: "insights.diagnostics.fix.effect.change_egress",
  refresh_subscription: "insights.diagnostics.fix.effect.refresh_subscription",
  set_dns_mode_doh: "insights.diagnostics.fix.effect.set_dns_mode_doh",
  reissue_cert: "insights.diagnostics.fix.effect.reissue_cert",
} as const;
export type FixName = keyof typeof FIXES;

export function isFix(value: string): value is FixName {
  return Object.hasOwn(FIXES, value);
}

/** The name of a fix, for its button and its confirmation; one of a newer panel as it is. */
export function fixName(t: TFunction, fix: string): string {
  return isFix(fix) ? t(`insights.diagnostics.fix.name.${fix}`) : fix;
}

const RUN_REASONS = ["manual", "before_change", "after_change"] as const;

/** Why a run was made: by hand, before a change or after it. */
export function runReason(t: TFunction, reason: string): string {
  return (RUN_REASONS as readonly string[]).includes(reason)
    ? t(`insights.diagnostics.reason.${reason as (typeof RUN_REASONS)[number]}`)
    : reason;
}

/** The fixes that go with a confirmation of their own besides what they change. */
export const FIX_AFTERWARDS: Partial<
  Record<FixName, "insights.diagnostics.fix.afterwards.roll_edge" | "insights.diagnostics.fix.afterwards.reissue_cert">
> = {
  roll_edge: "insights.diagnostics.fix.afterwards.roll_edge",
  reissue_cert: "insights.diagnostics.fix.afterwards.reissue_cert",
};

/** The checks that have a name and a description of their own, by their id; the others are shown by their id. */
const CHECK_TEXTS = {
  "web.cert": "webCert",
  "web.dns": "webDns",
  "web.http2": "webHttp2",
  "web.decoy": "webDecoy",
  "web.base_path": "webBasePath",
} as const;

/** The name and the description of a check, when this version has them. */
export function checkText(t: TFunction, id: string): { label: string; description: string } | undefined {
  if (!Object.hasOwn(CHECK_TEXTS, id)) {
    return undefined;
  }
  const key = CHECK_TEXTS[id as keyof typeof CHECK_TEXTS];
  return { label: t(`insights.diagnostics.check.${key}.label`), description: t(`insights.diagnostics.check.${key}.description`) };
}

export type FixRefusal =
  /** The check no longer offers the fix: the admin runs the checks again. */
  | { kind: "stale"; message: string }
  /** This panel cannot apply the fix (UNIMPLEMENTED: a panel without the fixes, or one older than the fix). */
  | { kind: "unavailable"; message: string }
  /** The panel refused the fix, and says why (a node without the capability, a chain it cannot use). */
  | { kind: "refused"; message: string }
  /** Anything else: the message of errorMessage. */
  | { kind: "failed" };

/** What an ApplyFix error means for the dialog. */
export function fixRefusal(error: unknown): FixRefusal {
  if (!(error instanceof ConnectError)) {
    return { kind: "failed" };
  }
  const message = error.rawMessage;
  if (error.code === Code.Unimplemented) {
    return { kind: "unavailable", message };
  }
  if (error.code === Code.FailedPrecondition) {
    return /\bstale\b|run diagnostics again/i.test(message) ? { kind: "stale", message } : { kind: "refused", message };
  }
  if (error.code === Code.InvalidArgument) {
    return { kind: "refused", message };
  }
  return { kind: "failed" };
}

/** The id of the proxy of a target "proxy:<id>", else "". */
export function proxyOfTarget(target: string): string {
  return target.startsWith("proxy:") ? target.slice("proxy:".length) : "";
}

/** The scope of a run for a node, or for one of its proxies. */
export function scopeOf(proxyId: string | undefined): string {
  return proxyId === undefined || proxyId === "" ? "node" : `proxy:${proxyId}`;
}

/** Where a problem is seen: the page of its proxy, the diagnostics of its node, or the settings for one of the panel. */
export function problemLink(problem: Pick<Problem, "nodeId" | "proxyId">): string {
  if (problem.proxyId !== "") {
    return `/proxies/${encodeURIComponent(problem.proxyId)}`;
  }
  if (problem.nodeId !== "") {
    return `/nodes/${encodeURIComponent(problem.nodeId)}/diagnostics`;
  }
  return "/settings";
}

/** The diagnostics of a node, opening one of its runs. Run ids are not secrets. */
export function runLink(nodeId: string, runId: string): string {
  return `/nodes/${encodeURIComponent(nodeId)}/diagnostics?run=${encodeURIComponent(runId)}`;
}

export const JOURNAL_SOURCES = ["events", "audit"] as const;
export type JournalSource = (typeof JOURNAL_SOURCES)[number];

export const JOURNAL_PERIODS = ["all", "24h", "7d", "30d"] as const;
export type JournalPeriod = (typeof JOURNAL_PERIODS)[number];
const PERIOD_SECONDS: Record<Exclude<JournalPeriod, "all">, number> = { "24h": 86_400, "7d": 7 * 86_400, "30d": 30 * 86_400 };

export interface JournalFilter {
  source: JournalSource;
  period: JournalPeriod;
  /** Events: of this node and of this proxy; "" for all. */
  nodeId: string;
  proxyId: string;
  /** Events: "" for all, else "info", "warning" or "error" and worse. */
  minSeverity: string;
  /** Events: the kinds that begin with this. */
  kindPrefix: string;
  /** Audit: the actions that begin with this. */
  actionPrefix: string;
}

export const EMPTY_JOURNAL_FILTER: JournalFilter = {
  source: "events",
  period: "all",
  nodeId: "",
  proxyId: "",
  minSeverity: "",
  kindPrefix: "",
  actionPrefix: "",
};

/**
 * The request of a page of the journal for a filter. The panel refuses a filter
 * of the other source, so only those of the source asked are sent; the period
 * starts `period` before `nowUnix` (taken when the filter is applied).
 */
export function journalRequest(filter: JournalFilter, nowUnix: number, cursor: string) {
  const fromUnix = filter.period === "all" ? 0n : BigInt(nowUnix - PERIOD_SECONDS[filter.period]);
  const common = { source: filter.source, fromUnix, toUnix: 0n, cursor, limit: 50 };
  if (filter.source === "audit") {
    return { ...common, actionPrefix: filter.actionPrefix.trim() };
  }
  return {
    ...common,
    nodeId: filter.nodeId,
    proxyId: filter.proxyId,
    minSeverity: filter.minSeverity,
    kindPrefix: filter.kindPrefix.trim(),
  };
}

/** The class of the result of a probe: through to a datacenter, only to the proxy (L1), or not at all. */
export type ProbeClass = "ok" | "l1" | "failed";

export function probeClass(result: { ok: boolean; l1Ok?: boolean }): ProbeClass {
  if (result.ok) {
    return "ok";
  }
  return result.l1Ok === true ? "l1" : "failed";
}
