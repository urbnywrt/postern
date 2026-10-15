import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import {
  type ApplyFixRequest,
  type CheckResult,
  CheckResultSchema,
  type DiagnosticRun,
  DiagnosticRunSchema,
  type GetRunRequest,
  type HideProblemRequest,
  type JournalAuditSchema,
  type JournalEventSchema,
  type LatestChecksRequest,
  type ListJournalRequest,
  type ListProblemsRequest,
  type ListRunsRequest,
  type ProblemSchema,
  type StartRunRequest,
  type UnhideProblemRequest,
} from "../gen/postern/panel/v1/diagnostics_pb";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";

export type CheckInit = MessageInitShape<typeof CheckResultSchema>;
export type RunInit = MessageInitShape<typeof DiagnosticRunSchema>;

/** The message of the panel for a fix whose check no longer offers it. */
export const STALE_FIX = "this fix is stale: engine.ready of proxy:proxy-1 no longer offers recreate_instance; run diagnostics again";

const now = () => Math.floor(Date.now() / 1000);

/** The key of a problem of the feed: its own, or one made of what names it. */
const problemKey = (problem: MessageInitShape<typeof ProblemSchema>) =>
  problem.key ?? [problem.kind, problem.nodeId, problem.proxyId, problem.checkId, problem.target].map((part) => part ?? "").join("|");

function handler<Request, Response>(impl: (req: Request) => Response) {
  return vi.fn<(req: Request) => Response | Promise<Response>>(impl);
}

/** A run with the counts of its results, as the panel gives them; one without results keeps those it has. */
function withCounts(run: DiagnosticRun): DiagnosticRun {
  if (run.results.length === 0) return run;
  const count = (status: string) => run.results.filter((result) => result.status === status).length;
  return create(DiagnosticRunSchema, { ...run, okCount: count("ok"), warnCount: count("warn"), failCount: count("fail"), skipCount: count("skip") });
}

/** Whether a result belongs to the scope of a proxy: the host checks, the proxy's own, and its members and listener (here: all but other proxies). */
const inProxyScope = (result: CheckResult, proxyId: string) =>
  !result.target.startsWith("proxy:") || result.target === `proxy:${proxyId}`;

/**
 * DiagnosticsService over the nodes and proxies of the inventory. `latest` has
 * the light checks of each node, `runs` every run with its results (newest
 * last). StartRun makes a run that stays "running" until a test calls
 * `finishRun`. GetRun and ListRuns give the counts of the results. ApplyFix
 * refuses as the panel does: a fix that the current results (or, with no
 * offered run, a problem of the feed: panel.versions of edge.outdated) no
 * longer offer is stale, and an unavailable one is refused with its reason.
 */
export function createFakeDiagnostics(requireSession: () => void, inventory: { nodes: Node[]; proxies: Proxy[] }) {
  const state = {
    latest: new Map<string, CheckResult[]>(),
    runs: [] as DiagnosticRun[],
    problems: [] as MessageInitShape<typeof ProblemSchema>[],
    /** When each hidden problem was hidden, by its key. */
    hidden: new Map<string, bigint>(),
    events: [] as MessageInitShape<typeof JournalEventSchema>[],
    audit: [] as MessageInitShape<typeof JournalAuditSchema>[],
    nextRun: 1,
    generation: 7n,
    setLatest(nodeId: string, results: CheckInit[]) {
      state.latest.set(
        nodeId,
        results.map((result) => create(CheckResultSchema, result)),
      );
    },
    addRun(init: RunInit) {
      const run = create(DiagnosticRunSchema, { state: "done", scope: "node", reason: "manual", startedUnix: BigInt(now()), ...init });
      state.runs.push(run);
      return run;
    },
    finishRun(id: string, { state: end = "done", results = [], regressed = false }: { state?: string; results?: CheckInit[]; regressed?: boolean } = {}) {
      const run = state.runs.find((entry) => entry.id === id);
      if (run === undefined) throw new Error(`no run ${id}`);
      run.state = end;
      run.results = results.map((result) => create(CheckResultSchema, result));
      run.finishedUnix = BigInt(now());
      run.regressed = regressed;
    },
  };

  const findNode = (id: string) => {
    const node = inventory.nodes.find((entry) => entry.id === id);
    if (node === undefined) throw new ConnectError("no such node", Code.NotFound);
    return node;
  };
  const findProxy = (id: string) => {
    const proxy = inventory.proxies.find((entry) => entry.id === id);
    if (proxy === undefined) throw new ConnectError("no such proxy", Code.NotFound);
    return proxy;
  };
  const failing = (status: string) => status === "warn" || status === "fail";

  const rpc = {
    startRun: handler((req: StartRunRequest) => {
      requireSession();
      findNode(req.nodeId);
      const going = state.runs.find((run) => run.nodeId === req.nodeId && run.state === "running");
      if (going !== undefined) return { runId: going.id };
      const run = state.addRun({ id: `run-${String(state.nextRun++)}`, nodeId: req.nodeId, scope: req.scope || "node", state: "running" });
      return { runId: run.id };
    }),

    getRun: handler((req: GetRunRequest) => {
      requireSession();
      const run = state.runs.find((entry) => entry.id === req.runId);
      if (run === undefined) throw new ConnectError("no such run", Code.NotFound);
      return withCounts(run);
    }),

    listRuns: handler((req: ListRunsRequest) => {
      requireSession();
      let runs: DiagnosticRun[];
      if (req.proxyId !== "") {
        const proxy = findProxy(req.proxyId);
        runs = state.runs.filter((run) => run.nodeId === proxy.nodeId && (run.scope === "node" || run.scope === `proxy:${proxy.id}`));
      } else {
        findNode(req.nodeId);
        runs = state.runs.filter((run) => run.nodeId === req.nodeId);
      }
      return { runs: [...runs].reverse().map((run) => create(DiagnosticRunSchema, { ...withCounts(run), results: [] })) };
    }),

    latestChecks: handler((req: LatestChecksRequest) => {
      requireSession();
      if (req.proxyId !== "") {
        const proxy = findProxy(req.proxyId);
        return { results: (state.latest.get(proxy.nodeId) ?? []).filter((result) => inProxyScope(result, proxy.id)) };
      }
      findNode(req.nodeId);
      return { results: state.latest.get(req.nodeId) ?? [] };
    }),

    applyFix: handler((req: ApplyFixRequest) => {
      requireSession();
      findNode(req.nodeId);
      if (req.checkId === "" || req.fix === "") throw new ConnectError("check_id and fix are required", Code.InvalidArgument);
      const same = (result: CheckResult) => result.id === req.checkId && result.target === req.target;
      const light = (state.latest.get(req.nodeId) ?? []).find(same);
      // The panel's own panel.versions is offered by the feed (edge.outdated), with no light check.
      const fromFeed = state.problems.find(
        (problem) => problem.nodeId === req.nodeId && problem.checkId === req.checkId && (problem.target ?? "") === req.target,
      );
      const offeredByFeed =
        fromFeed === undefined
          ? undefined
          : create(CheckResultSchema, {
              id: req.checkId,
              target: req.target,
              status: "warn",
              fix: fromFeed.fix ?? "",
              fixAvailable: fromFeed.fixAvailable ?? false,
              fixUnavailableReason: fromFeed.fixUnavailableReason ?? "",
            });
      const source =
        req.offeredRunId === ""
          ? (light ?? (req.checkId === "panel.versions" ? offeredByFeed : undefined))
          : state.runs.find((run) => run.id === req.offeredRunId)?.results.find(same);
      if (source === undefined) {
        throw new ConnectError(STALE_FIX, Code.FailedPrecondition);
      }
      if (source.fix !== req.fix) {
        throw new ConnectError(STALE_FIX, Code.FailedPrecondition);
      }
      if (!source.fixAvailable) {
        throw new ConnectError(source.fixUnavailableReason, Code.FailedPrecondition);
      }
      // The light checks are newer than the run: a check that passes now has nothing to fix.
      if (light !== undefined && !failing(light.status)) {
        throw new ConnectError(STALE_FIX, Code.FailedPrecondition);
      }
      if (req.fix === "change_egress" && req.chainId === "") {
        throw new ConnectError("change_egress needs a chain", Code.InvalidArgument);
      }
      state.generation += 1n;
      const before =
        req.offeredRunId !== ""
          ? req.offeredRunId
          : state.addRun({ id: `run-${String(state.nextRun++)}`, nodeId: req.nodeId, reason: "before_change", change: `fix ${req.fix}` }).id;
      return { beforeRunId: before, generation: state.generation };
    }),

    listProblems: handler((req: ListProblemsRequest) => {
      requireSession();
      return {
        problems: state.problems
          .filter((problem) => (req.nodeId === "" || problem.nodeId === req.nodeId) && (req.proxyId === "" || problem.proxyId === req.proxyId))
          .map((problem) => {
            const key = problemKey(problem);
            const hiddenAt = state.hidden.get(key);
            return { ...problem, key, hidden: hiddenAt !== undefined, hiddenAtUnix: hiddenAt ?? 0n };
          })
          .filter((problem) => req.includeHidden || !problem.hidden),
      };
    }),

    hideProblem: handler((req: HideProblemRequest) => {
      requireSession();
      if (!state.problems.some((problem) => problemKey(problem) === req.key)) throw new ConnectError("the problem: not found", Code.NotFound);
      state.hidden.set(req.key, BigInt(now()));
      return {};
    }),

    unhideProblem: handler((req: UnhideProblemRequest) => {
      requireSession();
      state.hidden.delete(req.key);
      return {};
    }),

    listJournal: handler((req: ListJournalRequest) => {
      requireSession();
      const audit = req.source === "audit";
      if (audit && (req.nodeId !== "" || req.proxyId !== "" || req.minSeverity !== "" || req.kindPrefix !== "")) {
        throw new ConnectError("a filter of the events in a request of the audit log", Code.InvalidArgument);
      }
      if (!audit && (req.adminId !== "" || req.actionPrefix !== "")) {
        throw new ConnectError("a filter of the audit log in a request of the events", Code.InvalidArgument);
      }
      const rank = (severity: string | undefined) => (severity === "error" ? 2 : severity === "warning" || severity === "warn" ? 1 : 0);
      const inTime = (ts: bigint | undefined) => (ts ?? 0n) >= req.fromUnix && (req.toUnix === 0n || (ts ?? 0n) < req.toUnix);
      const rows: { tsUnix?: bigint }[] = audit
        ? state.audit.filter((entry) => inTime(entry.tsUnix) && (entry.action ?? "").startsWith(req.actionPrefix))
        : state.events.filter(
            (event) =>
              inTime(event.tsUnix) &&
              (req.nodeId === "" || event.nodeId === req.nodeId) &&
              (req.proxyId === "" || event.proxyId === req.proxyId) &&
              rank(event.severity) >= rank(req.minSeverity) &&
              (event.kind ?? "").startsWith(req.kindPrefix),
          );
      const limit = req.limit === 0 ? 50 : req.limit;
      const start = req.cursor === "" ? 0 : Number(req.cursor);
      const page = rows.slice(start, start + limit);
      const nextCursor = start + limit < rows.length ? String(start + limit) : "";
      return audit ? { audit: page, nextCursor } : { events: page, nextCursor };
    }),
  };

  return { rpc, state };
}
