import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { isRunning, type JournalFilter, journalRequest, RUN_POLL_MS } from "../../app/diagnostics";
import { DiagnosticsService, type ListRunsResponse } from "../../gen/postern/panel/v1/diagnostics_pb";
import { useClient } from "../client";
import { nodeKeys, proxyKeys, REFRESH_MS } from "./keys";

/** Of a node, or of one of its proxies. */
export interface DiagnosticsTarget {
  nodeId: string;
  proxyId?: string;
}

const ids = ({ nodeId, proxyId }: DiagnosticsTarget) =>
  proxyId === undefined || proxyId === "" ? { nodeId, proxyId: "" } : { nodeId: "", proxyId };

export const diagnosticsKeys = {
  all: ["diagnostics"] as const,
  latest: (target: DiagnosticsTarget) => ["diagnostics", "latest", target.nodeId, target.proxyId ?? ""] as const,
  runs: (target: DiagnosticsTarget) => ["diagnostics", "runs", target.nodeId, target.proxyId ?? ""] as const,
  run: (id: string) => ["diagnostics", "run", id] as const,
  problems: (nodeId: string, proxyId: string, includeHidden = false) => ["diagnostics", "problems", nodeId, proxyId, includeHidden] as const,
  journal: (filter: JournalFilter, nowUnix: number) => ["diagnostics", "journal", filter, nowUnix] as const,
};

// Every query here shows its own error where its data would be (silent).

/** The light checks that the node reported last, of the node or of the scope of one of its proxies. */
export function useLatestChecks(target: DiagnosticsTarget) {
  const diagnostics = useClient(DiagnosticsService);
  return useQuery({
    queryKey: diagnosticsKeys.latest(target),
    queryFn: ({ signal }) => diagnostics.latestChecks(ids(target), { signal }),
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/**
 * The runs of a node, or those that cover a proxy, newest first, without their
 * results. `refetchInterval` may depend on what was got last.
 */
export function useRuns(
  target: DiagnosticsTarget,
  refetchInterval: number | false | ((runs: ListRunsResponse | undefined) => number | false) = REFRESH_MS,
) {
  const diagnostics = useClient(DiagnosticsService);
  return useQuery({
    queryKey: diagnosticsKeys.runs(target),
    queryFn: ({ signal }) => diagnostics.listRuns({ ...ids(target), limit: 20 }, { signal }),
    refetchInterval: typeof refetchInterval === "function" ? (query) => refetchInterval(query.state.data) : refetchInterval,
    meta: { silent: true },
  });
}

/**
 * A run with its results so far. While it is running it is asked for every
 * second; once it is done (or the page that shows it is gone) it is not.
 */
export function useRun(runId: string) {
  const diagnostics = useClient(DiagnosticsService);
  return useQuery({
    queryKey: diagnosticsKeys.run(runId),
    queryFn: ({ signal }) => diagnostics.getRun({ runId }, { signal }),
    enabled: runId !== "",
    refetchInterval: (query) => (query.state.status !== "error" && isRunning(query.state.data) ? RUN_POLL_MS : false),
    meta: { silent: true },
  });
}

/** Starts a full run of a scope of a node, or gets the one in progress. The page says why it failed. */
export function useStartRun() {
  const diagnostics = useClient(DiagnosticsService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (req: { nodeId: string; scope: string }) => diagnostics.startRun(req),
    meta: { silent: true },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["diagnostics", "runs"] });
    },
  });
}

export interface ApplyFixVars {
  nodeId: string;
  checkId: string;
  target: string;
  fix: string;
  chainId?: string;
  /** The run that offered the fix; "" for the light checks or the problem feed. */
  offeredRunId: string;
}

/** Applies the fix that a result offers. The dialog says why the panel refused it. */
export function useApplyFix() {
  const diagnostics = useClient(DiagnosticsService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: ApplyFixVars) => diagnostics.applyFix({ ...vars, chainId: vars.chainId ?? "" }),
    meta: { silent: true },
    onSuccess: (_answer, vars) => {
      void queryClient.invalidateQueries({ queryKey: diagnosticsKeys.all });
      void queryClient.invalidateQueries({ queryKey: nodeKeys.detail(vars.nodeId) });
      void queryClient.invalidateQueries({ queryKey: proxyKeys.all });
    },
  });
}

/**
 * What is wrong now: across the fleet, or of a node or a proxy. The problems
 * that an admin hid are left out, or with `includeHidden` marked hidden.
 */
export function useProblems({ nodeId = "", proxyId = "", includeHidden = false }: { nodeId?: string; proxyId?: string; includeHidden?: boolean } = {}) {
  const diagnostics = useClient(DiagnosticsService);
  return useQuery({
    queryKey: diagnosticsKeys.problems(nodeId, proxyId, includeHidden),
    queryFn: ({ signal }) => diagnostics.listProblems({ nodeId, proxyId, includeHidden }, { signal }),
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/** Hides a problem of the feed until it changes, or shows it again; the feed is asked again after either. */
export function useProblemHide() {
  const diagnostics = useClient(DiagnosticsService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ key, hide }: { key: string; hide: boolean }) =>
      hide ? diagnostics.hideProblem({ key }).then(() => undefined) : diagnostics.unhideProblem({ key }).then(() => undefined),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["diagnostics", "problems"] }),
  });
}

/**
 * The journal, page by page with the cursor of the panel: events or the audit
 * log, for a filter whose period ends at `nowUnix` (taken when it is applied).
 */
export function useJournal(filter: JournalFilter, nowUnix: number) {
  const diagnostics = useClient(DiagnosticsService);
  return useInfiniteQuery({
    queryKey: diagnosticsKeys.journal(filter, nowUnix),
    queryFn: ({ signal, pageParam }) => diagnostics.listJournal(journalRequest(filter, nowUnix, pageParam), { signal }),
    initialPageParam: "",
    getNextPageParam: (last) => (last.nextCursor === "" ? undefined : last.nextCursor),
    meta: { silent: true },
  });
}
