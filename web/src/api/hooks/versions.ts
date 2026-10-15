import type { MessageInitShape } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type Rollout,
  type StartRolloutRequestSchema,
  type ReleaseSourceSchema,
  VersionService,
} from "../../gen/postern/panel/v1/versions_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { nodeKeys, proxyKeys, REFRESH_MS } from "./keys";

// The catalog of versions, the rollouts and the update of the panel
// (VersionService). A rollout that is active is asked for every ROLLOUT_POLL_MS,
// so that its steps move on the screen; everything else only changes when an
// admin changes it, or at the next check of the release sources.

export const versionKeys = {
  all: ["versions"] as const,
  components: ["versions", "components"] as const,
  releases: (component: string) => ["versions", "releases", component] as const,
  rollouts: ["versions", "rollouts"] as const,
  rollout: (id: string) => ["versions", "rollouts", "detail", id] as const,
  panel: ["versions", "panel"] as const,
  source: ["versions", "source"] as const,
};

/** How often an active rollout is asked for again. */
export const ROLLOUT_POLL_MS = 2_000;

/** The statuses of a rollout that is not over: it holds its channel and its nodes. */
export const ACTIVE_ROLLOUT = ["preparing", "running", "paused", "failed"] as const;

export function isActiveRollout(status: string): boolean {
  return (ACTIVE_ROLLOUT as readonly string[]).includes(status);
}

export function useComponents() {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: versionKeys.components,
    queryFn: ({ signal }) => versions.listComponents({}, { signal }),
    meta: { silent: true },
  });
}

export function useReleases(component: string, { enabled = true }: { enabled?: boolean } = {}) {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: versionKeys.releases(component),
    queryFn: async ({ signal }) => (await versions.listReleases({ component }, { signal })).releases,
    enabled: enabled && component !== "",
    meta: { silent: true },
  });
}

/** Fetches the release list of a component (or of every one, for "") now. The page shows why it cannot ("too soon"). */
export function useRefreshReleases() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (component: string) => versions.refreshReleases({ component }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: versionKeys.all }),
    meta: { silent: true },
  });
}

export function usePrepareRelease() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { component: string; version: string; archs?: string[] }) =>
      present((await versions.prepareRelease({ ...vars, archs: vars.archs ?? [] })).release),
    onSettled: (_data, _error, vars) => queryClient.invalidateQueries({ queryKey: versionKeys.releases(vars.component) }),
    meta: { silent: true },
  });
}

export function useRecheckRelease() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { component: string; version: string; arch: string }) =>
      present((await versions.recheckRelease(vars)).release),
    onSettled: (_data, _error, vars) => queryClient.invalidateQueries({ queryKey: versionKeys.releases(vars.component) }),
    meta: { silent: true },
  });
}

/** What a change of channel touches when it is made: the versions of proxies, and the nodes. */
function useRefreshAfterChannel() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: versionKeys.components }),
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
      queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
    ]);
}

/**
 * Without `confirm` the panel changes nothing and lists the proxies that the
 * change alters (Ruling S5-11); with it, the change is made.
 */
export function useSetDefaultChannel() {
  const versions = useClient(VersionService);
  const refresh = useRefreshAfterChannel();
  return useMutation({
    mutationFn: (vars: { channel: string; confirm: boolean }) => versions.setDefaultChannel(vars),
    onSuccess: async (answer) => {
      if (answer.applied) await refresh();
    },
  });
}

/** As useSetDefaultChannel, for one node; channel "" follows the default of the panel. */
export function useSetNodeChannel() {
  const versions = useClient(VersionService);
  const refresh = useRefreshAfterChannel();
  return useMutation({
    mutationFn: (vars: { nodeId: string; channel: string; confirm: boolean }) => versions.setNodeChannel(vars),
    onSuccess: async (answer) => {
      if (answer.applied) await refresh();
    },
  });
}

export type StartRolloutVars = MessageInitShape<typeof StartRolloutRequestSchema>;

/** Starts a rollout. A refusal (another rollout holds the channel or a node) is shown by the dialog. */
export function useStartRollout() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: StartRolloutVars) => present((await versions.startRollout(vars)).rollout),
    onSuccess: (rollout) => {
      queryClient.setQueryData(versionKeys.rollout(rollout.id), rollout);
      // A channel that nothing follows has moved already (a rollout completed at once).
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: versionKeys.rollouts }),
        queryClient.invalidateQueries({ queryKey: versionKeys.components }),
      ]);
    },
    meta: { silent: true },
  });
}

/** The newest rollouts, asked for every ROLLOUT_POLL_MS while one of them is active. */
export function useRollouts(limit = 20) {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: [...versionKeys.rollouts, "list", limit],
    queryFn: async ({ signal }) => (await versions.listRollouts({ activeOnly: false, limit }, { signal })).rollouts,
    refetchInterval: (query) =>
      query.state.data?.some((rollout) => isActiveRollout(rollout.status)) === true ? ROLLOUT_POLL_MS : REFRESH_MS,
    meta: { silent: true },
  });
}

/** One rollout, asked for every ROLLOUT_POLL_MS while it is active. */
export function useRollout(id: string, initial?: Rollout) {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: versionKeys.rollout(id),
    queryFn: async ({ signal }) => present((await versions.getRollout({ id }, { signal })).rollout),
    initialData: initial,
    // The list carries it already; the poll takes over from there.
    staleTime: ROLLOUT_POLL_MS,
    refetchInterval: (query) => (isActiveRollout(query.state.data?.status ?? "") ? ROLLOUT_POLL_MS : false),
    meta: { silent: true },
  });
}

export type RolloutAction = "continue" | "pause" | "retry" | "abort";

/** Continue, Pause, Retry or Abort. A refusal comes back with the reason of the panel, which the view shows. */
export function useRolloutAction() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, action }: { id: string; action: RolloutAction }) => {
      const call = {
        continue: versions.continueRollout,
        pause: versions.pauseRollout,
        retry: versions.retryRollout,
        abort: versions.abortRollout,
      }[action];
      return present((await call({ id })).rollout);
    },
    onSuccess: (rollout) => {
      queryClient.setQueryData(versionKeys.rollout(rollout.id), rollout);
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: [...versionKeys.rollouts, "list"] }),
        queryClient.invalidateQueries({ queryKey: versionKeys.components }),
      ]);
    },
    meta: { silent: true },
  });
}

export function usePanelVersion() {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: versionKeys.panel,
    queryFn: ({ signal }) => versions.getPanelVersion({}, { signal }),
    meta: { silent: true },
  });
}

export function useUpdatePanel() {
  const versions = useClient(VersionService);
  return useMutation({
    mutationFn: (version: string) => versions.updatePanel({ version }),
    meta: { silent: true },
  });
}

export function useReleaseSource() {
  const versions = useClient(VersionService);
  return useQuery({
    queryKey: versionKeys.source,
    queryFn: async ({ signal }) => present((await versions.getReleaseSource({}, { signal })).source),
    meta: { silent: true },
  });
}

export interface SetReleaseSourceVars {
  source: MessageInitShape<typeof ReleaseSourceSchema>;
  /** Unset keeps the token; "" removes it. */
  token?: string;
  githubToken?: string;
}

export function useSetReleaseSource() {
  const versions = useClient(VersionService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: SetReleaseSourceVars) => present((await versions.setReleaseSource(vars)).source),
    onSuccess: (source) => {
      queryClient.setQueryData(versionKeys.source, source);
      return queryClient.invalidateQueries({ queryKey: versionKeys.components });
    },
  });
}

// ---- the upload of a release bundle (POST /api/releases/upload, not Connect) ----

/** The verdict on one asset of a bundle (selfupdate.AssetResult). */
export interface UploadAsset {
  name: string;
  ok: boolean;
  sha256?: string;
  reason?: string;
}

/** The answer of the upload (selfupdate.UploadResult); 200 when accepted, 422 when refused. */
export interface UploadResult {
  version: string;
  accepted: boolean;
  assets: UploadAsset[];
  ignored?: string[];
  stable?: { applied: boolean; reason?: string };
  error?: string;
}

/** Sends a bundle; `onProgress` gets the share sent so far, 0 to 1. */
export type UploadBundle = (file: File, onProgress: (share: number) => void) => Promise<UploadResult>;

export const UPLOAD_URL = "/api/releases/upload";

/**
 * The upload through XMLHttpRequest, which reports the progress of a request
 * body (fetch does not). The panel answers 200 and 422 with an UploadResult,
 * anything else with a line of text, which becomes the error.
 */
export const uploadBundle: UploadBundle = (file, onProgress) =>
  new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", UPLOAD_URL);
    request.setRequestHeader("Content-Type", "application/x-tar");
    request.upload.onprogress = (event) => {
      if (event.lengthComputable && event.total > 0) onProgress(event.loaded / event.total);
    };
    request.onload = () => {
      if (request.status === 200 || request.status === 422) {
        try {
          resolve(JSON.parse(request.responseText) as UploadResult);
        } catch {
          reject(new Error(`HTTP ${String(request.status)}`));
        }
        return;
      }
      const text = request.responseText.trim();
      reject(new Error(text !== "" ? text : `HTTP ${String(request.status)}`));
    };
    request.onerror = () => {
      reject(new Error("network"));
    };
    request.send(file);
  });
