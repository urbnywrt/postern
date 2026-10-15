import type { MessageInitShape } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  DeployService,
  type InstallRequestSchema,
  type PreflightRequestSchema,
} from "../../gen/postern/panel/v1/deploy_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { deployKeys, nodeKeys } from "./keys";

/** How often the log of a running job is asked for. */
export const JOB_POLL_MS = 1000;

/**
 * How the panel last reached the server of a node over SSH, whether it keeps
 * credentials for it, and the job that the node runs, if any (GetTarget).
 */
export function useDeployTarget(nodeId: string) {
  const deploy = useClient(DeployService);
  return useQuery({
    queryKey: deployKeys.target(nodeId),
    queryFn: ({ signal }) => deploy.getTarget({ nodeId }, { signal }),
    meta: { silent: true },
  });
}

export type PreflightVars = MessageInitShape<typeof PreflightRequestSchema>;

/**
 * Logs in to the server and checks it. The page shows what goes wrong, so a
 * failure is not also a notification. The answer is a host key to confirm, a
 * changed host key, or the report.
 */
export function usePreflight() {
  const deploy = useClient(DeployService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: PreflightVars) => deploy.preflight(vars),
    meta: { silent: true },
    onSuccess: (_response, vars) => queryClient.invalidateQueries({ queryKey: deployKeys.target(vars.nodeId ?? "") }),
  });
}

export type InstallVars = MessageInitShape<typeof InstallRequestSchema>;

/** Starts the job that installs the node, and answers with its id. */
export function useInstall() {
  const deploy = useClient(DeployService);
  return useMutation({
    mutationFn: async (vars: InstallVars) => (await deploy.install(vars)).jobId,
    meta: { silent: true },
  });
}

/**
 * A job with its log, asked for every JOB_POLL_MS while it runs. When it has
 * ended, the node is asked for again: an install changes its status.
 */
export function useJob(id: string, nodeId: string) {
  const deploy = useClient(DeployService);
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: deployKeys.job(id),
    queryFn: async ({ signal }) => {
      const job = present((await deploy.getJob({ id }, { signal })).job);
      if (job.status !== "running") {
        void queryClient.invalidateQueries({ queryKey: nodeKeys.detail(nodeId) });
        void queryClient.invalidateQueries({ queryKey: deployKeys.target(nodeId) });
      }
      return job;
    },
    refetchInterval: (query) => (query.state.data === undefined || query.state.data.status === "running" ? JOB_POLL_MS : false),
    meta: { silent: true },
  });
}

/** The page shows why a cancel failed, so it is not also a notification. */
export function useCancelJob() {
  const deploy = useClient(DeployService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deploy.cancelJob({ id }),
    meta: { silent: true },
    onSuccess: (_response, id) => queryClient.invalidateQueries({ queryKey: deployKeys.job(id) }),
  });
}
