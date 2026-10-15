import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type ChainCheck,
  ChainService,
  type EgressParams,
  EgressService,
} from "../../gen/postern/panel/v1/egress_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { chainKeys, egressKeys, nodeKeys, proxyKeys, REFRESH_MS } from "./keys";

// Egresses and chains change only when an admin changes them, so they are not
// asked for again by themselves. The health of the members of a node changes by
// itself, and is asked for again every REFRESH_MS, like the state of a node.

/** The egresses that a node can use, or every egress when `nodeId` is empty. */
export function useEgresses(nodeId = "", { enabled = true }: { enabled?: boolean } = {}) {
  const egresses = useClient(EgressService);
  return useQuery({
    queryKey: egressKeys.list(nodeId),
    queryFn: async ({ signal }) => (await egresses.listEgresses({ nodeId }, { signal })).egresses,
    enabled,
    meta: { silent: true },
  });
}

/** The chains that a node can use, or every chain when `nodeId` is empty. */
export function useChains(nodeId = "", { enabled = true }: { enabled?: boolean } = {}) {
  const chains = useClient(ChainService);
  return useQuery({
    queryKey: chainKeys.list(nodeId),
    queryFn: async ({ signal }) => (await chains.listChains({ nodeId }, { signal })).chains,
    enabled,
    meta: { silent: true },
  });
}

/** What a node last reported of the health of the members of its chains. */
export function useNodeEgressHealth(nodeId: string) {
  const egresses = useClient(EgressService);
  return useQuery({
    queryKey: egressKeys.health(nodeId),
    queryFn: ({ signal }) => egresses.getNodeEgressHealth({ nodeId }, { signal }),
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/**
 * What a change of egresses or chains touches: both lists (a chain lists its
 * egresses, an egress its chains), and the generations of the nodes that use
 * them.
 */
function useRefreshAfterChange() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: egressKeys.all }),
      queryClient.invalidateQueries({ queryKey: chainKeys.all }),
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
    ]);
}

/** The parameters of an egress as a form sends them: every field, empty when the kind does not have it. */
export type EgressParamsVars = Pick<
  EgressParams,
  "interface" | "bindIp" | "addr" | "username" | "password" | "uri" | "url" | "select" | "country" | "propagationChannelId" | "sponsorId"
>;

export interface CreateEgressVars {
  name: string;
  kind: string;
  /** Empty for an egress that every node can use. */
  nodeId: string;
  params: EgressParamsVars;
}

export function useCreateEgress() {
  const egresses = useClient(EgressService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: CreateEgressVars) => present((await egresses.createEgress(vars)).egress),
    onSuccess: refresh,
  });
}

/** The fields that are set change; an empty secret in `params` keeps the stored one (UpdateEgressRequest). */
export interface UpdateEgressVars {
  id: string;
  name?: string;
  params?: EgressParamsVars;
}

export function useUpdateEgress() {
  const egresses = useClient(EgressService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: UpdateEgressVars) => {
      const answer = await egresses.updateEgress(vars);
      // The checks that the panel made before the change, by node.
      return { egress: present(answer.egress), beforeRunIds: answer.beforeRunIds };
    },
    onSuccess: refresh,
  });
}

export function useDeleteEgress() {
  const egresses = useClient(EgressService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: (id: string) => egresses.deleteEgress({ id }),
    onSuccess: refresh,
  });
}

export interface ValidateEgressVars {
  kind: string;
  params: EgressParamsVars;
  /** The egress whose stored secrets fill in those that `params` leave empty; empty for a new one. */
  id: string;
}

/** Asks the panel whether it takes the parameters, without storing anything. Its answer is not kept. */
export function useValidateEgress() {
  const egresses = useClient(EgressService);
  return useMutation({
    mutationFn: (vars: ValidateEgressVars) => egresses.validateEgress(vars),
    gcTime: 0,
  });
}

export function useRefreshSubscription() {
  const egresses = useClient(EgressService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => egresses.refreshSubscription({ id }),
    // The nodes that run it have a new generation.
    onSuccess: () => queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
  });
}

/** The check of a chain as a form sends it. */
export type ChainCheckVars = Pick<ChainCheck, "intervalSeconds" | "timeoutSeconds" | "failThreshold" | "recoverThreshold" | "dcAddrs">;

export interface CreateChainVars {
  name: string;
  /** Empty for a chain that every node can use. */
  nodeId: string;
  memberIds: string[];
  check: ChainCheckVars;
}

export function useCreateChain() {
  const chains = useClient(ChainService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: CreateChainVars) => present((await chains.createChain(vars)).chain),
    onSuccess: refresh,
  });
}

/** The fields that are set change (UpdateChainRequest). */
export interface UpdateChainVars {
  id: string;
  name?: string;
  memberIds?: string[];
  check?: ChainCheckVars;
}

export function useUpdateChain() {
  const chains = useClient(ChainService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async ({ id, name, memberIds, check }: UpdateChainVars) =>
      present(
        (
          await chains.updateChain({
            id,
            name,
            members: memberIds === undefined ? undefined : { ids: memberIds },
            check,
          })
        ).chain,
      ),
    onSuccess: refresh,
  });
}

export function useDeleteChain() {
  const chains = useClient(ChainService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: (id: string) => chains.deleteChain({ id }),
    onSuccess: refresh,
  });
}

/** What a change of the egress settings of a node touches: the node, and the chains, which list the nodes whose default they are. */
function useRefreshAfterNodeChange() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
      queryClient.invalidateQueries({ queryKey: chainKeys.all }),
      queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
    ]);
}

export function useSetNodeDefaultChain() {
  const chains = useClient(ChainService);
  const refresh = useRefreshAfterNodeChange();
  return useMutation({
    mutationFn: async (vars: { nodeId: string; chainId: string }) => {
      const answer = await chains.setNodeDefaultChain(vars);
      return { node: present(answer.node), beforeRunId: answer.beforeRunId };
    },
    onSuccess: refresh,
  });
}

export function useSetNodeDnsMode() {
  const egresses = useClient(EgressService);
  const refresh = useRefreshAfterNodeChange();
  return useMutation({
    mutationFn: async (vars: { nodeId: string; dnsMode: string }) => {
      const answer = await egresses.setNodeDnsMode(vars);
      return { node: present(answer.node), beforeRunId: answer.beforeRunId };
    },
    onSuccess: refresh,
  });
}
