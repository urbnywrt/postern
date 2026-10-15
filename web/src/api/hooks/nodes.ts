import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { NodeService } from "../../gen/postern/panel/v1/nodes_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { listenerKeys, nodeKeys, proxyKeys, REFRESH_MS } from "./keys";

// The pages show these queries themselves, so a failure is not also a notification
// (`silent`, see app/queryClient.ts). They are asked again every REFRESH_MS while
// the tab is open: the status of a node changes without anyone touching it.

/** `enabled: false` holds the query back, for a form that does not need the nodes (the node is given). */
export function useNodes({ enabled = true }: { enabled?: boolean } = {}) {
  const nodes = useClient(NodeService);
  return useQuery({
    queryKey: nodeKeys.list,
    queryFn: async ({ signal }) => (await nodes.listNodes({}, { signal })).nodes,
    enabled,
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/** `enabled: false` holds the query back, for a form that may not have a node. */
export function useNode(id: string, { enabled = true }: { enabled?: boolean } = {}) {
  const nodes = useClient(NodeService);
  return useQuery({
    queryKey: nodeKeys.detail(id),
    queryFn: async ({ signal }) => present((await nodes.getNode({ id }, { signal })).node),
    enabled,
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/**
 * How to install a node by hand (GetNodeInstall): its bundle, the node kit of
 * each architecture and whether the panel has it, and the install command.
 * Unlike the state of the node it is not asked for every few seconds: it changes
 * with the panel, not with the node.
 */
export function useNodeInstall(nodeId: string) {
  const nodes = useClient(NodeService);
  return useQuery({
    queryKey: nodeKeys.install(nodeId),
    queryFn: ({ signal }) => nodes.getNodeInstall({ nodeId }, { signal }),
    meta: { silent: true },
  });
}

export interface CreateJoinTokenVars {
  nodeId: string;
  /** The panel address that the node joins at, checked like the panel does (app/panelUrl.ts). */
  panelUrl: string;
}

/**
 * Makes a join token for a node and the command that installs it with Docker
 * (CreateJoinToken). Each call replaces the token before it, and the panel records
 * it: it is asked for on a button only, never when a page opens.
 */
export function useCreateJoinToken() {
  const nodes = useClient(NodeService);
  return useMutation({
    mutationFn: (vars: CreateJoinTokenVars) => nodes.createJoinToken(vars),
    // The block shows why the panel refused, next to the button.
    meta: { silent: true },
    // The answer holds the token: it goes with the block that shows it.
    gcTime: 0,
  });
}

export interface CreateNodeVars {
  name: string;
  /** Empty: the node gets the address that it joins from. */
  mgmtHost: string;
  /** 0 lets the panel pick a random high port. */
  mgmtPort: number;
  /** Empty means the management host. */
  linkHost: string;
}

export function useCreateNode() {
  const nodes = useClient(NodeService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: CreateNodeVars) => nodes.createNode(vars),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
  });
}

/** The fields that are set change; the others stay (UpdateNodeRequest). */
export interface UpdateNodeVars {
  id: string;
  name?: string;
  mgmtHost?: string;
  mgmtPort?: number;
  linkHost?: string;
  note?: string;
  /** "panel" or "direct" (capability artifact-direct). */
  artifactSource?: string;
}

export function useUpdateNode() {
  const nodes = useClient(NodeService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: UpdateNodeVars) => present((await nodes.updateNode(vars)).node),
    onSuccess: (node) => {
      queryClient.setQueryData(nodeKeys.detail(node.id), node);
      // The links of its proxies follow the link host.
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: nodeKeys.list }),
        queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
      ]);
    },
  });
}

export function useDeleteNode() {
  const nodes = useClient(NodeService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => nodes.deleteNode({ id }),
    onSuccess: (_response, id) => {
      // A node takes its listeners, proxies and statistics with it.
      queryClient.removeQueries({ queryKey: nodeKeys.detail(id) });
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: nodeKeys.list }),
        queryClient.invalidateQueries({ queryKey: listenerKeys.all }),
        queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
      ]);
    },
  });
}

export interface SetNodeMgmtModeVars {
  nodeId: string;
  /** "port" or "hidden"; mgmtSni and publicPort are for hidden. */
  mode: string;
  mgmtSni: string;
  publicPort: number;
}

/**
 * Switches how the panel reaches the agent of a node (SetNodeMgmtMode). It takes
 * up to a minute: the panel checks the new path live. A failed check is no error
 * but an answer with `ok` false and the reason, which the dialog shows.
 */
export function useSetNodeMgmtMode() {
  const nodes = useClient(NodeService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: SetNodeMgmtModeVars) => nodes.setNodeMgmtMode(vars),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
  });
}
