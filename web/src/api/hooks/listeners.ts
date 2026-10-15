import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type { PortOwner } from "../../gen/postern/panel/v1/nodes_pb";
import { type Listener, ListenerService } from "../../gen/postern/panel/v1/proxies_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { listenerKeys, nodeKeys, proxyKeys } from "./keys";

/**
 * The listeners of a node, or of every node with no `nodeId`. `enabled: false`
 * holds the query back, for a form that has not been told the node yet: an empty
 * `nodeId` there would ask for the listeners of every node.
 */
export function useListeners(nodeId = "", { enabled = true }: { enabled?: boolean } = {}) {
  const listeners = useClient(ListenerService);
  return useQuery({
    queryKey: listenerKeys.list(nodeId),
    queryFn: async ({ signal }) => (await listeners.listListeners({ nodeId }, { signal })).listeners,
    enabled,
    meta: { silent: true },
  });
}

/** What a change of listeners touches: the listeners, the generation of the node, the links of proxies. */
function useRefreshAfterChange() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: listenerKeys.all }),
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
      queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
    ]);
}

export interface CreateListenerVars {
  nodeId: string;
  /** "tls" or "http-upstream". */
  kind: string;
  bindIp: string;
  port: number;
  linkHostOverride: string;
  strangerAction: string;
  maskTarget: string;
  nonTlsAction: string;
  /** The web servers in front of an http-upstream listener; empty on a tls one. */
  trustedCidrs: string[];
}

/**
 * A listener as the panel stored it, and the processes other than Postern that the node said
 * hold its address: the edge cannot listen there until they let it go.
 */
export interface SavedListener {
  listener: Listener;
  portTakenBy: PortOwner[];
}

export function useCreateListener() {
  const listeners = useClient(ListenerService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: CreateListenerVars): Promise<SavedListener> => {
      const answer = await listeners.createListener(vars);
      return { listener: present(answer.listener), portTakenBy: answer.portTakenBy };
    },
    onSuccess: refresh,
  });
}

/** The fields that are set change; the others stay (UpdateListenerRequest). */
export interface UpdateListenerVars {
  id: string;
  bindIp?: string;
  port?: number;
  linkHostOverride?: string;
  strangerAction?: string;
  maskTarget?: string;
  nonTlsAction?: string;
  /** Replaces the trusted CIDRs as a whole. */
  trustedCidrs?: { cidrs: string[] };
}

export function useUpdateListener() {
  const listeners = useClient(ListenerService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: UpdateListenerVars): Promise<SavedListener> => {
      const answer = await listeners.updateListener(vars);
      return { listener: present(answer.listener), portTakenBy: answer.portTakenBy };
    },
    onSuccess: refresh,
  });
}

export function useDeleteListener() {
  const listeners = useClient(ListenerService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: (id: string) => listeners.deleteListener({ id }),
    onSuccess: refresh,
  });
}
