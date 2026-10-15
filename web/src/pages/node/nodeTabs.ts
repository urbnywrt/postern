/** The tabs of the page of a node, in order; each is a route under /nodes/:nodeId (the overview is its index). */
export const NODE_TABS = ["overview", "proxies", "egress", "diagnostics", "settings"] as const;
export type NodeTab = (typeof NODE_TABS)[number];

/** The route handle by which a tab is known (see the router). */
export interface NodeTabHandle {
  nodeTab: NodeTab;
}

/** The address of a tab of a node. */
export const nodeTabPath = (nodeId: string, tab: NodeTab) => (tab === "overview" ? `/nodes/${nodeId}` : `/nodes/${nodeId}/${tab}`);
