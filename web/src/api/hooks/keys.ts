// The keys of the queries, in one place: a change of a node touches the lists of
// listeners and proxies as well, and the hooks of each kind need the keys of the
// others to say what to ask for again.

export const nodeKeys = {
  all: ["nodes"] as const,
  list: ["nodes", "list"] as const,
  detail: (id: string) => ["nodes", "detail", id] as const,
  /** Under the detail of the node, so that it goes when the node goes. */
  install: (id: string) => ["nodes", "detail", id, "install"] as const,
};

export const listenerKeys = {
  all: ["listeners"] as const,
  /** Of one node, or of every node when `nodeId` is empty. */
  list: (nodeId: string) => ["listeners", "list", nodeId] as const,
};

export interface ProxyFilter {
  /** Empty for the proxies of every node. */
  nodeId?: string;
  /** Matches the id, name, note and domain, letter case aside. */
  query?: string;
  /** "telemt" or "mtg"; empty for every engine. */
  engine?: string;
  /** Only the proxies that run another engine or version than they should, or one older than the newest of their channel. */
  outdated?: boolean;
}

export const proxyKeys = {
  all: ["proxies"] as const,
  lists: ["proxies", "list"] as const,
  list: (filter: ProxyFilter) =>
    ["proxies", "list", filter.nodeId ?? "", filter.query ?? "", filter.engine ?? "", filter.outdated ?? false] as const,
  detail: (id: string) => ["proxies", "detail", id] as const,
  links: (id: string) => ["proxies", "links", id] as const,
  /** The snippets for the web server in front of a WEB proxy on an http-upstream listener. */
  snippets: (id: string) => ["proxies", "snippets", id] as const,
};

export const dnsKeys = {
  all: ["dns"] as const,
  list: ["dns", "list"] as const,
};

export const deployKeys = {
  /** How the panel reaches the server of a node over SSH, under the node, so that it goes with it. */
  target: (nodeId: string) => ["nodes", "detail", nodeId, "ssh"] as const,
  job: (id: string) => ["jobs", id] as const,
};

export const egressKeys = {
  all: ["egresses"] as const,
  /** Those that one node can use, or every egress when `nodeId` is empty. */
  list: (nodeId: string) => ["egresses", "list", nodeId] as const,
  /** What a node last reported of the members of its chains. */
  health: (nodeId: string) => ["egresses", "health", nodeId] as const,
};

export const chainKeys = {
  all: ["chains"] as const,
  /** Those that one node can use, or every chain when `nodeId` is empty. */
  list: (nodeId: string) => ["chains", "list", nodeId] as const,
};

export const statsKeys = {
  live: (proxyId: string) => ["stats", "live", proxyId] as const,
  series: (proxyId: string, range: string) => ["stats", "series", proxyId, range] as const,
};

/** The statistics of MetricsService and the probes; every key starts with "metrics", so that a change of the settings refreshes them all. */
export const metricsKeys = {
  all: ["metrics"] as const,
  overview: (sinceUnix: number) => ["metrics", "overview", sinceUnix] as const,
  nodeSeries: (nodeId: string, range: string) => ["metrics", "nodeSeries", nodeId, range] as const,
  topProxies: (nodeId: string, range: string, limit: number) => ["metrics", "top", nodeId, range, limit] as const,
  countries: (scope: { proxyId?: string; nodeId?: string }, range: string) =>
    ["metrics", "countries", scope.proxyId ?? "", scope.nodeId ?? "", range] as const,
  ipSightings: (proxyId: string, country: string, limit: number, offset: number) =>
    ["metrics", "ips", proxyId, country, limit, offset] as const,
  egressHistory: (nodeId: string, range: string) => ["metrics", "egress", nodeId, range] as const,
  probes: (proxyId: string, range: string) => ["metrics", "probes", proxyId, range] as const,
};

export const settingsKeys = {
  stats: ["settings", "stats"] as const,
  storage: ["settings", "storage"] as const,
};

export const geoipKeys = {
  status: ["geoip"] as const,
};

export const publicPageKeys = {
  all: ["publicPage"] as const,
};

/** How often the pages that show the state of nodes and proxies ask the panel again. */
export const REFRESH_MS = 10_000;
