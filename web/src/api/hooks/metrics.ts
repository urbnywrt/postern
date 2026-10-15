import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { MetricsService } from "../../gen/postern/panel/v1/metrics_pb";
import { useClient } from "../client";
import { metricsKeys, REFRESH_MS } from "./keys";

/** The statistics are minutes at the finest, so asking more often than once a minute shows nothing new. */
const METRICS_REFRESH_MS = 60_000;

// Every query here shows its own error where its data would be (silent).

/** Every node at a glance: its latest minute, and what its proxies carried since `sinceUnix` (0: the last 24 hours). */
export function useNodesOverview(sinceUnix: number) {
  const metrics = useClient(MetricsService);
  return useQuery({
    queryKey: metricsKeys.overview(sinceUnix),
    queryFn: ({ signal }) => metrics.overview({ sinceUnix: BigInt(sinceUnix) }, { signal }),
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/** The load and the traffic of a node over a range. */
export function useNodeSeries(nodeId: string, range: string) {
  const metrics = useClient(MetricsService);
  return useQuery({
    queryKey: metricsKeys.nodeSeries(nodeId, range),
    queryFn: ({ signal }) => metrics.nodeSeries({ nodeId, range }, { signal }),
    refetchInterval: METRICS_REFRESH_MS,
    meta: { silent: true },
  });
}

/** The proxies that carried the most over a range: of a node, or of every node when `nodeId` is empty. */
export function useTopProxies(nodeId: string, range: string, limit = 10) {
  const metrics = useClient(MetricsService);
  return useQuery({
    queryKey: metricsKeys.topProxies(nodeId, range, limit),
    queryFn: ({ signal }) => metrics.topProxies({ nodeId, range, limit }, { signal }),
    refetchInterval: METRICS_REFRESH_MS,
    meta: { silent: true },
  });
}

/** The countries of the clients over a range: of a proxy, of the proxies of a node, or of every proxy. */
export function useCountries(scope: { proxyId?: string; nodeId?: string }, range: string, { enabled = true }: { enabled?: boolean } = {}) {
  const metrics = useClient(MetricsService);
  return useQuery({
    enabled,
    queryKey: metricsKeys.countries(scope, range),
    queryFn: ({ signal }) =>
      metrics.countries({ proxyId: scope.proxyId ?? "", nodeId: scope.nodeId ?? "", range }, { signal }),
    refetchInterval: METRICS_REFRESH_MS,
    meta: { silent: true },
  });
}

/**
 * A page of where client addresses were seen on a proxy. The panel keeps them only
 * under the IP policy "full", so the query is made only then (`enabled`).
 * The page shown stays while the next one loads.
 */
export function useIpSightings(
  proxyId: string,
  { country, limit, offset, enabled }: { country: string; limit: number; offset: number; enabled: boolean },
) {
  const metrics = useClient(MetricsService);
  return useQuery({
    queryKey: metricsKeys.ipSightings(proxyId, country, limit, offset),
    queryFn: ({ signal }) => metrics.listIpSightings({ proxyId, country, limit, offset }, { signal }),
    enabled,
    refetchInterval: METRICS_REFRESH_MS,
    placeholderData: keepPreviousData,
    meta: { silent: true },
  });
}

/** The hours of the members of the egress chains of a node, over a range of at most 30 days. */
export function useEgressHistory(nodeId: string, range: string) {
  const metrics = useClient(MetricsService);
  return useQuery({
    queryKey: metricsKeys.egressHistory(nodeId, range),
    queryFn: ({ signal }) => metrics.egressHistory({ nodeId, range }, { signal }),
    refetchInterval: METRICS_REFRESH_MS,
    meta: { silent: true },
  });
}
