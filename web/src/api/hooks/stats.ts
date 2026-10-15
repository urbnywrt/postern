import { useQuery } from "@tanstack/react-query";

import { StatsService } from "../../gen/postern/panel/v1/proxies_pb";
import { useClient } from "../client";
import { REFRESH_MS, statsKeys } from "./keys";

/** The latest minute that the node reported about a proxy, and its status; asked again every 10 seconds. */
export function useProxyLive(proxyId: string) {
  const stats = useClient(StatsService);
  return useQuery({
    queryKey: statsKeys.live(proxyId),
    queryFn: ({ signal }) => stats.proxyLive({ proxyId }, { signal }),
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

/** A point of the series is a minute, and there is a new one each minute. */
const SERIES_REFRESH_MS = 60_000;

/** The traffic of a proxy over a range that ends now: "1h", "24h", "7d" or "30d". */
export function useProxySeries(proxyId: string, range = "24h") {
  const stats = useClient(StatsService);
  return useQuery({
    queryKey: statsKeys.series(proxyId, range),
    queryFn: ({ signal }) => stats.proxySeries({ proxyId, range }, { signal }),
    refetchInterval: SERIES_REFRESH_MS,
    meta: { silent: true },
  });
}
