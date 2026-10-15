import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ProbeService } from "../../gen/postern/panel/v1/probes_pb";
import { useClient } from "../client";
import { metricsKeys } from "./keys";

/** Probes are minute data: asking more often than once a minute shows nothing new. */
const PROBES_REFRESH_MS = 60_000;

/** The probes of a proxy over "24h" or "7d", from the panel and from its node, and the uptime of each. */
export function useProbeHistory(proxyId: string, range: "24h" | "7d") {
  const probes = useClient(ProbeService);
  return useQuery({
    queryKey: metricsKeys.probes(proxyId, range),
    queryFn: ({ signal }) => probes.probeHistory({ proxyId, range }, { signal }),
    refetchInterval: PROBES_REFRESH_MS,
    meta: { silent: true },
  });
}

/**
 * Probes a proxy from the panel now. The page says why when the panel refuses
 * (a WEB proxy, no link host, asked again too soon), so the error is not a
 * notification as well.
 */
export function useProbeNow() {
  const probes = useClient(ProbeService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (proxyId: string) => probes.probeNow({ proxyId }),
    meta: { silent: true },
    onSuccess: (_result, proxyId) => {
      void queryClient.invalidateQueries({ queryKey: ["metrics", "probes", proxyId] });
    },
  });
}
