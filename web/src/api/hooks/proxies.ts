import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { notifyWarning } from "../../app/notify";
import { type Proxy, ProxyService, type WebSettingsInput } from "../../gen/postern/panel/v1/proxies_pb";
import i18n from "../../i18n";
import { present } from "../answer";
import { useClient } from "../client";
import { nodeKeys, type ProxyFilter, proxyKeys, REFRESH_MS } from "./keys";

export function useProxies(filter: ProxyFilter = {}, { enabled = true }: { enabled?: boolean } = {}) {
  const proxies = useClient(ProxyService);
  return useQuery({
    queryKey: proxyKeys.list(filter),
    queryFn: async ({ signal }) =>
      (
        await proxies.listProxies(
          { nodeId: filter.nodeId ?? "", query: filter.query ?? "", engine: filter.engine ?? "", outdated: filter.outdated ?? false },
          { signal },
        )
      ).proxies,
    // The table of the last filter stays while the next one is on its way, so that
    // typing in the search box does not flash a spinner for each letter.
    placeholderData: keepPreviousData,
    enabled,
    refetchInterval: REFRESH_MS,
    meta: { silent: true },
  });
}

export function useProxy(id: string) {
  const proxies = useClient(ProxyService);
  return useQuery({
    queryKey: proxyKeys.detail(id),
    queryFn: async ({ signal }) => present((await proxies.getProxy({ id }, { signal })).proxy),
    meta: { silent: true },
  });
}

/**
 * The links of a proxy, which carry its secret. They are not kept after the page
 * is left (`gcTime: 0`), and not asked for again by themselves: the secret and the
 * address only change when the proxy does, which asks for them again.
 */
export function useProxyLinks(id: string) {
  const proxies = useClient(ProxyService);
  return useQuery({
    queryKey: proxyKeys.links(id),
    queryFn: ({ signal }) => proxies.getProxyLinks({ id }, { signal }),
    gcTime: 0,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    meta: { silent: true },
  });
}

/** The snippets of the web server in front of a WEB proxy on an http-upstream listener. */
export function useWebSnippets(id: string, { enabled = true }: { enabled?: boolean } = {}) {
  const proxies = useClient(ProxyService);
  return useQuery({
    queryKey: proxyKeys.snippets(id),
    queryFn: ({ signal }) => proxies.getWebSnippets({ id }, { signal }),
    enabled,
    meta: { silent: true },
  });
}

/** What a change of proxies touches: the proxies, and the generation of their node. */
function useRefreshAfterChange() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: proxyKeys.all }),
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
    ]);
}

/** The WEB settings of a request (WebSettingsInput): the PEM fields are bytes. */
export type WebSettingsVars = Pick<
  WebSettingsInput,
  "basePath" | "secretMode" | "carrier" | "certMode" | "dnsCredentialId" | "acmeEmail"
> & {
  certFullchainPem?: Uint8Array;
  certKeyPem?: Uint8Array;
};

export interface ProxyLimitsVars {
  devices: number;
  connsTotal: number;
  connsPerIp: number;
}

export interface CreateProxyVars {
  nodeId: string;
  listenerId: string;
  /** "faketls" or "web". */
  type: string;
  /** The settings of a WEB proxy; left out for a fake-TLS one. */
  web?: WebSettingsVars;
  name: string;
  note: string;
  /** Empty picks a free domain of the pool of the panel. */
  domain: string;
  /** Empty makes a random secret. */
  secret: string;
  limits: ProxyLimitsVars;
  adTag: string;
  /** Empty for the default chain of the node. */
  egressChainId: string;
  /** The chains by scope ("me", "fetch"); a scope that is not there takes the chain of the proxy. */
  egressScopeChains: Record<string, string>;
  /** "auto" (on when there is an ad tag), "on" or "off": whether the engine goes through the middle proxies of Telegram. */
  useMiddleProxy: string;
}

/**
 * Shows what the panel warned of when it took a change of a proxy (a node without public addresses, an imported
 * certificate that expires soon): the change is done, the warnings stay on the screen until they are closed.
 */
function warn(warnings: string[]) {
  for (const warning of warnings) {
    notifyWarning(i18n.t("proxy.form.warning"), warning);
  }
}

export function useCreateProxy() {
  const proxies = useClient(ProxyService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: CreateProxyVars) => {
      const answer = await proxies.createProxy(vars);
      warn(answer.warnings);
      return present(answer.proxy);
    },
    onSuccess: refresh,
  });
}

/** The fields that are set change; the others stay (UpdateProxyRequest). */
export interface UpdateProxyVars {
  id: string;
  name?: string;
  note?: string;
  /** An empty domain picks a new one from the pool. */
  domain?: string;
  /** Replaces the limits as a whole. */
  limits?: ProxyLimitsVars;
  adTag?: string;
  /** Empty for the default chain of the node. */
  egressChainId?: string;
  /** Replaces the chains by scope as a whole. */
  egressScopeChains?: { chains: Record<string, string> };
  /** Replaces the WEB settings as a whole; without PEM fields, the stored certificate stays. */
  web?: WebSettingsVars;
  useMiddleProxy?: string;
  /** The version to pin the proxy to; empty follows the channel of its node again. */
  engineVersion?: string;
}

export function useUpdateProxy() {
  const proxies = useClient(ProxyService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: UpdateProxyVars) => {
      const answer = await proxies.updateProxy(vars);
      warn(answer.warnings);
      // The check that the panel made before the change, "" for none.
      return { proxy: present(answer.proxy), beforeRunId: answer.beforeRunId };
    },
    onSuccess: refresh,
  });
}

export function useDeleteProxy() {
  const proxies = useClient(ProxyService);
  const queryClient = useQueryClient();
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: (id: string) => proxies.deleteProxy({ id }),
    onSuccess: (_response, id) => {
      queryClient.removeQueries({ queryKey: proxyKeys.detail(id) });
      queryClient.removeQueries({ queryKey: proxyKeys.links(id) });
      return refresh();
    },
  });
}

/** Pauses a proxy or resumes it. The answer is the proxy as it is now, put in the lists and the detail at once. */
export function useSetProxyEnabled() {
  const proxies = useClient(ProxyService);
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { id: string; enabled: boolean }) =>
      present((await proxies.setProxyEnabled(vars)).proxy),
    onSuccess: (proxy) => {
      queryClient.setQueriesData<Proxy[]>({ queryKey: proxyKeys.lists }, (list) =>
        list?.map((entry) => (entry.id === proxy.id ? proxy : entry)),
      );
      queryClient.setQueryData(proxyKeys.detail(proxy.id), proxy);
      // The node has a new generation.
      return queryClient.invalidateQueries({ queryKey: nodeKeys.all });
    },
  });
}

/**
 * The tg link of a proxy as a promise, for the clipboard (see useCopy). The link
 * carries the secret, so it goes from the panel to the clipboard and is kept
 * nowhere else.
 */
export function useTgLink(): (id: string) => Promise<string> {
  const proxies = useClient(ProxyService);
  return async (id) => (await proxies.getProxyLinks({ id })).tg;
}
