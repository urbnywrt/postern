import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { DnsCredentialService } from "../../gen/postern/panel/v1/dns_pb";
import { present } from "../answer";
import { useClient } from "../client";
import { dnsKeys, nodeKeys } from "./keys";

/** The DNS credentials, without their tokens: the panel never returns them. */
export function useDnsCredentials({ enabled = true }: { enabled?: boolean } = {}) {
  const dns = useClient(DnsCredentialService);
  return useQuery({
    queryKey: dnsKeys.list,
    queryFn: async ({ signal }) => (await dns.listDnsCredentials({}, { signal })).credentials,
    enabled,
    meta: { silent: true },
  });
}

function useRefreshAfterChange() {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: dnsKeys.all }),
      // A new token raises the generation of the nodes that use it.
      queryClient.invalidateQueries({ queryKey: nodeKeys.all }),
    ]);
}

export interface CreateDnsCredentialVars {
  name: string;
  provider: string;
  token: string;
}

export function useCreateDnsCredential() {
  const dns = useClient(DnsCredentialService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: CreateDnsCredentialVars) => present((await dns.createDnsCredential(vars)).credential),
    onSuccess: refresh,
  });
}

export interface UpdateDnsCredentialVars {
  id: string;
  name?: string;
  token?: string;
}

export function useUpdateDnsCredential() {
  const dns = useClient(DnsCredentialService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: async (vars: UpdateDnsCredentialVars) => present((await dns.updateDnsCredential(vars)).credential),
    onSuccess: refresh,
  });
}

export function useDeleteDnsCredential() {
  const dns = useClient(DnsCredentialService);
  const refresh = useRefreshAfterChange();
  return useMutation({
    mutationFn: (id: string) => dns.deleteDnsCredential({ id }),
    onSuccess: refresh,
  });
}
