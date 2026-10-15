import type { DescService } from "@bufbuild/protobuf";
import { type Client, createClient, type Transport } from "@connectrpc/connect";
import { createContext, useContext, useMemo } from "react";

import { transport } from "./transport";

/** The transport that the clients of the app use. Tests put an in-memory one here. */
export const TransportContext = createContext<Transport>(transport);

export function useClient<T extends DescService>(service: T): Client<T> {
  const current = useContext(TransportContext);
  return useMemo(() => createClient(service, current), [service, current]);
}
