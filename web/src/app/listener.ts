import type { Listener } from "../gen/postern/panel/v1/proxies_pb";

/** The kinds of a listener: a public TLS port, or a loopback port behind a web server of the node. */
export const LISTENER_KINDS = ["tls", "http-upstream"] as const;

/** The address of a listener as the UI names it, with its kind when it is not the usual one. */
export function listenerLabel(listener: Listener, t: (key: "listener.kind.http-upstream") => string): string {
  const address = `${listener.bindIp}:${String(listener.port)}`;
  return listener.kind === "http-upstream" ? `${address} (${t("listener.kind.http-upstream")})` : address;
}
