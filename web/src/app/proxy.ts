import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";

/** How a proxy is called: by its name, and by its domain when it has none. */
export function proxyTitle(proxy: Proxy): string {
  return proxy.name !== "" ? proxy.name : proxy.domain;
}
