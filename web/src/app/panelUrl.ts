// The address that a node reaches the panel at, for the one-command install
// (NodeService.CreateJoinToken) and the SSH install. The check is the one of
// the panel (nodes.CheckPanelURL in internal/panel/nodes/installcmd.go), so
// that the form says what is wrong before the panel refuses it; the panel
// checks again all the same.

import { readStored, writeStored } from "./storage";

/** Why an address is refused, as a key of the translation files. */
export type PanelUrlError =
  | "validation.panelUrl"
  | "validation.panelUrlPath"
  | "validation.panelUrlPort"
  | "validation.panelUrlHttp";

export type PanelUrlCheck = { ok: true; url: string } | { ok: false; error: PanelUrlError };

/** A host name in lower case: labels of letters, digits and hyphens. */
const HOST_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** An IPv4 address in its strict form: four decimal numbers 0-255, no leading zeros. */
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** An IPv6 address in the normal form of the browser, mapped from IPv4 (::ffff:a.b.c.d). */
const IPV4_IN_IPV6 = /^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/;

const refused = (error: PanelUrlError): PanelUrlCheck => ({ ok: false, error });

/** An IPv6 address in its normal form (RFC 5952), or undefined when it is none. */
function normalIPv6(text: string): string | undefined {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) {
    return undefined;
  }
  try {
    const host = new URL(`http://[${text}]/`).hostname;
    return host.slice(1, -1);
  } catch {
    return undefined;
  }
}

/**
 * Checks the address that a node reaches the panel at and returns it in its normal
 * form: https://host[:port], the scheme and the host in lower case, without a
 * trailing "/". No path other than "/", no query, no fragment, no user name, and
 * http:// only for a loopback host (127.0.0.0/8, ::1 or localhost).
 */
export function checkPanelUrl(raw: string): PanelUrlCheck {
  if (raw === "" || /[?#@\\ '"]/.test(raw) || /[^\x21-\x7e]/.test(raw)) {
    return refused("validation.panelUrl");
  }
  const parts = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)(\/.*)?$/.exec(raw);
  if (parts === null) {
    return refused("validation.panelUrl");
  }
  const [, rawScheme = "", authority = "", path = ""] = parts;
  if (authority === "") {
    return refused("validation.panelUrl");
  }
  if (path !== "" && path !== "/") {
    return refused("validation.panelUrlPath");
  }
  const scheme = rawScheme.toLowerCase();
  if (scheme !== "https" && scheme !== "http") {
    return refused("validation.panelUrl");
  }

  const hostPort = authority.startsWith("[")
    ? /^\[([^\]]*)\](?::(.*))?$/.exec(authority)
    : /^([^:[\]]*)(?::(.*))?$/.exec(authority);
  if (hostPort === null) {
    return refused("validation.panelUrl");
  }
  const bracketed = authority.startsWith("[");
  const host = (hostPort[1] ?? "").toLowerCase();
  const port = hostPort[2];
  if (port !== undefined) {
    const n = Number(port);
    if (port === "" || !/^\d+$/.test(port) || n < 1 || n > 65535 || String(n) !== port) {
      return refused("validation.panelUrlPort");
    }
  }

  let shown: string;
  let loopback: boolean;
  if (IPV4.test(host)) {
    shown = host;
    loopback = host.startsWith("127.");
  } else if (bracketed) {
    const v6 = normalIPv6(host);
    if (v6 === undefined || IPV4_IN_IPV6.test(v6)) {
      return refused("validation.panelUrl");
    }
    shown = `[${v6}]`;
    loopback = v6 === "::1";
  } else if (HOST_NAME.test(host) && host.length <= 253) {
    shown = host;
    loopback = host === "localhost";
  } else {
    return refused("validation.panelUrl");
  }
  if (scheme === "http" && !loopback) {
    return refused("validation.panelUrlHttp");
  }
  return { ok: true, url: `${scheme}://${shown}${port === undefined ? "" : `:${port}`}` };
}

/** Where the browser keeps the panel address for nodes that was last used. */
export const PANEL_URL_KEY = "postern.panelUrlForNodes";

/**
 * The panel address for nodes that the form starts with: the one that was last used
 * in this browser, or the address that the page was opened at.
 */
export function storedPanelUrl(): string {
  const stored = readStored(PANEL_URL_KEY);
  if (stored !== null && stored !== "") {
    return stored;
  }
  try {
    return window.location.origin;
  } catch {
    return "";
  }
}

/** Remembers the panel address for nodes in this browser, when it can. */
export function rememberPanelUrl(url: string): void {
  writeStored(PANEL_URL_KEY, url);
}
