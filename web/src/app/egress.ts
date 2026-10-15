import type { TFunction } from "i18next";

import type { EgressParamsVars } from "../api/hooks/egress";
import type { Egress } from "../gen/postern/panel/v1/egress_pb";

/** The kinds of egresses, in the order that a form offers them (EgressService). */
export const EGRESS_KINDS = ["direct", "socks5", "http", "xray-uri", "xray-subscription", "warp", "psiphon"] as const;

export type EgressKind = (typeof EGRESS_KINDS)[number];

export function isEgressKind(kind: string): kind is EgressKind {
  return (EGRESS_KINDS as readonly string[]).includes(kind);
}

/**
 * The kinds that are not confirmed on a real server yet, and are labelled
 * experimental: Psiphon (its own client, psiphon-tunnel-core), until the check
 * on a real server passes.
 */
export const EXPERIMENTAL_KINDS: readonly string[] = ["psiphon"];

export function isExperimental(kind: string): boolean {
  return EXPERIMENTAL_KINDS.includes(kind);
}

/** The parameters of each kind, as EgressParams names them. */
export const KIND_FIELDS: Record<EgressKind, readonly (keyof EgressParamsVars)[]> = {
  direct: ["interface", "bindIp"],
  socks5: ["addr", "username", "password"],
  http: ["addr", "username", "password"],
  "xray-uri": ["uri"],
  "xray-subscription": ["url", "select"],
  warp: [],
  psiphon: ["country", "propagationChannelId", "sponsorId"],
};

/** The exit countries that a psiphon egress takes (internal/providers/psiphoncore: Countries). */
export const PSIPHON_COUNTRIES = [
  "AT", "AU", "BE", "BG", "CA", "CH", "CZ", "DE", "DK", "EE", "ES", "FI",
  "FR", "GB", "HR", "HU", "IE", "IN", "IT", "JP", "LV", "NL", "NO", "PL",
  "PT", "RO", "RS", "SE", "SG", "SK", "US",
] as const;

/** The scopes that a proxy can have chains of its own for: its connections to the middle proxies, and its downloads. */
export const PROXY_SCOPES = ["me", "fetch"] as const;

export type ProxyScope = (typeof PROXY_SCOPES)[number];

/** The name of a kind, in the language of the page; a kind of a newer panel is shown as it is. */
export function kindLabel(t: TFunction, kind: string): string {
  switch (kind) {
    case "direct":
      return t("egress.kinds.direct");
    case "socks5":
      return t("egress.kinds.socks5");
    case "http":
      return t("egress.kinds.http");
    case "xray-uri":
      return t("egress.kinds.xrayUri");
    case "xray-subscription":
      return t("egress.kinds.xraySubscription");
    case "warp":
      return t("egress.kinds.warp");
    case "psiphon":
      return t("egress.kinds.psiphon");
    default:
      return kind;
  }
}

/** The name of a country by its code, in the language of the page; the code where the browser has no name. */
export function countryName(code: string, language: string): string {
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

/**
 * What an egress goes through, without its secrets, as a line of a table: the
 * address of a proxy, the server of a share link, the host of a subscription
 * and which of its servers, an interface, a country. Empty when there is
 * nothing to say (warp, a direct egress of the default route).
 */
export function egressSummary(t: TFunction, egress: Egress): string {
  const p = egress.params;
  switch (egress.kind) {
    case "direct":
      return [p?.interface ?? "", p?.bindIp ?? ""].filter((part) => part !== "").join(", ");
    case "socks5":
    case "http":
      return p?.username ? `${p.username}@${p.addr}` : (p?.addr ?? "");
    case "xray-uri":
      return egress.masked;
    case "xray-subscription":
      return `${egress.masked} · ${selectLabel(t, p?.select ?? "")}`;
    case "psiphon":
      return p?.country ?? "";
    default:
      return "";
  }
}

/** How the servers of a subscription are picked, in words. */
export function selectLabel(t: TFunction, select: string): string {
  if (select === "first") {
    return t("egress.form.selectFirst");
  }
  if (select.startsWith("name:")) {
    return t("egress.selectByName", { text: select.slice("name:".length) });
  }
  return t("egress.form.selectAll");
}
