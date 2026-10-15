import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import type {
  CountriesRequest,
  CountryTotalSchema,
  EgressHistoryRequest,
  IpSightingSchema,
  ListIpSightingsRequest,
  MemberHistorySchema,
  NodePointSchema,
  NodeSeriesRequest,
  OverviewRequest,
  TopProxiesRequest,
} from "../gen/postern/panel/v1/metrics_pb";
import { GeoIPStatusSchema, type SetGeoIPEnabledRequest } from "../gen/postern/panel/v1/geoip_pb";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { ProbeHistoryRequest, ProbeNowRequest, ProbePointSchema } from "../gen/postern/panel/v1/probes_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import type { PanelAddressSchema, UpdateStatsSettingsRequest } from "../gen/postern/panel/v1/settings_pb";

export type IpPolicy = "full" | "countries" | "off";

/** The attribution that the panel sends with every answer about countries. */
export const ATTRIBUTION = "IP Geolocation by DB-IP";
export const ATTRIBUTION_URL = "https://db-ip.com";
/** The message of the panel for IP history under another policy than "full". */
export const NOT_FULL = 'the IP policy is not "full"';
/** The message of the panel for a probe of a proxy that is paused. */
export const PROBE_PAUSED = "the proxy is disabled";

export interface InsightsOptions {
  ipPolicy?: IpPolicy;
  /** The addresses that the nodes see the panel come from. */
  panelAddresses?: MessageInitShape<typeof PanelAddressSchema>[];
  /** The country database of the panel; a current one unless this says otherwise. */
  geoip?: MessageInitShape<typeof GeoIPStatusSchema>;
}

/** The licence of the DB-IP database. */
export const LICENCE = "CC BY 4.0";

const now = () => Math.floor(Date.now() / 1000);

function handler<Request, Response>(impl: (req: Request) => Response) {
  return vi.fn<(req: Request) => Response | Promise<Response>>(impl);
}

/**
 * MetricsService and ProbeService over the nodes and proxies of the inventory.
 * What a test wants a call to answer goes into `state`; without it, the answers
 * are small made-up ones. ListIpSightings fails as the panel does while the IP
 * policy is not "full", and ProbeNow for a paused proxy.
 */
export function createFakeInsights(
  requireSession: () => void,
  inventory: { nodes: Node[]; proxies: Proxy[] },
  options: InsightsOptions = {},
) {
  const state = {
    ipPolicy: options.ipPolicy ?? "countries",
    geoipMonth: "2026-10",
    nodeSeries: new Map<string, MessageInitShape<typeof NodePointSchema>[]>(),
    /** By proxy id, node id, or "" for every proxy. */
    countries: new Map<string, MessageInitShape<typeof CountryTotalSchema>[]>(),
    sightings: new Map<string, MessageInitShape<typeof IpSightingSchema>[]>(),
    egressHistory: new Map<string, MessageInitShape<typeof MemberHistorySchema>[]>(),
    probes: new Map<string, MessageInitShape<typeof ProbePointSchema>[]>(),
    /** What the overview says of each node, besides its id. */
    overview: new Map<string, Record<string, unknown>>(),
    /** The proxies of TopProxies, busiest first; the inventory's with zeros when unset. */
    top: undefined as undefined | Record<string, unknown>[],
    settings: { minutesHours: 48, hoursDays: 90, ipDays: 7, probeIntervalMinutes: 5, extraProbeSources: [] as string[] },
    panelAddresses: options.panelAddresses ?? [],
    storage: { fileBytes: 30_000_000n, freeBytes: 1_000_000n, rows: { stats_proxy_1m: 2880n, ip_sightings: 0n } as Record<string, bigint> },
    geoip: create(GeoIPStatusSchema, {
      enabled: true,
      present: true,
      month: "2026-10",
      builtUnix: BigInt(now() - 5 * 86_400),
      size: 8_000_000n,
      sha256: "ab".repeat(32),
      fetchedUnix: BigInt(now() - 86_400),
      checkedUnix: BigInt(now() - 3600),
      error: "",
      attribution: ATTRIBUTION,
      attributionUrl: ATTRIBUTION_URL,
      licence: LICENCE,
      ...options.geoip,
    }),
  };

  const notFound = (what: string) => new ConnectError(`no such ${what}`, Code.NotFound);
  const findNode = (id: string) => {
    if (!inventory.nodes.some((node) => node.id === id)) throw notFound("node");
  };
  const findProxy = (id: string) => {
    const proxy = inventory.proxies.find((entry) => entry.id === id);
    if (proxy === undefined) throw notFound("proxy");
    return proxy;
  };
  const frame = (range: string) => {
    const seconds = { "1h": 3600, "": 86_400, "24h": 86_400, "7d": 7 * 86_400, "30d": 30 * 86_400 }[range] ?? 90 * 86_400;
    const step = seconds <= 7 * 86_400 ? 60 : 3600;
    const to = now() - (now() % step) + step;
    return { stepSeconds: step, fromUnix: BigInt(to - seconds), toUnix: BigInt(to) };
  };

  const invalid = (message: string) => new ConnectError(message, Code.InvalidArgument);
  const answerSettings = () => ({
    settings: { ...state.settings, ipPolicy: state.ipPolicy },
    panelAddresses: state.panelAddresses,
  });
  const inRange = (value: number, min: number, max: number, what: string) => {
    if (value < min || value > max) throw invalid(`${what} must be ${String(min)} to ${String(max)}`);
  };
  const isAddress = (text: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(text) || (/^[0-9a-f:]+$/i.test(text) && text.includes(":"));

  const rpc = {
    getStatsSettings: handler(() => {
      requireSession();
      return answerSettings();
    }),

    updateStatsSettings: handler((req: UpdateStatsSettingsRequest) => {
      requireSession();
      const next = req.settings;
      if (next === undefined) throw invalid("settings are required");
      inRange(next.minutesHours, 6, 168, "minutes_hours");
      inRange(next.hoursDays, 7, 730, "hours_days");
      inRange(next.ipDays, 1, 30, "ip_days");
      inRange(next.probeIntervalMinutes, 0, 60, "probe_interval_minutes");
      if (!["full", "countries", "off"].includes(next.ipPolicy)) throw invalid("ip_policy is not known");
      if (next.extraProbeSources.length > 16) throw invalid("at most 16 extra probe sources");
      for (const source of next.extraProbeSources) {
        if (!isAddress(source)) throw invalid(`${source} is not a single IP address`);
      }
      state.settings = {
        minutesHours: next.minutesHours,
        hoursDays: next.hoursDays,
        ipDays: next.ipDays,
        probeIntervalMinutes: next.probeIntervalMinutes,
        extraProbeSources: [...next.extraProbeSources],
      };
      state.ipPolicy = next.ipPolicy as IpPolicy;
      return answerSettings();
    }),

    getStorage: handler(() => {
      requireSession();
      return state.storage;
    }),

    getGeoIP: handler(() => {
      requireSession();
      return { status: state.geoip };
    }),

    refreshGeoIP: handler(() => {
      requireSession();
      if (state.geoip.enabled) state.geoip = create(GeoIPStatusSchema, { ...state.geoip, checkedUnix: BigInt(now()) });
      return { status: state.geoip };
    }),

    setGeoIPEnabled: handler((req: SetGeoIPEnabledRequest) => {
      requireSession();
      state.geoip = create(GeoIPStatusSchema, { ...state.geoip, enabled: req.enabled });
      return { status: state.geoip };
    }),

    overview: handler((req: OverviewRequest) => {
      requireSession();
      return {
        nodes: inventory.nodes.map((node) => ({ nodeId: node.id, ...state.overview.get(node.id) })),
        sinceUnix: req.sinceUnix,
        nowUnix: BigInt(now()),
      };
    }),

    nodeSeries: handler((req: NodeSeriesRequest) => {
      requireSession();
      findNode(req.nodeId);
      const f = frame(req.range);
      return { ...f, points: state.nodeSeries.get(req.nodeId) ?? [] };
    }),

    topProxies: handler((req: TopProxiesRequest) => {
      requireSession();
      const proxies =
        state.top ??
        inventory.proxies.map((proxy) => ({ proxyId: proxy.id, name: proxy.name, nodeId: proxy.nodeId, up: 0n, down: 0n }));
      return {
        proxies: proxies.filter((proxy) => req.nodeId === "" || proxy.nodeId === req.nodeId).slice(0, req.limit || 10),
        ...frame(req.range),
      };
    }),

    countries: handler((req: CountriesRequest) => {
      requireSession();
      if (req.proxyId !== "") findProxy(req.proxyId);
      if (req.nodeId !== "") findNode(req.nodeId);
      const { fromUnix, toUnix } = frame(req.range);
      return {
        countries: state.ipPolicy === "off" ? [] : (state.countries.get(req.proxyId || req.nodeId) ?? []),
        policy: state.ipPolicy,
        geoipMonth: state.geoipMonth,
        attribution: ATTRIBUTION,
        attributionUrl: ATTRIBUTION_URL,
        fromUnix,
        toUnix,
      };
    }),

    listIpSightings: handler((req: ListIpSightingsRequest) => {
      requireSession();
      findProxy(req.proxyId);
      if (state.ipPolicy !== "full") {
        throw new ConnectError(NOT_FULL, Code.FailedPrecondition);
      }
      const all = (state.sightings.get(req.proxyId) ?? []).filter(
        (sighting) => req.country === "" || sighting.country === req.country,
      );
      const limit = req.limit || 50;
      return { sightings: all.slice(req.offset, req.offset + limit), total: all.length };
    }),

    egressHistory: handler((req: EgressHistoryRequest) => {
      requireSession();
      findNode(req.nodeId);
      const { fromUnix, toUnix } = frame(req.range);
      return { members: state.egressHistory.get(req.nodeId) ?? [], fromUnix, toUnix };
    }),

    probeHistory: handler((req: ProbeHistoryRequest) => {
      requireSession();
      findProxy(req.proxyId);
      const points = state.probes.get(req.proxyId) ?? [];
      const vantages = [...new Set(points.map((point) => point.vantage ?? ""))].sort();
      return {
        points,
        uptimes: vantages.map((vantage) => {
          const mine = points.filter((point) => point.vantage === vantage);
          const ok = mine.filter((point) => point.ok === true).length;
          return { vantage, ok, total: mine.length, uptime: ok / mine.length };
        }),
      };
    }),

    probeNow: handler((req: ProbeNowRequest) => {
      requireSession();
      const proxy = findProxy(req.proxyId);
      if (!proxy.enabled) {
        throw new ConnectError(PROBE_PAUSED, Code.FailedPrecondition);
      }
      const result = { kind: "l2", ok: true, latencyMs: 120, error: "", l1Ok: true };
      state.probes.set(proxy.id, [
        ...(state.probes.get(proxy.id) ?? []),
        { ts: BigInt(now()), vantage: "panel", kind: "l2", ok: true, latencyMs: 120, error: "" },
      ]);
      return result;
    }),
  };

  return { rpc, state };
}
