import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import { checkPanelUrl } from "../app/panelUrl";
import {
  type CreateJoinTokenRequest,
  type CreateNodeRequest,
  type DeleteNodeRequest,
  type GetNodeInstallRequest,
  type GetNodeInstallResponseSchema,
  type GetNodeRequest,
  type Node,
  NodeSchema,
  type SetNodeMgmtModeRequest,
  type UpdateNodeRequest,
} from "../gen/postern/panel/v1/nodes_pb";
import {
  type CreateListenerRequest,
  type CreateProxyRequest,
  type DeleteListenerRequest,
  type DeleteProxyRequest,
  type GetProxyLinksRequest,
  type GetProxyLinksResponseSchema,
  type GetProxyRequest,
  type GetWebSnippetsRequest,
  type Listener,
  type ListListenersRequest,
  ListenerSchema,
  type ListProxiesRequest,
  type Proxy,
  type ProxyLiveRequest,
  type ProxyLiveResponseSchema,
  ProxySchema,
  type ProxySeriesRequest,
  type ProxySeriesResponseSchema,
  type SetProxyEnabledRequest,
  type UpdateListenerRequest,
  type UpdateProxyRequest,
  type WebSettings,
  type WebSettingsInput,
  WebSettingsSchema,
} from "../gen/postern/panel/v1/proxies_pb";

// An in-memory panel for the screens of nodes, listeners, proxies and stats. It
// answers like the panel does where a screen can tell: a missing session is a 401,
// an unknown id is NOT_FOUND, a taken address or domain is ALREADY_EXISTS, a
// listener that proxies use cannot be deleted. The values are documentation
// addresses and names only.

/** The install command as the panel words it, with <ARCH> for the UI to fill in. */
export const INSTALL_COMMAND =
  "tar -xf postern-node-kit-linux-<ARCH>.tar && sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node";
/** The image of the node that the one-command install runs, unless a test says the panel has none. */
export const NODE_IMAGE = "ghcr.io/example/postern-node:0.1.0";

/** The docker run command as the panel renders it (nodes.RenderDockerCommand), shortened. */
export function dockerCommandFor(image: string, panelUrl: string, token: string): string {
  return [
    "docker run -d --name postern-agent --restart unless-stopped \\",
    `  -e POSTERN_JOIN='${panelUrl}#${token}' \\`,
    `  ${image}`,
  ].join("\n");
}

/** The compose file as the panel renders it (nodes.RenderCompose), shortened. */
export function composeFor(image: string, panelUrl: string, token: string): string {
  return [
    "name: postern",
    "services:",
    "  postern-agent:",
    `    image: ${image}`,
    "    environment:",
    `      POSTERN_JOIN: "${panelUrl}#${token}"`,
    "",
  ].join("\n");
}

/** The version of the panel, which its node kits have too. */
export const PANEL_VERSION = "0.1.0";
/** The architectures of the node kits, in the order of the panel. */
export const KIT_ARCHES = ["amd64", "arm64"];
export const QR_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 3 3" width="24" height="24"><path fill="#000" d="M0 0h1v1H0z"/></svg>';

const now = () => Math.floor(Date.now() / 1000);
let sequence = 0;
const next = () => ++sequence;

type NodeInit = MessageInitShape<typeof NodeSchema>;
type ListenerInit = MessageInitShape<typeof ListenerSchema>;
type ProxyInit = MessageInitShape<typeof ProxySchema>;

/** A node that is online and up to date, unless `init` says otherwise. */
export function makeNode(init: NodeInit = {}): Node {
  const n = next();
  return create(NodeSchema, {
    id: `node-${String(n)}`,
    name: `Node ${String(n)}`,
    mgmtHost: "203.0.113.7",
    mgmtPort: 61000 + n,
    linkHost: "203.0.113.7",
    status: "online",
    agentVersion: "0.1.0",
    edgeVersion: "0.1.0",
    arch: "amd64",
    os: "linux",
    publicIps: ["203.0.113.7"],
    desiredGeneration: 5n,
    appliedGeneration: 5n,
    lastSeenUnix: BigInt(now() - 20),
    note: "",
    ...init,
  });
}

/** A TLS listener on 0.0.0.0:443 of the node `nodeId`. */
export function makeListener(init: ListenerInit = {}): Listener {
  const n = next();
  return create(ListenerSchema, {
    id: `listener-${String(n)}`,
    nodeId: "node-1",
    kind: "tls",
    bindIp: "0.0.0.0",
    port: 443,
    linkHostOverride: "",
    strangerAction: "mask",
    maskTarget: "",
    nonTlsAction: "drop",
    trustedCidrs: [],
    createdUnix: BigInt(now() - 3600),
    updatedUnix: BigInt(now() - 3600),
    ...init,
  });
}

/** An enabled proxy that is serving, on the listener `listenerId` of the node `nodeId`. */
export function makeProxy(init: ProxyInit = {}): Proxy {
  const n = next();
  return create(ProxySchema, {
    id: `proxy-${String(n)}`,
    nodeId: "node-1",
    listenerId: "listener-1",
    type: "faketls",
    name: `Proxy ${String(n)}`,
    note: "",
    enabled: true,
    domain: `host${String(n)}.example.com`,
    limits: { devices: 0, connsTotal: 0, connsPerIp: 0 },
    adTag: "",
    engine: "telemt",
    engineVersion: "3.5.13",
    engineVersionPinned: false,
    useMiddleProxy: "auto",
    status: {
      phase: "serving",
      reason: "",
      runningVersion: "3.5.13",
      instanceGeneration: 5n,
      reportedUnix: BigInt(now() - 30),
    },
    createdUnix: BigInt(now() - 3600),
    updatedUnix: BigInt(now() - 3600),
    ...init,
  } as ProxyInit);
}

export interface InventoryOptions {
  nodes?: NodeInit[];
  listeners?: ListenerInit[];
  proxies?: ProxyInit[];
  /** The architectures whose node kit the panel has: all of KIT_ARCHES unless this says otherwise. */
  kits?: string[];
  /** The image of the node (GetNodeInstall.node_image): NODE_IMAGE unless this says otherwise; empty for none. */
  nodeImage?: string;
}

const notFound = (what: string) => new ConnectError(`no such ${what}`, Code.NotFound);
const invalid = (message: string) => new ConnectError(message, Code.InvalidArgument);

/** A mock of a handler. A test may make it answer later, with a promise, to see a page while a call is on its way. */
function handler<Request, Response>(impl: (req: Request) => Response) {
  return vi.fn<(req: Request) => Response | Promise<Response>>(impl);
}

function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw notFound(what);
  }
  return value;
}

function hex(text: string): string {
  return Array.from(new TextEncoder().encode(text), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * The processes other than Postern that hold the address of a listener, as the panel names them
 * in its answer: the owners of the port on the node where one of the two listens on every
 * address, or both on the same one.
 */
function portTakenBy(node: Node | undefined, bindIp: string, port: number) {
  const everywhere = (address: string) => address === "0.0.0.0" || address === "::";
  return (node?.portOwners ?? []).filter(
    (owner) =>
      owner.port === port && !owner.postern && (everywhere(owner.bind) || everywhere(bindIp) || owner.bind === bindIp),
  );
}

/** The WEB settings of a proxy as the panel stores them: no certificate, no credential on an http-upstream listener. */
function webSettingsOf(input: WebSettingsInput, upstream: boolean): WebSettings {
  const certMode = input.certMode === "" ? "acme-dns01" : input.certMode;
  const imported = !upstream && certMode === "imported" && input.certFullchainPem.length > 0;
  return create(WebSettingsSchema, {
    basePath: input.basePath,
    secretMode: input.secretMode === "" ? "plain" : input.secretMode,
    carrier: input.carrier === "" ? "https" : input.carrier,
    certMode: upstream ? "" : certMode,
    dnsCredentialId: upstream || certMode !== "acme-dns01" ? "" : input.dnsCredentialId,
    acmeEmail: upstream ? "" : input.acmeEmail,
    certSha256: imported ? "ab".repeat(32) : "",
    certNotAfterUnix: imported ? BigInt(now() + 60 * 86_400) : 0n,
  });
}

/**
 * The state and the handlers of NodeService, ListenerService, ProxyService and
 * StatsService. `requireSession` throws the 401 of a visitor.
 */
export function createFakeInventory(requireSession: () => void, options: InventoryOptions = {}) {
  const state = {
    nodes: (options.nodes ?? []).map((init) => makeNode(init)),
    listeners: (options.listeners ?? []).map((init) => makeListener(init)),
    proxies: (options.proxies ?? []).map((init) => makeProxy(init)),
    kits: [...(options.kits ?? KIT_ARCHES)],
    nodeImage: options.nodeImage ?? NODE_IMAGE,
    /** The live join token of each node: a new one replaces the one before. */
    joinTokens: new Map<string, string>(),
    /** The secret of each proxy that was made here; others get a fixed one. */
    secrets: new Map<string, string>(),
    /** Answers that a test wants for a proxy, instead of the made-up ones. */
    links: new Map<string, MessageInitShape<typeof GetProxyLinksResponseSchema>>(),
    live: new Map<string, MessageInitShape<typeof ProxyLiveResponseSchema>>(),
    series: new Map<string, MessageInitShape<typeof ProxySeriesResponseSchema>>(),
  };

  const findNode = (id: string) => must(state.nodes.find((node) => node.id === id), "node");
  const findListener = (id: string) => must(state.listeners.find((listener) => listener.id === id), "listener");
  const findProxy = (id: string) => must(state.proxies.find((proxy) => proxy.id === id), "proxy");
  const bump = (nodeId: string) => {
    const node = state.nodes.find((entry) => entry.id === nodeId);
    if (node) {
      node.desiredGeneration += 1n;
    }
  };

  const rpc = {
    // ---- NodeService ----
    listNodes: vi.fn(() => {
      requireSession();
      return { nodes: state.nodes };
    }),

    getNode: handler((req: GetNodeRequest) => {
      requireSession();
      return { node: findNode(req.id) };
    }),

    createNode: handler((req: CreateNodeRequest) => {
      requireSession();
      if (req.name.trim() === "") {
        throw invalid("name is empty");
      }
      const node = makeNode({
        name: req.name.trim(),
        mgmtHost: req.mgmtHost,
        mgmtPort: req.mgmtPort === 0 ? 62345 : req.mgmtPort,
        linkHost: req.linkHost === "" ? req.mgmtHost : req.linkHost,
        status: "provisioning",
        agentVersion: "",
        edgeVersion: "",
        arch: "",
        os: "",
        publicIps: [],
        desiredGeneration: 0n,
        appliedGeneration: 0n,
        lastSeenUnix: 0n,
      });
      state.nodes.push(node);
      return { node, bundleUrl: `/api/nodes/${node.id}/bundle.tar`, installCommand: INSTALL_COMMAND };
    }),

    updateNode: handler((req: UpdateNodeRequest) => {
      requireSession();
      const node = findNode(req.id);
      if (req.name !== undefined) {
        if (req.name.trim() === "") {
          throw invalid("name is empty");
        }
        node.name = req.name.trim();
      }
      if (req.mgmtHost !== undefined) node.mgmtHost = req.mgmtHost;
      if (req.mgmtPort !== undefined) node.mgmtPort = req.mgmtPort;
      if (req.linkHost !== undefined) node.linkHost = req.linkHost === "" ? node.mgmtHost : req.linkHost;
      if (req.note !== undefined) node.note = req.note;
      if (req.artifactSource !== undefined) {
        if (req.artifactSource === "direct" && !node.capabilities.includes("artifact-direct")) {
          throw new ConnectError("the agent of the node cannot download artifacts itself", Code.FailedPrecondition);
        }
        node.artifactSource = req.artifactSource === "" ? "panel" : req.artifactSource;
      }
      return { node };
    }),

    deleteNode: handler((req: DeleteNodeRequest) => {
      requireSession();
      findNode(req.id);
      state.nodes = state.nodes.filter((node) => node.id !== req.id);
      state.listeners = state.listeners.filter((listener) => listener.nodeId !== req.id);
      state.proxies = state.proxies.filter((proxy) => proxy.nodeId !== req.id);
      return {};
    }),

    getNodeInstall: handler((req: GetNodeInstallRequest): MessageInitShape<typeof GetNodeInstallResponseSchema> => {
      requireSession();
      const node = findNode(req.nodeId);
      return {
        bundleUrl: `/api/nodes/${node.id}/bundle.tar`,
        kits: KIT_ARCHES.map((arch) => ({
          arch,
          url: `/api/node-kit/${arch}`,
          available: state.kits.includes(arch),
          version: PANEL_VERSION,
        })),
        installCommand: INSTALL_COMMAND,
        nodeImage: state.nodeImage,
      };
    }),

    createJoinToken: handler((req: CreateJoinTokenRequest) => {
      requireSession();
      const node = findNode(req.nodeId);
      if (state.nodeImage === "") {
        throw new ConnectError("the panel has no node image: set POSTERN_NODE_IMAGE", Code.FailedPrecondition);
      }
      const checked = checkPanelUrl(req.panelUrl);
      if (!checked.ok) {
        throw invalid("panel_url: it must be https://host[:port], or http:// for a loopback host");
      }
      const token = `tok${String(next()).padStart(40, "0")}`;
      state.joinTokens.set(node.id, token);
      return {
        token,
        expiresUnix: BigInt(now() + 24 * 3600),
        dockerCommand: dockerCommandFor(state.nodeImage, checked.url, token),
        composeYaml: composeFor(state.nodeImage, checked.url, token),
        image: state.nodeImage,
      };
    }),

    setNodeMgmtMode: handler((req: SetNodeMgmtModeRequest) => {
      requireSession();
      const node = findNode(req.nodeId);
      const hidden = req.mode === "hidden";
      node.mgmtMode = req.mode;
      node.mgmtSni = hidden ? req.mgmtSni : "";
      node.mgmtPublicPort = hidden ? req.publicPort : 0;
      return { ok: true, reason: "", node };
    }),

    // ---- ListenerService ----
    listListeners: handler((req: ListListenersRequest) => {
      requireSession();
      return { listeners: state.listeners.filter((l) => req.nodeId === "" || l.nodeId === req.nodeId) };
    }),

    createListener: handler((req: CreateListenerRequest) => {
      requireSession();
      findNode(req.nodeId);
      const upstream = req.kind === "http-upstream";
      const bindIp = req.bindIp === "" ? (upstream ? "127.0.0.1" : "0.0.0.0") : req.bindIp;
      if (state.listeners.some((l) => l.nodeId === req.nodeId && l.bindIp === bindIp && l.port === req.port)) {
        throw new ConnectError("another listener of the node has this address", Code.AlreadyExists);
      }
      if (upstream && req.trustedCidrs.length === 0) {
        throw invalid("an http-upstream listener needs trusted_cidrs");
      }
      const listener = makeListener({
        nodeId: req.nodeId,
        kind: upstream ? "http-upstream" : "tls",
        bindIp,
        port: req.port,
        trustedCidrs: req.trustedCidrs,
        linkHostOverride: req.linkHostOverride,
        strangerAction: req.strangerAction === "" ? "mask" : req.strangerAction,
        maskTarget: req.maskTarget,
        nonTlsAction: req.nonTlsAction === "" ? "drop" : req.nonTlsAction,
      });
      state.listeners.push(listener);
      bump(req.nodeId);
      const node = state.nodes.find((entry) => entry.id === req.nodeId);
      return { listener, portTakenBy: portTakenBy(node, listener.bindIp, listener.port) };
    }),

    updateListener: handler((req: UpdateListenerRequest) => {
      requireSession();
      const listener = findListener(req.id);
      if (req.bindIp !== undefined) listener.bindIp = req.bindIp === "" ? "0.0.0.0" : req.bindIp;
      if (req.port !== undefined) listener.port = req.port;
      if (req.linkHostOverride !== undefined) listener.linkHostOverride = req.linkHostOverride;
      if (req.strangerAction !== undefined) listener.strangerAction = req.strangerAction;
      if (req.maskTarget !== undefined) listener.maskTarget = req.maskTarget;
      if (req.nonTlsAction !== undefined) listener.nonTlsAction = req.nonTlsAction;
      if (req.trustedCidrs !== undefined) listener.trustedCidrs = req.trustedCidrs.cidrs;
      bump(listener.nodeId);
      const node = state.nodes.find((entry) => entry.id === listener.nodeId);
      return { listener, portTakenBy: portTakenBy(node, listener.bindIp, listener.port) };
    }),

    deleteListener: handler((req: DeleteListenerRequest) => {
      requireSession();
      const listener = findListener(req.id);
      if (state.proxies.some((proxy) => proxy.listenerId === req.id)) {
        throw new ConnectError("the listener is still used by proxies", Code.FailedPrecondition);
      }
      state.listeners = state.listeners.filter((entry) => entry.id !== req.id);
      bump(listener.nodeId);
      return {};
    }),

    // ---- ProxyService ----
    listProxies: handler((req: ListProxiesRequest) => {
      requireSession();
      const query = req.query.toLowerCase();
      const matches = (proxy: Proxy) =>
        query === "" || [proxy.id, proxy.name, proxy.note, proxy.domain].some((text) => text.toLowerCase().includes(query));
      // outdated: the panel judged it so (a newer release on its channel), or the node reports another engine
      // or version than the proxy is to run.
      const outdated = (proxy: Proxy) => {
        const engine = proxy.status?.runningEngine ?? "";
        return (
          proxy.outdated ||
          (engine !== "" && engine !== proxy.engine) ||
          (proxy.status?.runningVersion ?? "") !== proxy.engineVersion
        );
      };
      return {
        proxies: state.proxies.filter(
          (p) =>
            (req.nodeId === "" || p.nodeId === req.nodeId) &&
            matches(p) &&
            (req.engine === "" || p.engine === req.engine) &&
            (!req.outdated || outdated(p)),
        ),
      };
    }),

    getProxy: handler((req: GetProxyRequest) => {
      requireSession();
      return { proxy: findProxy(req.id) };
    }),

    createProxy: handler((req: CreateProxyRequest) => {
      requireSession();
      findNode(req.nodeId);
      const listener = findListener(req.listenerId);
      if (listener.nodeId !== req.nodeId) {
        throw notFound("listener");
      }
      const web = req.type === "web";
      if (web && req.domain === "") {
        throw invalid("a web proxy needs its domain");
      }
      const webInput = req.web;
      if (web && webInput === undefined) {
        throw invalid("a web proxy needs web settings");
      }
      const domain = req.domain === "" ? `pool${String(next())}.example.com` : req.domain;
      if (state.proxies.some((p) => p.listenerId === req.listenerId && p.domain.toLowerCase() === domain.toLowerCase())) {
        throw new ConnectError("another proxy of the listener has this domain", Code.AlreadyExists);
      }
      const proxy = makeProxy({
        nodeId: req.nodeId,
        listenerId: req.listenerId,
        type: web ? "web" : "faketls",
        web: web && webInput ? webSettingsOf(webInput, listener.kind === "http-upstream") : undefined,
        name: req.name,
        note: req.note,
        domain,
        limits: req.limits,
        adTag: req.adTag,
        egressChainId: req.egressChainId,
        egressScopeChains: Object.fromEntries(Object.entries(req.egressScopeChains).filter(([, chain]) => chain !== "")),
        useMiddleProxy: req.useMiddleProxy === "" ? "auto" : req.useMiddleProxy,
        status: { phase: "pending", reason: "", runningVersion: "", instanceGeneration: 0n, reportedUnix: 0n },
      });
      state.proxies.push(proxy);
      state.secrets.set(proxy.id, req.secret === "" ? "ef".repeat(16) : req.secret);
      bump(req.nodeId);
      return { proxy };
    }),

    updateProxy: handler((req: UpdateProxyRequest) => {
      requireSession();
      const proxy = findProxy(req.id);
      if (req.name !== undefined) proxy.name = req.name;
      if (req.note !== undefined) proxy.note = req.note;
      if (req.domain !== undefined) proxy.domain = req.domain === "" ? `pool${String(next())}.example.com` : req.domain;
      if (req.adTag !== undefined) proxy.adTag = req.adTag;
      if (req.useMiddleProxy !== undefined) proxy.useMiddleProxy = req.useMiddleProxy === "" ? "auto" : req.useMiddleProxy;
      if (req.engineVersion !== undefined) {
        proxy.engineVersionPinned = req.engineVersion !== "";
        proxy.versionSource = req.engineVersion !== "" ? "pinned" : "channel";
        if (req.engineVersion !== "") proxy.engineVersion = req.engineVersion;
      }
      if (req.limits !== undefined) proxy.limits = req.limits;
      if (req.egressChainId !== undefined) proxy.egressChainId = req.egressChainId;
      if (req.egressScopeChains !== undefined) {
        proxy.egressScopeChains = Object.fromEntries(Object.entries(req.egressScopeChains.chains).filter(([, chain]) => chain !== ""));
      }
      if (req.web !== undefined) {
        if (proxy.type !== "web") {
          throw invalid("web settings are for a proxy of type web");
        }
        const listener = findListener(proxy.listenerId);
        const kept = proxy.web;
        const next = webSettingsOf(req.web, listener.kind === "http-upstream");
        if (req.web.certFullchainPem.length === 0 && kept && next.certMode === "imported") {
          next.certSha256 = kept.certSha256;
          next.certNotAfterUnix = kept.certNotAfterUnix;
        }
        proxy.web = next;
      }
      bump(proxy.nodeId);
      return { proxy };
    }),

    getWebSnippets: handler((req: GetWebSnippetsRequest) => {
      requireSession();
      const proxy = findProxy(req.id);
      const listener = findListener(proxy.listenerId);
      if (proxy.type !== "web" || listener.kind !== "http-upstream") {
        throw new ConnectError("snippets are for a WEB proxy on an http-upstream listener", Code.FailedPrecondition);
      }
      const base = `/${proxy.web?.basePath ?? ""}`;
      const addr = `${listener.bindIp}:${String(listener.port)}`;
      return {
        caddy: `handle ${base}/* {\n\treverse_proxy ${addr}\n}\nhandle ${base} {\n\treverse_proxy ${addr}\n}\n`,
        nginx: `location ^~ ${base}/ {\n\tproxy_pass http://${addr};\n}\nlocation = ${base} {\n\tproxy_pass http://${addr};\n}\n`,
      };
    }),

    deleteProxy: handler((req: DeleteProxyRequest) => {
      requireSession();
      const proxy = findProxy(req.id);
      state.proxies = state.proxies.filter((entry) => entry.id !== req.id);
      bump(proxy.nodeId);
      return {};
    }),

    setProxyEnabled: handler((req: SetProxyEnabledRequest) => {
      requireSession();
      const proxy = findProxy(req.id);
      proxy.enabled = req.enabled;
      bump(proxy.nodeId);
      return { proxy };
    }),

    getProxyLinks: handler((req: GetProxyLinksRequest) => {
      requireSession();
      const proxy = findProxy(req.id);
      const given = state.links.get(proxy.id);
      if (given) {
        return given;
      }
      const listener = findListener(proxy.listenerId);
      const node = findNode(proxy.nodeId);
      const server = listener.linkHostOverride || node.linkHost;
      const secret = `ee${state.secrets.get(proxy.id) ?? "cd".repeat(16)}${hex(proxy.domain)}`;
      const query = `server=${server}&port=${String(listener.port)}&secret=${secret}`;
      return { tg: `tg://proxy?${query}`, https: `https://t.me/proxy?${query}`, qrSvg: QR_SVG };
    }),

    // ---- StatsService ----
    proxyLive: handler((req: ProxyLiveRequest) => {
      requireSession();
      const proxy = findProxy(req.proxyId);
      return (
        state.live.get(proxy.id) ?? {
          minute: {
            minuteUnix: BigInt(now() - 60),
            up: 1_500_000n,
            down: 12_000_000n,
            connsNew: 3,
            connsPeak: 8,
            devices: 4,
            connsActive: 5,
          },
          status: proxy.status,
        }
      );
    }),

    proxySeries: handler((req: ProxySeriesRequest) => {
      requireSession();
      const proxy = findProxy(req.proxyId);
      const end = now() - (now() % 60);
      return (
        state.series.get(proxy.id) ?? {
          stepSeconds: 60,
          fromUnix: BigInt(end - 86_400),
          toUnix: BigInt(end),
          points: [
            { tsUnix: BigInt(end - 180), up: 1_000n, down: 20_000n, connsNew: 1, connsPeak: 2, devices: 1 },
            { tsUnix: BigInt(end - 120), up: 2_000n, down: 30_000n, connsNew: 2, connsPeak: 3, devices: 2 },
          ],
        }
      );
    }),
  };

  return { rpc, state };
}

export type FakeInventory = ReturnType<typeof createFakeInventory>;
