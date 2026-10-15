import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import {
  type Chain,
  ChainSchema,
  type CreateChainRequest,
  type CreateEgressRequest,
  type DeleteChainRequest,
  type DeleteEgressRequest,
  type Egress,
  type EgressParams,
  EgressParamsSchema,
  EgressSchema,
  type GetChainRequest,
  type GetEgressRequest,
  type GetNodeEgressHealthRequest,
  GetNodeEgressHealthResponseSchema,
  type ListChainsRequest,
  type ListEgressesRequest,
  type RefreshSubscriptionRequest,
  type SetNodeDefaultChainRequest,
  type SetNodeDnsModeRequest,
  type UpdateChainRequest,
  type UpdateEgressRequest,
  type ValidateEgressRequest,
  type ValidateEgressResponseSchema,
} from "../gen/postern/panel/v1/egress_pb";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";

// An in-memory panel for the screens of egresses and chains. It answers like
// the panel does where a screen can tell: an unknown id is NOT_FOUND, an egress
// that a chain has and a chain in use cannot be deleted, and no answer holds a
// secret (a password, a share link, the URL of a subscription).

const now = () => Math.floor(Date.now() / 1000);
let sequence = 0;
const next = () => ++sequence;

type EgressInit = MessageInitShape<typeof EgressSchema>;
type ChainInit = MessageInitShape<typeof ChainSchema>;
type HealthInit = MessageInitShape<typeof GetNodeEgressHealthResponseSchema>;

/** An egress of every node, a direct one unless `init` says otherwise. */
export function makeEgress(init: EgressInit = {}): Egress {
  const n = next();
  return create(EgressSchema, {
    id: `egress-${String(n)}`,
    name: `Egress ${String(n)}`,
    kind: "direct",
    nodeId: "",
    params: {},
    createdUnix: BigInt(now() - 3600),
    updatedUnix: BigInt(now() - 3600),
    ...init,
  } as EgressInit);
}

/** A chain of every node, without members unless `init` says otherwise. */
export function makeChain(init: ChainInit = {}): Chain {
  const n = next();
  return create(ChainSchema, {
    id: `chain-${String(n)}`,
    name: `Chain ${String(n)}`,
    nodeId: "",
    memberIds: [],
    check: {},
    createdUnix: BigInt(now() - 3600),
    updatedUnix: BigInt(now() - 3600),
    ...init,
  } as ChainInit);
}

export interface EgressOptions {
  egresses?: EgressInit[];
  chains?: ChainInit[];
  /** What the nodes reported of the health of their chains, by node id. */
  health?: Record<string, HealthInit>;
}

const notFound = (what: string) => new ConnectError(`no such ${what}`, Code.NotFound);
const invalid = (message: string) => new ConnectError(message, Code.InvalidArgument);
const precondition = (message: string) => new ConnectError(message, Code.FailedPrecondition);

function handler<Request, Response>(impl: (req: Request) => Response) {
  return vi.fn<(req: Request) => Response | Promise<Response>>(impl);
}

const KINDS = ["direct", "socks5", "http", "xray-uri", "xray-subscription", "warp", "psiphon"];

/** What can be shown of a share link or the URL of a subscription: the scheme and the host. */
function maskedOf(kind: string, params: EgressParams | undefined): string {
  const text = kind === "xray-uri" ? (params?.uri ?? "") : kind === "xray-subscription" ? (params?.url ?? "") : "";
  const match = /^([a-z0-9+.-]+):\/\/(?:[^@/?#]*@)?([^/?#]+)/i.exec(text);
  return match ? `${match[1] ?? ""}://${match[2] ?? ""}` : "";
}

/**
 * The state and the handlers of EgressService and ChainService.
 * `requireSession` throws the 401 of a visitor; `nodes` and `proxies` are those
 * of the inventory, whose default chains and DNS modes these change.
 */
export function createFakeEgress(
  requireSession: () => void,
  inventory: { nodes: Node[]; proxies: Proxy[] },
  options: EgressOptions = {},
) {
  const state = {
    egresses: (options.egresses ?? []).map((init) => makeEgress(init)),
    chains: (options.chains ?? []).map((init) => makeChain(init)),
    health: new Map(Object.entries(options.health ?? {})),
    /** The secrets that were sent, by egress id: what the panel keeps sealed. */
    secrets: new Map<string, EgressParams>(),
  };
  const findEgress = (id: string) => {
    const found = state.egresses.find((e) => e.id === id);
    if (found === undefined) throw notFound("egress");
    return found;
  };
  const findChain = (id: string) => {
    const found = state.chains.find((c) => c.id === id);
    if (found === undefined) throw notFound("chain");
    return found;
  };
  const findNode = (id: string) => {
    const found = inventory.nodes.find((n) => n.id === id);
    if (found === undefined) throw notFound("node");
    return found;
  };
  const usable = (owner: string, nodeId: string) => nodeId === "" || owner === "" || owner === nodeId;
  const chainIdsOf = (id: string) => state.chains.filter((c) => c.memberIds.includes(id)).map((c) => c.id);
  const withChains = (e: Egress) => {
    e.chainIds = chainIdsOf(e.id);
    return e;
  };
  /** An egress as the panel answers with it: without its secrets. */
  const answer = (e: Egress, sent: EgressParams | undefined) => {
    e.masked = maskedOf(e.kind, sent ?? e.params) || e.masked;
    if (sent !== undefined && (e.kind === "socks5" || e.kind === "http")) {
      e.passwordSet = sent.username !== "" && (sent.password !== "" || e.passwordSet);
    }
    if (sent !== undefined) {
      e.params = create(EgressParamsSchema, { ...sent, password: "", uri: "", url: "" });
    }
    return withChains(e);
  };
  const bump = (nodeId: string) => {
    const node = inventory.nodes.find((n) => n.id === nodeId);
    if (node) node.desiredGeneration += 1n;
  };
  /**
   * The interval of the health checks of a node in seconds, as the panel works
   * it out (checkInterval in internal/panel/egress): the node runs one check,
   * that of its default chain, or else of the first chain by id that it uses
   * (its default chain, and the chain and the scope chains of its proxies) and
   * that has a check; a check without an interval, or none, is every 30 seconds.
   */
  const checkInterval = (node: Node): number => {
    const byId = new Map(state.chains.map((c) => [c.id, c]));
    const hasCheck = (c: Chain | undefined) => {
      const check = c?.check;
      return (
        check !== undefined &&
        (check.intervalSeconds !== 0 || check.timeoutSeconds !== 0 || check.failThreshold !== 0 || check.recoverThreshold !== 0 || check.dcAddrs.length > 0)
      );
    };
    const used = new Set([node.defaultChainId]);
    for (const proxy of inventory.proxies.filter((p) => p.nodeId === node.id)) {
      used.add(proxy.egressChainId);
      Object.values(proxy.egressScopeChains).forEach((id) => used.add(id));
    }
    const own = byId.get(node.defaultChainId);
    const chain = hasCheck(own) ? own : [...used].sort().map((id) => byId.get(id)).find(hasCheck);
    const seconds = chain?.check?.intervalSeconds ?? 0;
    return seconds === 0 ? 30 : seconds;
  };

  const rpc = {
    // ---- EgressService ----
    listEgresses: handler((req: ListEgressesRequest) => {
      requireSession();
      return { egresses: state.egresses.filter((e) => usable(e.nodeId, req.nodeId)).map(withChains) };
    }),

    getEgress: handler((req: GetEgressRequest) => {
      requireSession();
      return { egress: withChains(findEgress(req.id)) };
    }),

    createEgress: handler((req: CreateEgressRequest) => {
      requireSession();
      if (req.name.trim() === "") throw invalid("name is empty");
      if (!KINDS.includes(req.kind)) throw invalid("kind must be one of the kinds");
      const egress = makeEgress({ name: req.name.trim(), kind: req.kind, nodeId: req.nodeId });
      state.egresses.push(answer(egress, req.params));
      if (req.params) state.secrets.set(egress.id, req.params);
      return { egress };
    }),

    updateEgress: handler((req: UpdateEgressRequest) => {
      requireSession();
      const egress = findEgress(req.id);
      if (req.name !== undefined) egress.name = req.name.trim();
      if (req.params !== undefined) {
        answer(egress, req.params);
      }
      return { egress: withChains(egress) };
    }),

    deleteEgress: handler((req: DeleteEgressRequest) => {
      requireSession();
      findEgress(req.id);
      if (chainIdsOf(req.id).length > 0) {
        throw precondition("the egress is a member of a chain: take it out of it first");
      }
      state.egresses = state.egresses.filter((e) => e.id !== req.id);
      return {};
    }),

    validateEgress: handler((req: ValidateEgressRequest): MessageInitShape<typeof ValidateEgressResponseSchema> => {
      requireSession();
      if (!KINDS.includes(req.kind)) return { valid: false, problem: "params: the kind must be one of the kinds" };
      if (req.kind === "xray-uri") {
        const uri = req.params?.uri ?? "";
        if (uri === "" && req.id === "") return { valid: false, problem: "params: params_json has no uri" };
        const scheme = /^([a-z]+):\/\//.exec(uri)?.[1] ?? "vless";
        return { valid: true, masked: maskedOf(req.kind, req.params), protocol: scheme, security: "none", network: "tcp" };
      }
      return { valid: true, masked: maskedOf(req.kind, req.params) };
    }),

    refreshSubscription: handler((req: RefreshSubscriptionRequest) => {
      requireSession();
      const egress = findEgress(req.id);
      if (egress.kind !== "xray-subscription") throw precondition("only a subscription can be fetched again");
      const chains = new Set(chainIdsOf(egress.id));
      const nodeIds = inventory.nodes.filter((n) => chains.has(n.defaultChainId)).map((n) => n.id);
      nodeIds.forEach(bump);
      return { nodeIds };
    }),

    getNodeEgressHealth: handler((req: GetNodeEgressHealthRequest) => {
      requireSession();
      const node = findNode(req.nodeId);
      const init = state.health.get(req.nodeId);
      if (init === undefined) {
        return create(GetNodeEgressHealthResponseSchema, { nodeStatus: node.status, stale: true });
      }
      // What the panel adds to a report (EgressService.GetNodeEgressHealth): the
      // status of the node, the kinds of the egresses, and what is stale: the
      // node is not online, or the report or a check is older than three
      // intervals of the check of the node, and at least 120 seconds. A test
      // may set them itself.
      const report = create(GetNodeEgressHealthResponseSchema, init);
      const limit = BigInt(Math.max(3 * checkInterval(node), 120));
      const at = BigInt(now());
      report.nodeStatus = report.nodeStatus === "" ? node.status : report.nodeStatus;
      report.stale ||= node.status !== "online" || at - report.reportedUnix > limit;
      for (const m of report.members) {
        if (m.egressKind === "") {
          m.egressKind = state.egresses.find((e) => e.id === m.egressId)?.kind ?? (m.egressId === "direct" ? "direct" : "");
        }
        m.stale ||= report.stale || (m.checkedUnix > 0n && at - m.checkedUnix > limit);
      }
      return report;
    }),

    setNodeDnsMode: handler((req: SetNodeDnsModeRequest) => {
      requireSession();
      const node = findNode(req.nodeId);
      if (!["", "doh", "system"].includes(req.dnsMode)) throw invalid("dns_mode must be doh, system or empty");
      if (node.dnsMode !== req.dnsMode) {
        node.dnsMode = req.dnsMode;
        bump(node.id);
      }
      return { node };
    }),

    // ---- ChainService ----
    listChains: handler((req: ListChainsRequest) => {
      requireSession();
      return { chains: state.chains.filter((c) => usable(c.nodeId, req.nodeId)) };
    }),

    getChain: handler((req: GetChainRequest) => {
      requireSession();
      return { chain: findChain(req.id) };
    }),

    createChain: handler((req: CreateChainRequest) => {
      requireSession();
      if (req.name.trim() === "") throw invalid("name is empty");
      if (req.memberIds.length === 0) throw invalid("a chain has 1 to 64 members");
      req.memberIds.forEach(findEgress);
      const chain = makeChain({ name: req.name.trim(), nodeId: req.nodeId, memberIds: req.memberIds, check: req.check });
      state.chains.push(chain);
      return { chain };
    }),

    updateChain: handler((req: UpdateChainRequest) => {
      requireSession();
      const chain = findChain(req.id);
      if (req.name !== undefined) chain.name = req.name.trim();
      if (req.members !== undefined) {
        req.members.ids.forEach(findEgress);
        chain.memberIds = [...req.members.ids];
      }
      if (req.check !== undefined) chain.check = req.check;
      inventory.nodes.filter((n) => n.defaultChainId === chain.id).forEach((n) => {
        bump(n.id);
      });
      return { chain };
    }),

    deleteChain: handler((req: DeleteChainRequest) => {
      requireSession();
      const chain = findChain(req.id);
      if (chain.defaultOf.length > 0 || inventory.nodes.some((n) => n.defaultChainId === chain.id) || chain.proxyIds.length > 0) {
        throw precondition("the chain is in use: change those first");
      }
      state.chains = state.chains.filter((c) => c.id !== req.id);
      return {};
    }),

    setNodeDefaultChain: handler((req: SetNodeDefaultChainRequest) => {
      requireSession();
      const node = findNode(req.nodeId);
      if (req.chainId !== "") {
        const chain = findChain(req.chainId);
        if (!usable(chain.nodeId, node.id)) throw invalid("the chain belongs to another node");
      }
      if (node.defaultChainId !== req.chainId) {
        state.chains.forEach((c) => {
          c.defaultOf = c.defaultOf.filter((id) => id !== node.id);
          if (c.id === req.chainId) c.defaultOf.push(node.id);
        });
        node.defaultChainId = req.chainId;
        bump(node.id);
      }
      return { node };
    }),
  };

  return { rpc, state };
}

export type FakeEgress = ReturnType<typeof createFakeEgress>;
