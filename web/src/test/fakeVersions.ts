import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import {
  type AffectedProxy,
  AffectedProxySchema,
  type AbortRolloutRequest,
  type Component,
  ComponentSchema,
  type ContinueRolloutRequest,
  type GetRolloutRequest,
  GetPanelVersionResponseSchema,
  type ListReleasesRequest,
  type ListRolloutsRequest,
  type PauseRolloutRequest,
  type PrepareReleaseRequest,
  type RecheckReleaseRequest,
  type RefreshReleasesRequest,
  type Release,
  ReleaseSchema,
  ReleaseSourceSchema,
  type RetryRolloutRequest,
  type Rollout,
  RolloutSchema,
  type SetDefaultChannelRequest,
  type SetNodeChannelRequest,
  type SetReleaseSourceRequest,
  type StartRolloutRequest,
  type UpdatePanelRequest,
} from "../gen/postern/panel/v1/versions_pb";

// An in-memory VersionService for the Versions page. It answers like the panel
// where the page can tell: a change of channel without confirm changes nothing
// and lists the proxies it would alter (Ruling S5-11); one active rollout per
// channel and per node, with the conflict naming the rollout that holds it; the
// actions of a rollout are refused, with a reason, in a status that does not
// take them; the tokens of the release source are never answered.

type ComponentInit = MessageInitShape<typeof ComponentSchema>;
type ReleaseInit = MessageInitShape<typeof ReleaseSchema>;
type RolloutInit = MessageInitShape<typeof RolloutSchema>;
type AffectedInit = MessageInitShape<typeof AffectedProxySchema>;
type PanelInit = MessageInitShape<typeof GetPanelVersionResponseSchema>;

export interface VersionsOptions {
  components?: ComponentInit[];
  releases?: ReleaseInit[];
  rollouts?: RolloutInit[];
  defaultChannel?: string;
  /** The proxies that a change to each channel alters, by channel (default) or "node:<id>:<channel>". */
  affected?: Record<string, AffectedInit[]>;
  panelVersion?: PanelInit;
}

let sequence = 0;

const precondition = (message: string) => new ConnectError(message, Code.FailedPrecondition);
const invalid = (message: string) => new ConnectError(message, Code.InvalidArgument);
const notFound = (what: string) => new ConnectError(`no such ${what}`, Code.NotFound);
const handler = <Request, Response>(impl: (req: Request) => Response) =>
  vi.fn<(req: Request) => Response | Promise<Response>>(impl);

const CHANNELS = ["stable", "latest"];
const ACTIVE = ["preparing", "running", "paused", "failed"];

export function createFakeVersions(requireSession: () => void, inventory: { nodes: Node[] }, options: VersionsOptions = {}) {
  const state = {
    components: (options.components ?? []).map((init) => create(ComponentSchema, init)),
    releases: (options.releases ?? []).map((init) => create(ReleaseSchema, init)),
    rollouts: (options.rollouts ?? []).map((init) => create(RolloutSchema, init)),
    defaultChannel: options.defaultChannel ?? "stable",
    includePrereleases: false,
    affected: options.affected ?? {},
    panel: create(GetPanelVersionResponseSchema, {
      version: "v0.5.0",
      imageVersion: "v0.5.0",
      canUpdate: false,
      cannotUpdateReason: "the panel knows no newer release",
      kitSigned: true,
      ...options.panelVersion,
    }),
    source: create(ReleaseSourceSchema, { kind: "github", repo: "urbnywrt/postern" }),
    /** The tokens as sent: what the panel keeps sealed. */
    tokens: { token: "", githubToken: "" },
  };

  const findRollout = (id: string) => {
    const found = state.rollouts.find((r) => r.id === id);
    if (found === undefined) throw notFound("rollout");
    return found;
  };
  const affectedOf = (key: string): AffectedProxy[] => (state.affected[key] ?? []).map((init) => create(AffectedProxySchema, init));
  const channelOk = (channel: string, allowEmpty: boolean) => {
    if (!(CHANNELS.includes(channel) || (allowEmpty && channel === ""))) throw invalid("channel must be stable or latest");
  };
  const activeOn = (pred: (r: Rollout) => boolean) => state.rollouts.find((r) => ACTIVE.includes(r.status) && pred(r));
  const component = (name: string): Component | undefined => state.components.find((c) => c.name === name);

  const rpc = {
    listComponents: handler(() => {
      requireSession();
      return { components: state.components, defaultChannel: state.defaultChannel, includePrereleases: state.includePrereleases };
    }),

    listReleases: handler((req: ListReleasesRequest) => {
      requireSession();
      return { releases: state.releases.filter((r) => r.component === req.component) };
    }),

    refreshReleases: handler((req: RefreshReleasesRequest) => {
      requireSession();
      return { components: state.components.filter((c) => req.component === "" || c.name === req.component) };
    }),

    prepareRelease: handler((req: PrepareReleaseRequest) => {
      requireSession();
      const release: Release | undefined = state.releases.find((r) => r.component === req.component && r.version === req.version);
      if (release === undefined) throw notFound("release");
      release.assets.forEach((a) => {
        if (a.state === "unchecked") a.state = "ready";
      });
      return { release };
    }),

    recheckRelease: handler((req: RecheckReleaseRequest) => {
      requireSession();
      const release = state.releases.find((r) => r.component === req.component && r.version === req.version);
      if (release === undefined) throw notFound("release");
      const asset = release.assets.find((a) => a.arch === req.arch);
      if (asset === undefined) throw notFound("asset");
      asset.state = "unchecked";
      asset.reason = "";
      return { release };
    }),

    setDefaultChannel: handler((req: SetDefaultChannelRequest) => {
      requireSession();
      channelOk(req.channel, false);
      const affectedProxies = affectedOf(req.channel);
      if (req.confirm) state.defaultChannel = req.channel;
      return { affectedProxies, applied: req.confirm };
    }),

    setNodeChannel: handler((req: SetNodeChannelRequest) => {
      requireSession();
      channelOk(req.channel, true);
      const node = inventory.nodes.find((n) => n.id === req.nodeId);
      if (node === undefined) throw notFound("node");
      const affectedProxies = affectedOf(`node:${req.nodeId}:${req.channel}`);
      if (req.confirm) {
        node.engineChannel = req.channel === "" ? state.defaultChannel : req.channel;
        node.engineChannelDefault = req.channel === "";
      }
      return { affectedProxies, applied: req.confirm };
    }),

    startRollout: handler((req: StartRolloutRequest) => {
      requireSession();
      if (!["manual", "auto"].includes(req.mode)) throw invalid("mode must be manual or auto");
      if (req.kind === "version") {
        const held = activeOn((r) => r.kind === "version" && r.component === req.component && r.channel === req.channel);
        if (held) throw precondition(`rollout ${held.id} is active for ${req.component} on ${req.channel}`);
      } else if (req.kind === "switch") {
        if (req.proxyIds.length === 0) throw invalid("the selection is empty");
      } else if (req.kind !== "node") {
        throw invalid("kind must be version, switch or node");
      }
      const nodes = req.kind === "node" && req.nodeIds.length > 0 ? inventory.nodes.filter((n) => req.nodeIds.includes(n.id)) : inventory.nodes;
      const rollout = create(RolloutSchema, {
        id: `rollout-${String(++sequence)}`,
        kind: req.kind,
        component: req.kind === "node" ? "postern" : req.component,
        channel: req.channel,
        fromVersion: req.kind === "version" ? (component(req.component)?.channelVersions[req.channel] ?? "") : "",
        toVersion: req.toVersion,
        toEngine: req.kind === "switch" ? req.component : "",
        mode: req.mode,
        pauseSeconds: req.pauseSeconds,
        status: "running",
        agent: req.agent,
        edge: req.edge,
        skipOffline: req.skipOffline,
        steps: nodes.map((n, index) => ({ index, nodeId: n.id, nodeName: n.name, status: index === 0 ? "applying" : "pending", items: 1 })),
        createdUnix: BigInt(Math.floor(Date.now() / 1000)),
      });
      // As the panel: an engine channel that no proxy follows moves at once.
      const comp = req.kind === "version" ? component(req.component) : undefined;
      if (comp?.kind === "engine" && !comp.followedChannels.includes(req.channel)) {
        rollout.status = "completed";
        rollout.steps = [];
        comp.channelVersions[req.channel] = req.toVersion;
      }
      state.rollouts.unshift(rollout);
      return { rollout };
    }),

    getRollout: handler((req: GetRolloutRequest) => {
      requireSession();
      return { rollout: findRollout(req.id) };
    }),

    listRollouts: handler((req: ListRolloutsRequest) => {
      requireSession();
      const all = state.rollouts.filter((r) => !req.activeOnly || ACTIVE.includes(r.status));
      return { rollouts: req.limit > 0 ? all.slice(0, req.limit) : all };
    }),

    continueRollout: handler((req: ContinueRolloutRequest) => {
      requireSession();
      const rollout = findRollout(req.id);
      if (rollout.status !== "paused") throw precondition(`the rollout is ${rollout.status}, not paused`);
      rollout.status = "running";
      return { rollout };
    }),

    pauseRollout: handler((req: PauseRolloutRequest) => {
      requireSession();
      const rollout = findRollout(req.id);
      if (rollout.status !== "running") throw precondition(`the rollout is ${rollout.status}, not running`);
      rollout.status = "paused";
      return { rollout };
    }),

    retryRollout: handler((req: RetryRolloutRequest) => {
      requireSession();
      const rollout = findRollout(req.id);
      if (rollout.status !== "failed") throw precondition(`the rollout is ${rollout.status}, not failed`);
      rollout.status = "running";
      rollout.error = "";
      return { rollout };
    }),

    abortRollout: handler((req: AbortRolloutRequest) => {
      requireSession();
      const rollout = findRollout(req.id);
      if (!ACTIVE.includes(rollout.status)) throw precondition(`the rollout is ${rollout.status} already`);
      rollout.status = "aborted";
      return { rollout };
    }),

    getPanelVersion: handler(() => {
      requireSession();
      return state.panel;
    }),

    updatePanel: handler((req: UpdatePanelRequest) => {
      requireSession();
      if (!state.panel.canUpdate) throw precondition(state.panel.cannotUpdateReason);
      return { version: req.version, restarting: true };
    }),

    getReleaseSource: handler(() => {
      requireSession();
      return { source: state.source };
    }),

    setReleaseSource: handler((req: SetReleaseSourceRequest) => {
      requireSession();
      if (req.token !== undefined) state.tokens.token = req.token;
      if (req.githubToken !== undefined) state.tokens.githubToken = req.githubToken;
      state.source = create(ReleaseSourceSchema, {
        kind: req.source?.kind ?? "",
        baseUrl: req.source?.baseUrl ?? "",
        repo: req.source?.repo ?? "",
        includePrereleases: req.source?.includePrereleases ?? false,
        hasToken: state.tokens.token !== "",
        hasGithubToken: state.tokens.githubToken !== "",
      });
      state.includePrereleases = state.source.includePrereleases;
      return { source: state.source };
    }),
  };

  return { rpc, state };
}

export type FakeVersions = ReturnType<typeof createFakeVersions>;
