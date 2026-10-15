import { describe, expect, it } from "vitest";

import { create } from "@bufbuild/protobuf";

import { NodeSchema } from "../gen/postern/panel/v1/nodes_pb";
import { ProxySchema } from "../gen/postern/panel/v1/proxies_pb";
import { ComponentSchema, GetPanelVersionResponseSchema, ReleaseSchema } from "../gen/postern/panel/v1/versions_pb";
import { buildStartRollout, channelUpdateLines, channelUpdates, DEFAULT_CHOICES, hasPin, mtgBlockers, outdatedNodes, posternUpdatable, rolloutActions, safeUrl, tokenField } from "./versions";

const ENGINE = { kind: "version", component: "telemt", componentKind: "engine", channel: "stable", toVersion: "3.5.13" } as const;
const PROVIDER = { kind: "version", component: "xray", componentKind: "provider", channel: "latest", toVersion: "v26.3.27" } as const;

describe("buildStartRollout", () => {
  it("an engine version, manual: canary proxy, no pause, no canary node", () => {
    expect(buildStartRollout(ENGINE, { ...DEFAULT_CHOICES, canaryProxyId: "p1", canaryNodeId: "n1", skipOffline: true })).toEqual({
      kind: "version",
      component: "telemt",
      channel: "stable",
      toVersion: "3.5.13",
      mode: "manual",
      pauseSeconds: 0,
      skipOffline: true,
      canaryProxyId: "p1",
      canaryNodeId: "",
    });
  });

  it("a provider version, auto: canary node and the pause", () => {
    expect(buildStartRollout(PROVIDER, { ...DEFAULT_CHOICES, mode: "auto", pauseSeconds: 300, canaryProxyId: "p1", canaryNodeId: "n1" })).toEqual({
      kind: "version",
      component: "xray",
      channel: "latest",
      toVersion: "v26.3.27",
      mode: "auto",
      pauseSeconds: 300,
      skipOffline: false,
      canaryProxyId: "",
      canaryNodeId: "n1",
    });
  });

  it("a switch: the engine as the component, the proxies, the pin", () => {
    expect(
      buildStartRollout({ kind: "switch", engine: "mtg" }, { ...DEFAULT_CHOICES, mode: "auto", pauseSeconds: 0, proxyIds: ["p1", "p2"], pinVersion: "v2.2.8", canaryProxyId: "p2" }),
    ).toEqual({
      kind: "switch",
      component: "mtg",
      toVersion: "v2.2.8",
      proxyIds: ["p1", "p2"],
      mode: "auto",
      pauseSeconds: 0,
      skipOffline: false,
      canaryProxyId: "p2",
      canaryNodeId: "",
    });
  });

  it("a node rollout: the nodes, agent and edge, a canary node", () => {
    expect(buildStartRollout({ kind: "node" }, { ...DEFAULT_CHOICES, nodeIds: ["n1", "n2"], edge: false, canaryNodeId: "n2", canaryProxyId: "p1" })).toEqual({
      kind: "node",
      nodeIds: ["n1", "n2"],
      agent: true,
      edge: false,
      mode: "manual",
      pauseSeconds: 0,
      skipOffline: false,
      canaryProxyId: "",
      canaryNodeId: "n2",
    });
  });
});

describe("rolloutActions", () => {
  it.each([
    ["running", ["pause", "abort"]],
    ["paused", ["continue", "abort"]],
    ["failed", ["retry", "abort"]],
    ["preparing", ["abort"]],
    ["completed", []],
    ["aborted", []],
  ])("%s takes %j", (status, actions) => {
    expect(rolloutActions(status)).toEqual(actions);
  });
});

describe("tokenField", () => {
  it("keeps, replaces or removes", () => {
    expect(tokenField("", false)).toBeUndefined();
    expect(tokenField("ghp_x", false)).toBe("ghp_x");
    expect(tokenField("ghp_x", true)).toBe("");
  });
});

describe("safeUrl", () => {
  it("takes only http and https", () => {
    expect(safeUrl("https://github.com/x")).toBe("https://github.com/x");
    expect(safeUrl("javascript:alert(1)")).toBeUndefined();
  });
});

describe("mtgBlockers", () => {
  const node = create(NodeSchema, { id: "n", capabilities: ["engine-mtg"] });
  const plain = { type: "faketls", adTag: "", useMiddleProxy: "auto" };
  it.each([
    [{}, ["engine-mtg"], []],
    [{ type: "web" }, ["engine-mtg"], ["web"]],
    [{ adTag: "0123456789abcdef0123456789abcdef" }, ["engine-mtg"], ["adTag"]],
    [{ useMiddleProxy: "on" }, ["engine-mtg"], ["middleProxy"]],
    [{}, [], ["capability"]],
  ])("%j on a node with %j: %j", (init, capabilities, reasons) => {
    const proxy = create(ProxySchema, { ...plain, ...init });
    expect(mtgBlockers(proxy, create(NodeSchema, { ...node, capabilities }))).toEqual(reasons);
  });

  it("does not know about a node that is not loaded: no capability reason", () => {
    expect(mtgBlockers(create(ProxySchema, plain), undefined)).toEqual([]);
  });
});

describe("hasPin", () => {
  it("is true when an asset has a pinned SHA-256", () => {
    expect(hasPin(create(ReleaseSchema, { assets: [{ arch: "amd64", sha256: "" }, { arch: "arm64", sha256: "ab" }] }))).toBe(true);
    expect(hasPin(create(ReleaseSchema, { assets: [{ arch: "amd64", sha256: "" }] }))).toBe(false);
  });
  it("is limited to an arch when one is given", () => {
    expect(hasPin(create(ReleaseSchema, { assets: [{ arch: "arm64", sha256: "ab" }] }), "amd64")).toBe(false);
  });
});

describe("channelUpdates", () => {
  it("names, per channel, the providers that could move, and the engines only on a channel that a proxy follows", () => {
    const components = [
      create(ComponentSchema, { name: "telemt", kind: "engine", channelVersions: { stable: "3.5.12", latest: "3.5.13" }, newest: { stable: "3.5.13", latest: "3.5.13" }, followedChannels: ["stable"] }),
      create(ComponentSchema, { name: "mtg", kind: "engine", channelVersions: { stable: "2.1.0", latest: "2.1.0" }, newest: { stable: "2.2.0", latest: "2.2.0" }, followedChannels: ["latest"] }),
      create(ComponentSchema, { name: "xray", kind: "provider", channelVersions: { latest: "v1" }, newest: { latest: "v2" } }),
      create(ComponentSchema, { name: "psiphon-core", kind: "provider", channelVersions: { stable: "1" }, newest: { stable: "2" } }),
      create(ComponentSchema, { name: "postern", kind: "panel", channelVersions: { stable: "v0.5.0" }, newest: { stable: "v0.6.0" } }),
    ];
    expect(channelUpdates(components)).toEqual({ stable: ["telemt", "psiphon-core"], latest: ["mtg", "xray"] });
  });
});

describe("channelUpdateLines", () => {
  it("lists each channel that channelUpdates names, with its current and newest version", () => {
    const components = [
      create(ComponentSchema, { name: "telemt", kind: "engine", channelVersions: { stable: "3.5.13", latest: "3.5.14" }, newest: { stable: "3.5.14", latest: "3.5.15" }, followedChannels: ["stable"] }),
      create(ComponentSchema, { name: "xray", kind: "provider", channelVersions: { latest: "v1" }, newest: { latest: "v2" } }),
    ];
    expect(channelUpdateLines(components).map(({ component, channel, from, to }) => [component.name, channel, from, to])).toEqual([
      ["telemt", "stable", "3.5.13", "3.5.14"],
      ["xray", "latest", "v1", "v2"],
    ]);
  });
});

describe("outdatedNodes", () => {
  const node = (id: string, agentVersion: string) => create(NodeSchema, { id, name: id, agentVersion });

  it("takes the nodes whose agent is older than the panel, by semver", () => {
    const nodes = [node("a", "0.4.2"), node("b", "v0.5.0"), node("c", "v0.5.0-rc.1"), node("d", "")];
    expect(outdatedNodes(nodes, "v0.5.0").map((n) => n.id)).toEqual(["a", "c"]);
  });

  it("takes none for a panel that is not a release", () => {
    expect(outdatedNodes([node("a", "0.4.2")], "dev")).toEqual([]);
  });
});

describe("posternUpdatable", () => {
  const panel = (init: { canUpdate?: boolean; version?: string; releases?: { version: string }[] }) =>
    create(GetPanelVersionResponseSchema, { version: "v0.5.0", ...init });

  it("is true when the panel can update to a newer release, or a node lags behind it", () => {
    expect(posternUpdatable(panel({ canUpdate: true, releases: [{ version: "v0.6.0" }] }), [])).toBe(true);
    expect(posternUpdatable(panel({}), [create(NodeSchema, { agentVersion: "0.4.0" })])).toBe(true);
  });

  it("is false when up to date, or when the update is refused and no node lags", () => {
    expect(posternUpdatable(panel({ canUpdate: true }), [create(NodeSchema, { agentVersion: "0.5.0" })])).toBe(false);
    expect(posternUpdatable(panel({ canUpdate: false, releases: [{ version: "v0.6.0" }] }), [])).toBe(false);
    expect(posternUpdatable(undefined, [])).toBe(false);
  });
});
