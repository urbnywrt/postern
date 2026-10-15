import type { TFunction } from "i18next";

import i18n from "../i18n";

import type { RolloutAction, StartRolloutVars } from "../api/hooks/versions";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import type { Component, GetPanelVersionResponse, Release, Rollout } from "../gen/postern/panel/v1/versions_pb";
import { orDash } from "./format";
import { compareVersions } from "./node";

// What the Versions page works out from what the panel says: the request of a
// rollout, the actions of a rollout in a status, the channels of a component.

/** What a rollout is to change: a channel of a component, the engine of proxies, or the nodes themselves. */
export type RolloutTarget =
  | { kind: "version"; component: string; componentKind: string; channel: string; toVersion: string; followed?: boolean }
  | { kind: "switch"; engine: string; proxyIds?: string[] }
  | { kind: "node"; nodeIds?: string[]; agent?: boolean; edge?: boolean };

/** What the admin chose in the rollout dialog. */
export interface RolloutChoices {
  mode: "manual" | "auto";
  /** The wait after a step in auto mode; 0 is the default of the panel (120 s). */
  pauseSeconds: number;
  /** Empty lets the panel pick. */
  canaryProxyId: string;
  canaryNodeId: string;
  skipOffline: boolean;
  /** The proxies of a switch. */
  proxyIds: string[];
  /** For a switch: the version to pin the proxies to; empty lets them follow their channel. */
  pinVersion: string;
  /** The nodes of a node rollout; empty is every node. */
  nodeIds: string[];
  agent: boolean;
  edge: boolean;
}

export const DEFAULT_CHOICES: RolloutChoices = {
  mode: "manual",
  pauseSeconds: 120,
  canaryProxyId: "",
  canaryNodeId: "",
  skipOffline: false,
  proxyIds: [],
  pinVersion: "",
  nodeIds: [],
  agent: true,
  edge: true,
};

/** Whether the first step of the rollout is a proxy (engines and switches) or a node (providers and node rollouts). */
export function canaryIsProxy(target: RolloutTarget): boolean {
  return target.kind === "switch" || (target.kind === "version" && target.componentKind === "engine");
}

/**
 * The StartRollout request for a target and the choices: only the fields that
 * the kind has; the pause only in auto mode; the canary that the kind takes.
 */
export function buildStartRollout(target: RolloutTarget, choices: RolloutChoices): StartRolloutVars {
  const common = {
    mode: choices.mode,
    pauseSeconds: choices.mode === "auto" ? Math.max(0, Math.round(choices.pauseSeconds)) : 0,
    skipOffline: choices.skipOffline,
    canaryProxyId: canaryIsProxy(target) ? choices.canaryProxyId : "",
    canaryNodeId: canaryIsProxy(target) ? "" : choices.canaryNodeId,
  };
  switch (target.kind) {
    case "version":
      return { kind: "version", component: target.component, channel: target.channel, toVersion: target.toVersion, ...common };
    case "switch":
      return { kind: "switch", component: target.engine, toVersion: choices.pinVersion, proxyIds: choices.proxyIds, ...common };
    case "node":
      return { kind: "node", nodeIds: choices.nodeIds, agent: choices.agent, edge: choices.edge, ...common };
  }
}

/**
 * The actions that a rollout in a status takes: Continue only when paused,
 * Retry only when failed, Pause when running, Abort while it is not over:
 * preparing, running, paused or failed (Abort works even when no executor
 * runs it, and cancels a stuck preparation).
 */
export function rolloutActions(status: string): RolloutAction[] {
  const actions: RolloutAction[] = [];
  if (status === "paused") actions.push("continue");
  if (status === "running") actions.push("pause");
  if (status === "failed") actions.push("retry");
  // The runner aborts any rollout that is not over, a stuck preparation too.
  if (status === "preparing" || status === "running" || status === "paused" || status === "failed") actions.push("abort");
  return actions;
}

/** The color of the status of a rollout or a step. */
export function statusColor(status: string): string {
  switch (status) {
    case "completed":
    case "done":
    case "ready":
      return "teal";
    case "failed":
    case "reverted":
    case "unusable":
      return "red";
    case "paused":
    case "skipped":
      return "yellow";
    case "aborted":
    case "unchecked":
    case "pending":
      return "gray";
    default:
      return "blue";
  }
}

/** What a rollout is about, in a line: "telemt, stable: 3.5.12 → 3.5.13". */
export function rolloutSummary(rollout: Rollout, t: TFunction): string {
  switch (rollout.kind) {
    case "switch":
      return rollout.toVersion !== ""
        ? t("versions.rolloutView.summarySwitchPinned", { engine: rollout.toEngine, version: rollout.toVersion })
        : t("versions.rolloutView.summarySwitch", { engine: rollout.toEngine });
    case "node":
      return t("versions.rolloutView.summaryNode", {
        version: orDash(rollout.toVersion),
        parts: [rollout.agent ? t("versions.rollout.agent") : "", rollout.edge ? t("versions.rollout.edge") : ""]
          .filter((part) => part !== "")
          .join(" + "),
      });
    default:
      return t("versions.rolloutView.summaryVersion", {
        component: rollout.component,
        channel: rollout.channel,
        from: orDash(rollout.fromVersion),
        to: rollout.toVersion,
      });
  }
}

const CHANNEL_ORDER = ["stable", "latest"];

/** The channels of a component in a fixed order, stable first, and any others after. */
export function channelsOf(component: Component): string[] {
  const names = new Set([...Object.keys(component.channelVersions), ...Object.keys(component.newest)]);
  return [...CHANNEL_ORDER.filter((c) => names.has(c)), ...[...names].filter((c) => !CHANNEL_ORDER.includes(c)).sort()];
}

/** The version that a rollout could move a channel to: of an engine or a provider, when the newest differs. */
export function updatableTo(component: Component, channel: string): string | undefined {
  if (component.kind !== "engine" && component.kind !== "provider") return undefined;
  const newest = component.newest[channel] ?? "";
  return newest !== "" && newest !== (component.channelVersions[channel] ?? "") ? newest : undefined;
}

/** Only a link of the web, never javascript: or data:. */
export function safeUrl(url: string): string | undefined {
  return /^https?:\/\//i.test(url) ? url : undefined;
}

/** A token as the source form sends it: unset keeps the stored one, "" removes it, anything else replaces it. */
export function tokenField(typed: string, remove: boolean): string | undefined {
  if (remove) return "";
  return typed !== "" ? typed : undefined;
}

/**
 * The word for a value that the panel sends (a status, a kind, a channel):
 * the translation under `prefix` when there is one, else the value itself, so
 * that a value of a newer panel still shows.
 */
export function term(t: TFunction, prefix: string, value: string): string {
  const key = `${prefix}.${value}`;
  return value !== "" && i18n.exists(key) ? (t as unknown as (key: string) => string)(key) : value;
}

/**
 * Why a proxy cannot run on mtg, as far as the panel shows it: a WEB proxy, an
 * ad tag, the middle proxies turned on, or a node without the capability
 * engine-mtg (unknown while the node is not loaded). Engine overrides and a
 * mask target override are not in the API: the panel refuses those itself,
 * and the dialog shows its words.
 */
export type MtgBlocker = "web" | "adTag" | "middleProxy" | "capability";

export function mtgBlockers(proxy: Proxy, node: Node | undefined): MtgBlocker[] {
  const out: MtgBlocker[] = [];
  if (proxy.type === "web") out.push("web");
  if (proxy.adTag !== "") out.push("adTag");
  if (proxy.useMiddleProxy === "on") out.push("middleProxy");
  if (node !== undefined && !node.capabilities.includes("engine-mtg")) out.push("capability");
  return out;
}

/** Whether a release has a pinned SHA-256 (for `arch`, when given): only such a version can be named in a desired state. */
export function hasPin(release: Release, arch = ""): boolean {
  return release.assets.some((a) => a.sha256 !== "" && (arch === "" || a.arch === arch));
}

/** Whether a proxy follows the channel of an engine; the panel does not say it of the other kinds. */
export function followsChannel(component: Component, channel: string): boolean {
  return component.followedChannels.includes(channel);
}

/** A channel of an engine or a provider that a rollout could move to a newer release. */
export interface ChannelUpdate {
  component: Component;
  channel: string;
  from: string;
  to: string;
}

/** The channels that could move to a newer release: of a provider, or of an engine when a proxy follows the channel. */
export function channelUpdateLines(components: Component[]): ChannelUpdate[] {
  const out: ChannelUpdate[] = [];
  for (const component of components) {
    for (const channel of channelsOf(component)) {
      const to = updatableTo(component, channel);
      if (to !== undefined && (component.kind !== "engine" || followsChannel(component, channel))) {
        out.push({ component, channel, from: component.channelVersions[channel] ?? "", to });
      }
    }
  }
  return out;
}

/** By channel, the engines and providers whose channel could move to a newer release: an engine only on a channel that a proxy follows. */
export function channelUpdates(components: Component[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of channelUpdateLines(components)) (out[line.channel] ??= []).push(line.component.name);
  return out;
}

/**
 * The nodes whose agent is older than the panel, which a node rollout brings up
 * to it. A node that never told its version counts for none, and so does every
 * node of a panel that is not a release (a dev build).
 */
export function outdatedNodes(nodes: Node[], panelVersion: string): Node[] {
  if (!/^v?\d+\.\d+/.test(panelVersion)) return [];
  return nodes.filter((node) => node.agentVersion !== "" && compareVersions(node.agentVersion, panelVersion) < 0);
}

/** Whether Postern can be updated: the panel to a newer release it may install, or a node to the panel's version. */
export function posternUpdatable(panel: Pick<GetPanelVersionResponse, "version" | "canUpdate" | "releases"> | undefined, nodes: Node[]): boolean {
  if (panel === undefined) return false;
  return (panel.canUpdate && panel.releases.length > 0) || outdatedNodes(nodes, panel.version).length > 0;
}
