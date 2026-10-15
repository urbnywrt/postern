import type { Node } from "../gen/postern/panel/v1/nodes_pb";

/**
 * Whether the edge of a node runs another version than its agent. An edge keeps the binary
 * that it was started with when the node is updated, until the operator rolls it (Ruling 38).
 * Only a node that has applied a state has an edge; one that does not say its version is older
 * than the report, or does not answer, and is taken for outdated as well.
 */
export function edgeOutdated(node: Node): boolean {
  return node.agentVersion !== "" && node.appliedGeneration > 0n && node.edgeVersion !== node.agentVersion;
}

/**
 * A node that was made in the panel and has not connected yet: its page is the install,
 * and the rest of it waits for the node.
 */
export function isProvisioning(node: Node): boolean {
  return node.status === "provisioning" && node.lastSeenUnix === 0n;
}

/** The one thing that the page of a node asks of the admin first, above its tabs. */
export type NodeBannerCase =
  | { kind: "provisioning" }
  | { kind: "agentUpdate"; agent: string; panel: string }
  | { kind: "edgeOutdated" }
  | { kind: "needsInstall" };

/** A version of a release, as "1.2.3": without its "v", or undefined for a build that is not a release ("dev"). */
function releaseVersion(version: string): string | undefined {
  const match = /^v?(\d+\.\d+\.\d+\S*)$/.exec(version.trim());
  return match?.[1];
}

/** Compares two runs of digits by value, of any size. */
function compareDigits(x: string, y: string): number {
  const a = x.replace(/^0+/, "");
  const b = y.replace(/^0+/, "");
  if (a.length !== b.length) return a.length - b.length;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compares two pre-release identifiers that are not numbers, as release.Compare in Go does:
 * by the leading letters (ASCII), then what follows them: nothing (lowest), a number by value
 * (rc9 < rc10), or anything else by ASCII (highest). A key keeps the order total.
 */
function compareText(x: string, y: string): number {
  const split = (s: string) => {
    const letters = /^[A-Za-z]*/.exec(s)?.[0] ?? "";
    const rest = s.slice(letters.length);
    const kind = rest === "" ? 0 : /^\d+$/.test(rest) ? 1 : 2;
    return { letters, rest, kind };
  };
  const l = split(x);
  const r = split(y);
  if (l.letters !== r.letters) return l.letters < r.letters ? -1 : 1;
  if (l.kind !== r.kind) return l.kind - r.kind;
  if (l.kind === 1) return compareDigits(l.rest, r.rest);
  return l.rest < r.rest ? -1 : l.rest > r.rest ? 1 : 0;
}

/**
 * Compares two versions of releases ("1.2.3", "v1.2.3-rc.1") as semver orders them: by
 * major, minor and patch, and a pre-release before its release, pre-releases by their
 * identifiers, with one deviation that release.Compare in Go shares: an identifier of letters
 * then digits is compared by the letters, then the number by value, so rc10 is newer than
 * rc9. Build metadata ("+...") is ignored. Negative when `a` is older.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (version: string) => {
    const bare = version.trim().replace(/^v/, "").split("+")[0] ?? "";
    const dash = bare.indexOf("-");
    const core = dash < 0 ? bare : bare.slice(0, dash);
    const pre = dash < 0 ? "" : bare.slice(dash + 1);
    return { core: core.split(".").map((part) => Number.parseInt(part, 10) || 0), pre };
  };
  const left = parse(a);
  const right = parse(b);
  for (let i = 0; i < 3; i++) {
    const diff = (left.core[i] ?? 0) - (right.core[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (left.pre === right.pre) return 0;
  if (left.pre === "") return 1;
  if (right.pre === "") return -1;
  const leftIds = left.pre.split(".");
  const rightIds = right.pre.split(".");
  const numeric = /^\d+$/;
  for (let i = 0; i < Math.max(leftIds.length, rightIds.length); i++) {
    const x = leftIds[i];
    const y = rightIds[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (numeric.test(x) && numeric.test(y)) return compareDigits(x, y);
    if (numeric.test(x)) return -1;
    if (numeric.test(y)) return 1;
    const c = compareText(x, y);
    if (c !== 0) return c;
  }
  return 0;
}

/**
 * Which banner the page of a node shows, the first that applies: a node never seen is to be
 * installed; an agent that can update itself and runs an older release than the panel is
 * offered the panel's; an edge behind its agent is to be rolled, when the node can roll it;
 * a node that cannot take an update itself needs a new build (as its versions card says).
 */
export function nodeBanner(node: Node, panelVersion = ""): NodeBannerCase | null {
  if (node.lastSeenUnix === 0n) {
    return { kind: "provisioning" };
  }
  const canAgent = node.capabilities.includes("update-self");
  const canEdge = node.capabilities.includes("update-edge");
  const agent = releaseVersion(node.agentVersion);
  const panel = releaseVersion(panelVersion);
  if (canAgent && agent !== undefined && panel !== undefined && compareVersions(agent, panel) < 0) {
    return { kind: "agentUpdate", agent, panel };
  }
  if (canEdge && edgeOutdated(node)) {
    return { kind: "edgeOutdated" };
  }
  if (!canAgent || !canEdge) {
    return { kind: "needsInstall" };
  }
  return null;
}
