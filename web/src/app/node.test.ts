import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { NodeSchema } from "../gen/postern/panel/v1/nodes_pb";
import { compareVersions, isProvisioning, nodeBanner } from "./node";

const node = (init: Parameters<typeof create<typeof NodeSchema>>[1] = {}) =>
  create(NodeSchema, {
    status: "online",
    agentVersion: "0.5.0",
    edgeVersion: "0.5.0",
    appliedGeneration: 2n,
    capabilities: ["update-self", "update-edge"],
    lastSeenUnix: 100n,
    ...init,
  });

describe("nodeBanner", () => {
  it("takes the first case that applies", () => {
    expect(nodeBanner(node({ lastSeenUnix: 0n, edgeVersion: "0.4.0" }), "v0.6.0")).toEqual({ kind: "provisioning" });
    expect(nodeBanner(node({ edgeVersion: "0.4.0" }), "v0.6.0")).toEqual({ kind: "agentUpdate", agent: "0.5.0", panel: "0.6.0" });
    expect(nodeBanner(node({ edgeVersion: "0.4.0" }), "v0.5.0")).toEqual({ kind: "edgeOutdated" });
    expect(nodeBanner(node({ edgeVersion: "0.4.0", capabilities: ["update-self"] }), "v0.5.0")).toEqual({ kind: "needsInstall" });
    expect(nodeBanner(node(), "v0.5.0")).toBeNull();
  });

  it("offers no agent from a panel that is not a release, or that it does not know yet", () => {
    expect(nodeBanner(node(), "dev")).toBeNull();
    expect(nodeBanner(node())).toBeNull();
    expect(nodeBanner(node({ agentVersion: "" }), "v0.6.0")).toBeNull();
  });

  it("offers the panel's agent only to an older one", () => {
    expect(nodeBanner(node({ agentVersion: "0.6.0", edgeVersion: "0.6.0" }), "v0.5.0")).toBeNull();
    expect(nodeBanner(node({ agentVersion: "0.5.0-rc.1", edgeVersion: "0.5.0-rc.1" }), "v0.5.0")).toEqual({
      kind: "agentUpdate",
      agent: "0.5.0-rc.1",
      panel: "0.5.0",
    });
  });
});

describe("isProvisioning", () => {
  it("is a node in provisioning that was never seen", () => {
    expect(isProvisioning(node({ status: "provisioning", lastSeenUnix: 0n }))).toBe(true);
    expect(isProvisioning(node({ status: "provisioning" }))).toBe(false);
    expect(isProvisioning(node({ status: "offline", lastSeenUnix: 0n }))).toBe(false);
  });
});

describe("compareVersions", () => {
  it.each([
    ["0.5.0", "0.6.0", -1],
    ["v0.10.0", "0.9.9", 1],
    ["1.2.3", "v1.2.3", 0],
    ["1.2.3-rc.1", "1.2.3", -1],
    ["1.2.3-rc.2", "1.2.3-rc.10", -1],
    ["1.2.3-alpha", "1.2.3-alpha.1", -1],
    ["1.2.3-beta", "1.2.3-alpha", 1],
    ["1.2.3-1", "1.2.3-alpha", -1],
    ["1.2.3+build.5", "1.2.3", 0],
    ["2.0.0", "1.99.99", 1],
    // Letters then digits: the letters, then the number by value (our tags are v1.0.0-rcN).
    ["v1.0.0-rc9", "v1.0.0-rc10", -1],
    ["v1.0.0-rc10", "v1.0.0", -1],
    ["v1.0.0-rc2", "v1.0.0-rc10", -1],
    ["1.0.0-beta2", "1.0.0-beta11", -1],
    ["1.0.0-beta11", "1.0.0-rc1", -1],
    ["1.0.0-rc1", "1.0.0-rc1.1", -1],
    ["1.0.0-rc10", "1.0.0-rc10", 0],
    ["1.0.0-rc", "1.0.0-rc1", -1],
    ["1.0.0-rc9", "1.0.0-rcx", -1],
    ["1.0.0-rc9", "1.0.0-rc2x", -1],
    ["1.0.0-rc10", "1.0.0-rc2x", -1],
  ])("%s against %s is %i", (a, b, sign) => {
    expect(Math.sign(compareVersions(a, b))).toBe(sign);
    expect(Math.sign(compareVersions(b, a))).toBe(-sign || 0);
  });

  it("is a total order on pre-releases of every shape", () => {
    const vs = ["1.0.0", "1.0.0-rc", "1.0.0-rc1", "1.0.0-rc2", "1.0.0-rc9", "1.0.0-rc10", "1.0.0-rc2x", "1.0.0-rc-x",
      "1.0.0-rcx", "1.0.0-rc.1", "1.0.0-rc.10", "1.0.0-1", "1.0.0-Beta2", "1.0.0-beta", "1.0.0-beta2", "1.0.0-beta11",
      "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-rc1.1", "1.0.0-a1b2"];
    const sorted = [...vs].sort(compareVersions);
    for (let i = 0; i < sorted.length; i++) {
      for (let j = i + 1; j < sorted.length; j++) {
        expect(Math.sign(compareVersions(sorted[i] ?? "", sorted[j] ?? ""))).toBe(-1);
      }
    }
  });
});
