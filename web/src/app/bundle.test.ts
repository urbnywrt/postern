import { describe, expect, it } from "vitest";

import { bundleHref, copyCommand, installCommandFor, kitFile, kitHref, ROLL_EDGE_COMMAND } from "./bundle";

describe("the downloads of the install", () => {
  it("take the path that the panel names", () => {
    expect(bundleHref("node-a", "/api/nodes/node-a/bundle.tar")).toBe("/api/nodes/node-a/bundle.tar");
    expect(kitHref("arm64", "/api/node-kit/arm64")).toBe("/api/node-kit/arm64");
  });

  it("follow no address that is not a path of the API of this panel", () => {
    for (const fromPanel of [
      "https://elsewhere.example.com/kit.tar",
      "//elsewhere.example.com/kit.tar",
      "/\\elsewhere.example.com/kit.tar",
      "javascript:alert(1)",
      "/nodes/node-a",
      "",
    ]) {
      expect(bundleHref("node-a", fromPanel)).toBe("/api/nodes/node-a/bundle.tar");
      expect(kitHref("arm64", fromPanel)).toBe("/api/node-kit/arm64");
    }
    expect(bundleHref("a/b c")).toBe("/api/nodes/a%2Fb%20c/bundle.tar");
    expect(kitHref("amd64")).toBe("/api/node-kit/amd64");
  });

  it("are named as the panel names them", () => {
    expect(kitFile("amd64")).toBe("postern-node-kit-linux-amd64.tar");
    expect(kitFile("arm64")).toBe("postern-node-kit-linux-arm64.tar");
  });
});

describe("the commands of the install", () => {
  it("fill the architecture into the command of the panel", () => {
    expect(installCommandFor("tar -xf postern-node-kit-linux-<ARCH>.tar && sudo bash install.sh", "arm64")).toBe(
      "tar -xf postern-node-kit-linux-arm64.tar && sudo bash install.sh",
    );
    expect(installCommandFor("<ARCH> and <ARCH>", "amd64")).toBe("amd64 and amd64");
    expect(installCommandFor("no placeholder", "amd64")).toBe("no placeholder");
  });

  it("leave out the unpacking of a kit that the panel does not have", () => {
    const command =
      "tar -xf postern-node-kit-linux-<ARCH>.tar && sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node";
    expect(installCommandFor(command, "arm64", false)).toBe(
      "sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node",
    );
    expect(installCommandFor(command, "arm64", true)).toBe(
      "tar -xf postern-node-kit-linux-arm64.tar && sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node",
    );
    // A command that unpacks nothing stays as the panel words it.
    expect(installCommandFor("sudo install-from-the-panel <ARCH>", "amd64", false)).toBe(
      "sudo install-from-the-panel amd64",
    );
  });

  it("make the directory on the server, and copy both files into it, on one line", () => {
    expect(copyCommand("arm64")).toBe(
      "ssh root@<SERVER> mkdir -p /root/postern && " +
        "scp postern-node-kit-linux-arm64.tar postern-node-bundle.tar root@<SERVER>:/root/postern/",
    );
  });

  it("copy the bundle alone without a kit, on one line", () => {
    expect(copyCommand("arm64", false)).toBe(
      "ssh root@<SERVER> mkdir -p /root/postern && scp postern-node-bundle.tar root@<SERVER>:/root/postern/",
    );
  });

  it("never break the line: a prompt of ssh would take the second line that is pasted", () => {
    for (const withKit of [true, false]) {
      expect(copyCommand("amd64", withKit)).not.toMatch(/[\r\n]/);
    }
  });
});

describe("the command that rolls the edge", () => {
  it("writes the file that the agent watches, for a node installed with install.sh or in Docker alike", () => {
    expect(ROLL_EDGE_COMMAND).toBe("sudo sh -c 'umask 077; date +%s > /opt/postern/data/run/roll-edge'");
  });
});
