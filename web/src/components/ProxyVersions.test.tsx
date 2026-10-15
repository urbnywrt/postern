import { configure, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

// Under the load of the whole suite, the first render of a page (its lazy route
// included) and the clicks through it take longer than the defaults of 1 s for a
// find and 5 s for a test, so this file waits longer for both.
configure({ asyncUtilTimeout: 5_000 });
const SLOW = { timeout: 20_000 };

const NODE = { id: "node-a", name: "Frankfurt", arch: "amd64", capabilities: ["rollout-status", "engine-mtg"] };
const PROXY = {
  id: "proxy-1",
  name: "Alpha",
  nodeId: "node-a",
  engine: "telemt",
  engineVersion: "3.5.13",
  versionSource: "channel",
  channel: "stable",
  status: { phase: "serving", runningEngine: "telemt", runningVersion: "3.5.12", failedVersion: "3.5.13" },
};
const RELEASES = [
  { component: "telemt", version: "3.5.13", assets: [{ arch: "amd64", sha256: "a".repeat(64) }] },
  { component: "telemt", version: "3.5.14", assets: [{ arch: "amd64", sha256: "" }] },
  { component: "telemt", version: "3.5.12", assets: [{ arch: "amd64", sha256: "b".repeat(64) }] },
];
const FIELD = { selector: "input" };

function openProxy() {
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], proxies: [PROXY], releases: RELEASES });
  renderApp({ route: "/proxies/proxy-1", transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const section = () => screen.findByRole("region", { name: t("proxy.versions.title") });

describe("ProxyVersions", SLOW, () => {
  it("shows what runs and what should, with the source and the failed version", async () => {
    openProxy();
    const versions = await section();
    expect(within(versions).getByText("telemt 3.5.12")).toBeInTheDocument();
    expect(within(versions).getByText(`telemt 3.5.13 · ${t("proxy.versions.source.channel", { channel: "stable" })}`)).toBeInTheDocument();
    expect(within(versions).getByText(t("proxy.versions.failed", { version: "3.5.13" }))).toBeInTheDocument();
  });

  it("pins the proxy to a version that has a pin, and only to those", async () => {
    const { panel, user } = openProxy();
    const versions = await section();
    await user.click(within(versions).getByLabelText(t("proxy.versions.pin"), FIELD));
    expect(await screen.findByRole("option", { name: "3.5.12" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "3.5.14" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: "3.5.12" }));
    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1", engineVersion: "3.5.12" });
  });

  it("opens the switch of the engine", async () => {
    const { user } = openProxy();
    const versions = await section();
    await user.click(within(versions).getByRole("button", { name: t("proxy.versions.switch") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleSwitchOne", { name: "Alpha" }) })).toBeInTheDocument();
  });
});
