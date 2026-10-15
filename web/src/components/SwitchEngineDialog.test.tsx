import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { SwitchEngineDialog } from "./SwitchEngineDialog";

const MTG_NODE = { id: "node-a", name: "Frankfurt", capabilities: ["rollout-status", "engine-mtg"] };
const OLD_NODE = { id: "node-b", name: "Helsinki", capabilities: ["rollout-status"] };
const PLAIN = { id: "proxy-1", name: "Alpha", nodeId: "node-a", engine: "telemt", type: "faketls", adTag: "", useMiddleProxy: "auto" };

function open(proxies: Record<string, unknown>[]) {
  const panel = createFakePanel({ signedIn: true, nodes: [MTG_NODE, OLD_NODE], proxies });
  const onClose = vi.fn();
  renderWithProviders(<SwitchEngineDialog opened proxyIds={proxies.map((p) => String(p.id))} onClose={onClose} />, { transport: panel.transport });
  return { panel, onClose, user: userEvent.setup() };
}

const mtgRadio = () => screen.findByRole("radio", { name: "mtg" });

describe("SwitchEngineDialog", () => {
  it.each<[string, Record<string, unknown>, TKey]>([
    ["a WEB proxy", { type: "web" }, "versions.switch.reason.web"],
    ["an ad tag", { adTag: "0123456789abcdef0123456789abcdef" }, "versions.switch.reason.adTag"],
    ["the middle proxies on", { useMiddleProxy: "on" }, "versions.switch.reason.middleProxy"],
    ["a node without engine-mtg", { nodeId: "node-b" }, "versions.switch.reason.capability"],
  ])("disables mtg for %s, with the reason", async (_what, init, reason) => {
    open([{ ...PLAIN, ...init }]);
    expect(await mtgRadio()).toBeDisabled();
    expect(await screen.findByText(t(reason), { exact: false })).toBeInTheDocument();
  });

  it("starts a one-proxy switch rollout to mtg", async () => {
    const { panel, user } = open([PLAIN]);
    await waitFor(async () => {
      expect(await mtgRadio()).toBeEnabled();
    });
    await user.click(await mtgRadio());
    expect(screen.getByText(t("versions.rollout.mtgNote"))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "switch", component: "mtg", proxyIds: ["proxy-1"] });
  });

  it("names the proxy that keeps a bulk switch off mtg", async () => {
    open([PLAIN, { ...PLAIN, id: "proxy-2", name: "Beta", adTag: "0123456789abcdef0123456789abcdef" }]);
    expect(await mtgRadio()).toBeDisabled();
    expect(await screen.findByText(`Beta: ${t("versions.switch.reason.adTag")}`)).toBeInTheDocument();
  });
});
