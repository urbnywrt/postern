import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { NodeSchema } from "../gen/postern/panel/v1/nodes_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { NodeEgressSettings } from "./NodeEgressSettings";

const NODE = { id: "node-a", name: "Frankfurt" };
const OTHER = { id: "node-b", name: "Amsterdam" };
const CHAINS = [
  { id: "chain-main", name: "Main" },
  { id: "chain-own", name: "Own of Amsterdam", nodeId: OTHER.id },
];

const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);

function open(init: { defaultChainId?: string; dnsMode?: string } = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [{ ...NODE, ...init }, OTHER], chains: CHAINS });
  const node = create(NodeSchema, { ...NODE, ...init });
  renderWithProviders(<NodeEgressSettings node={node} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

describe("NodeEgressSettings", () => {
  it("sets the default chain and the DNS mode of the node", async () => {
    const { panel, user } = open();
    expect(field("nodes.egress.defaultChain")).toHaveValue(t("nodes.egress.direct"));
    expect(field("nodes.egress.dnsMode")).toHaveValue(t("nodes.egress.dnsDoh"));

    await user.click(field("nodes.egress.defaultChain"));
    // The chains of another node are not offered.
    expect(screen.queryByRole("option", { name: "Own of Amsterdam" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("option", { name: "Main" }));
    await user.click(field("nodes.egress.dnsMode"));
    await user.click(await screen.findByRole("option", { name: t("nodes.egress.dnsSystem") }));
    await user.click(screen.getByRole("button", { name: t("nodes.egress.save") }));

    await waitFor(() => {
      expect(panel.rpc.setNodeDnsMode).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.setNodeDefaultChain.mock.calls[0]?.[0]).toMatchObject({ nodeId: NODE.id, chainId: "chain-main" });
    expect(panel.rpc.setNodeDnsMode.mock.calls[0]?.[0]).toMatchObject({ nodeId: NODE.id, dnsMode: "system" });
    expect(await screen.findByText(t("nodes.egress.saved"))).toBeInTheDocument();
  });

  it("sends only what changed, and none for the default DNS mode of the node", async () => {
    const { panel, user } = open({ defaultChainId: "chain-main" });
    await screen.findByDisplayValue("Main");
    await user.click(field("nodes.egress.defaultChain"));
    await user.click(await screen.findByRole("option", { name: t("nodes.egress.direct") }));
    await user.click(screen.getByRole("button", { name: t("nodes.egress.save") }));

    await waitFor(() => {
      expect(panel.rpc.setNodeDefaultChain).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.setNodeDefaultChain.mock.calls[0]?.[0]).toMatchObject({ nodeId: NODE.id, chainId: "" });
    expect(panel.rpc.setNodeDnsMode).not.toHaveBeenCalled();
  });

  it("says why when the panel cannot list the chains", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], chains: CHAINS });
    panel.rpc.listChains.mockImplementation(() => {
      throw new ConnectError("the panel could not list the chains", Code.Internal);
    });
    renderWithProviders(<NodeEgressSettings node={create(NodeSchema, NODE)} />, { transport: panel.transport });

    expect(await screen.findByText("the panel could not list the chains")).toBeInTheDocument();
  });
});
