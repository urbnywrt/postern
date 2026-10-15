import { create } from "@bufbuild/protobuf";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { NodeSchema } from "../gen/postern/panel/v1/nodes_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { NodeManagement } from "./NodeManagement";

const NODE = { id: "node-a", name: "Frankfurt", mgmtMode: "port" };
const LISTENERS = [
  { id: "l-443", nodeId: NODE.id, kind: "tls", port: 443 },
  { id: "l-443b", nodeId: NODE.id, kind: "tls", bindIp: "198.51.100.7", port: 443 },
  { id: "l-8443", nodeId: NODE.id, kind: "tls", port: 8443 },
  { id: "l-up", nodeId: NODE.id, kind: "http-upstream", bindIp: "127.0.0.1", port: 40443 },
  { id: "l-other", nodeId: "node-b", kind: "tls", port: 9443 },
];

const FIELD = { selector: "input, textarea" };

function open(init: Partial<typeof NODE> & { mgmtSni?: string; mgmtPublicPort?: number } = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [{ ...NODE, ...init }], listeners: LISTENERS });
  renderWithProviders(<NodeManagement node={create(NodeSchema, { ...NODE, ...init })} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

describe("NodeManagement", () => {
  it("shows the mode, and switches to hidden with an SNI and a tls port of the node", async () => {
    const { panel, user } = open();
    expect(screen.getByText(t("nodes.mgmt.modePort"))).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("nodes.mgmt.switch") }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByLabelText(t("nodes.mgmt.mode"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("nodes.mgmt.modeHidden") }));
    await user.type(within(dialog).getByLabelText(t("nodes.mgmt.sni"), FIELD), "mgmt.example.net");
    await user.click(within(dialog).getByLabelText(t("nodes.mgmt.publicPort"), FIELD));
    // One entry to a port, and only the tls listeners of this node.
    const options = (await screen.findAllByRole("option")).map((o) => o.textContent);
    expect(options).toEqual(["443", "8443"]);
    await user.click(screen.getByRole("option", { name: "8443" }));
    await user.click(within(dialog).getByRole("button", { name: t("nodes.mgmt.apply") }));

    await waitFor(() => {
      expect(panel.rpc.setNodeMgmtMode).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.setNodeMgmtMode.mock.calls[0]?.[0]).toMatchObject({
      nodeId: NODE.id,
      mode: "hidden",
      mgmtSni: "mgmt.example.net",
      publicPort: 8443,
    });
    expect(await screen.findByText(t("nodes.mgmt.done"))).toBeInTheDocument();
  });

  it("asks for the SNI and the port before it sends a switch to hidden", async () => {
    const { panel, user } = open();
    await user.click(screen.getByRole("button", { name: t("nodes.mgmt.switch") }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByLabelText(t("nodes.mgmt.mode"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("nodes.mgmt.modeHidden") }));
    await user.click(within(dialog).getByRole("button", { name: t("nodes.mgmt.apply") }));

    expect(await within(dialog).findAllByText(t("nodes.mgmt.required"))).toHaveLength(2);
    expect(panel.rpc.setNodeMgmtMode).not.toHaveBeenCalled();
  });

  it("shows why a switch back failed, and keeps the dialog open", async () => {
    const { panel, user } = open({ mgmtMode: "hidden", mgmtSni: "mgmt.example.net", mgmtPublicPort: 443 });
    expect(screen.getByText("mgmt.example.net")).toBeInTheDocument();
    panel.rpc.setNodeMgmtMode.mockImplementation(() => ({
      ok: false,
      reason: "the agent did not answer on its management port 61000: connection refused",
      node: create(NodeSchema, NODE),
    }));

    await user.click(screen.getByRole("button", { name: t("nodes.mgmt.switch") }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByLabelText(t("nodes.mgmt.mode"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("nodes.mgmt.modePort") }));
    await user.click(within(dialog).getByRole("button", { name: t("nodes.mgmt.apply") }));

    expect(await within(dialog).findByText(/connection refused/)).toBeInTheDocument();
    expect(within(dialog).getByText(t("nodes.mgmt.failed"))).toBeInTheDocument();
    expect(panel.rpc.setNodeMgmtMode.mock.calls[0]?.[0]).toMatchObject({ mode: "port", mgmtSni: "", publicPort: 0 });
  });
});
