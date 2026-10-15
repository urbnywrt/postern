import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t, type TKey } from "../test/t";

const now = () => Math.floor(Date.now() / 1000);
// A Select or a Modal can repeat a label, so a field is asked for by its input.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);

function openNodes(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, ...options });
  const view = renderApp({ route: "/nodes", transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

describe("Nodes", () => {
  it("lists the nodes with their address, versions, generations and last seen", async () => {
    openNodes({
      nodes: [
        {
          id: "node-a",
          name: "Frankfurt",
          mgmtHost: "203.0.113.7",
          mgmtPort: 8443,
          status: "online",
          agentVersion: "0.1.0",
          edgeVersion: "0.1.1",
          desiredGeneration: 7n,
          appliedGeneration: 6n,
          lastSeenUnix: BigInt(now() - 120),
        },
        { id: "node-b", name: "Amsterdam", mgmtHost: "2001:db8::1", mgmtPort: 9000, status: "offline" },
      ],
    });

    expect(await screen.findByRole("heading", { name: t("nodes.title") })).toBeInTheDocument();
    const frankfurt = within(await screen.findByRole("row", { name: /Frankfurt/ }));
    expect(frankfurt.getByRole("link", { name: "Frankfurt" })).toHaveAttribute("href", "/nodes/node-a");
    expect(frankfurt.getByText(t("status.node.online"))).toBeInTheDocument();
    expect(frankfurt.getByText("203.0.113.7:8443")).toBeInTheDocument();
    expect(frankfurt.getByText("0.1.0 / 0.1.1")).toBeInTheDocument();
    expect(frankfurt.getByText("6 / 7")).toBeInTheDocument();
    expect(frankfurt.getByText("2 minutes ago")).toBeInTheDocument();

    const amsterdam = within(screen.getByRole("row", { name: /Amsterdam/ }));
    // An IPv6 address is written in brackets, so that the port can be told from it.
    expect(amsterdam.getByText("[2001:db8::1]:9000")).toBeInTheDocument();
    expect(amsterdam.getByText(t("status.node.offline"))).toBeInTheDocument();
  });

  it("marks a node whose edge runs another version than its agent", async () => {
    openNodes({
      nodes: [
        { id: "node-a", name: "Frankfurt", agentVersion: "0.1.1", edgeVersion: "0.1.0", appliedGeneration: 5n },
        { id: "node-b", name: "Amsterdam", agentVersion: "0.1.1", edgeVersion: "0.1.1", appliedGeneration: 5n },
      ],
    });

    const frankfurt = within(await screen.findByRole("row", { name: /Frankfurt/ }));
    expect(frankfurt.getByText("0.1.1 / 0.1.0")).toBeInTheDocument();
    expect(frankfurt.getByText(t("node.edgeOutdated"))).toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /Amsterdam/ })).queryByText(t("node.edgeOutdated"))).not.toBeInTheDocument();
  });

  it("says that there are no nodes yet", async () => {
    openNodes();

    expect(await screen.findByText(t("nodes.empty"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("nodes.add") })).toBeInTheDocument();
  });

  it("adds a node: the dialog shows how to install it, and the list has the new node when it is closed", async () => {
    const { user } = openNodes({ nodes: [{ id: "node-a", name: "Frankfurt" }] });
    await screen.findByText("Frankfurt");

    await user.click(screen.getByRole("button", { name: t("nodes.add") }));
    await user.type(field("nodes.form.name"), "Amsterdam");
    await user.type(field("nodes.form.mgmtHost"), "203.0.113.9");
    await user.click(screen.getByRole("button", { name: t("nodes.form.create") }));

    const dialog = await screen.findByRole("dialog", { name: t("nodes.created.title") });
    expect(await within(dialog).findByRole("button", { name: t("nodes.docker.get") })).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: t("nodes.install.manualBlock") }));
    expect(await within(dialog).findByRole("link", { name: t("nodes.install.downloadBundle") })).toHaveAttribute(
      "href",
      expect.stringMatching(/^\/api\/nodes\/.+\/bundle\.tar$/),
    );

    await user.click(within(dialog).getByRole("button", { name: t("common.done") }));
    expect(await screen.findByRole("row", { name: /Amsterdam/ })).toBeInTheDocument();
    // The node is not online yet: it waits for its agent.
    expect(within(screen.getByRole("row", { name: /Amsterdam/ })).getByText(t("status.node.provisioning"))).toBeInTheDocument();
  });
});
