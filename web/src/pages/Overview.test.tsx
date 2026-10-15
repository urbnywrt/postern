import { Code, ConnectError } from "@connectrpc/connect";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const now = () => Math.floor(Date.now() / 1000);

function openOverview(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, ...options });
  const view = renderApp({ route: "/", transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

/** A tile is there once its node has been listed. */
const tile = async (name: string) => within(await screen.findByRole("article", { name }));

afterEach(() => {
  vi.useRealTimers();
});

describe("Overview", () => {
  it("shows a tile for each node: its status, versions, generations and when it was last seen", async () => {
    openOverview({
      nodes: [
        {
          id: "node-a",
          name: "Frankfurt",
          status: "online",
          agentVersion: "0.1.0",
          edgeVersion: "0.1.1",
          desiredGeneration: 7n,
          appliedGeneration: 7n,
          lastSeenUnix: BigInt(now() - 5 * 60),
        },
        { id: "node-b", name: "Amsterdam", status: "offline", agentVersion: "0.0.9", edgeVersion: "0.0.9" },
      ],
    });

    expect(await screen.findByRole("heading", { name: t("overview.title") })).toBeInTheDocument();
    const frankfurt = await tile("Frankfurt");
    expect(frankfurt.getByText(t("status.node.online"))).toBeInTheDocument();
    expect(frankfurt.getByText("0.1.0")).toBeInTheDocument();
    expect(frankfurt.getByText("0.1.1")).toBeInTheDocument();
    expect(frankfurt.getByText("7 / 7")).toBeInTheDocument();
    expect(frankfurt.getByText("5 minutes ago")).toBeInTheDocument();
    expect(frankfurt.queryByText(t("node.applying"))).not.toBeInTheDocument();

    const amsterdam = await tile("Amsterdam");
    expect(amsterdam.getByText(t("status.node.offline"))).toBeInTheDocument();
  });

  it("links each tile to the page of its node", async () => {
    openOverview({ nodes: [{ id: "node-a", name: "Frankfurt" }] });

    expect(await screen.findByRole("link", { name: "Frankfurt" })).toHaveAttribute("href", "/nodes/node-a");
  });

  it("says that a node is still applying a state, when it has not caught up with the panel", async () => {
    openOverview({ nodes: [{ id: "node-a", name: "Frankfurt", desiredGeneration: 9n, appliedGeneration: 7n }] });

    await screen.findByText("Frankfurt");
    const frankfurt = await tile("Frankfurt");
    expect(frankfurt.getByText("7 / 9")).toBeInTheDocument();
    expect(frankfurt.getByText(t("node.applying"))).toBeInTheDocument();
  });

  it("says on the tile why a node does not run its state", async () => {
    openOverview({
      nodes: [
        {
          id: "node-a",
          name: "Frankfurt",
          desiredGeneration: 9n,
          appliedGeneration: 7n,
          lastError: "the node refused the desired state of the panel: invalid node state: listener \"l1\": bad port",
        },
      ],
    });

    const frankfurt = await tile("Frankfurt");
    expect(frankfurt.getByText(t("node.failing"))).toBeInTheDocument();
    expect(frankfurt.queryByText(t("node.applying"))).not.toBeInTheDocument();
    expect(frankfurt.getByText(/invalid node state: listener "l1": bad port/)).toBeInTheDocument();
  });

  it("marks on the tile an edge that runs another version than the agent", async () => {
    openOverview({
      nodes: [
        { id: "node-a", name: "Frankfurt", agentVersion: "0.1.1", edgeVersion: "0.1.0", appliedGeneration: 5n },
        { id: "node-b", name: "Amsterdam", agentVersion: "0.1.1", edgeVersion: "0.1.1", appliedGeneration: 5n },
      ],
    });

    expect((await tile("Frankfurt")).getByText(t("node.edgeOutdated"))).toBeInTheDocument();
    expect((await tile("Amsterdam")).queryByText(t("node.edgeOutdated"))).not.toBeInTheDocument();
  });

  it("shows a node that has not connected yet without invented numbers", async () => {
    openOverview({
      nodes: [
        {
          id: "node-a",
          name: "Fresh",
          status: "provisioning",
          agentVersion: "",
          edgeVersion: "",
          desiredGeneration: 0n,
          appliedGeneration: 0n,
          lastSeenUnix: 0n,
        },
      ],
    });

    await screen.findByText("Fresh");
    const fresh = await tile("Fresh");
    expect(fresh.getByText(t("status.node.provisioning"))).toBeInTheDocument();
    expect(fresh.getByText(t("common.never"))).toBeInTheDocument();
    // No agent version, no edge version: a dash each, not an empty gap.
    expect(fresh.getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("shows a status that this version does not know as it is", async () => {
    openOverview({ nodes: [{ id: "node-a", name: "Frankfurt", status: "maintenance" }] });

    await screen.findByText("Frankfurt");
    expect((await tile("Frankfurt")).getByText("maintenance")).toBeInTheDocument();
  });

  it("says that there are no nodes yet, and offers to add the first", async () => {
    openOverview();

    expect(await screen.findByText(t("overview.empty"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("nodes.add") })).toHaveAttribute("href", "/nodes");
  });

  it("says why when the panel cannot list the nodes, and tries again on request", async () => {
    const { panel, user } = openOverview({ nodes: [{ id: "node-a", name: "Frankfurt" }] });
    panel.rpc.listNodes.mockImplementationOnce(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });

    expect(await screen.findByText("the database is locked")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("common.retry") }));

    expect(await screen.findByText("Frankfurt")).toBeInTheDocument();
  });

  it("keeps the tiles when a later refresh fails, and says that they may be out of date", async () => {
    const { panel, queryClient } = openOverview({ nodes: [{ id: "node-a", name: "Frankfurt" }] });
    await screen.findByText("Frankfurt");

    panel.rpc.listNodes.mockImplementation(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: ["nodes"] });
    });

    expect(await screen.findByText(t("errors.stale"))).toBeInTheDocument();
    expect(screen.getByText("Frankfurt")).toBeInTheDocument();
  });

  it("asks the panel again every 10 seconds, because the status of a node changes by itself", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { panel } = openOverview({ nodes: [{ id: "node-a", name: "Frankfurt", status: "online" }] });
    await screen.findByText(t("status.node.online"));
    const asked = panel.rpc.listNodes.mock.calls.length;

    const node = panel.inventory.nodes[0];
    if (node) node.status = "offline";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    await waitFor(() => {
      expect(panel.rpc.listNodes.mock.calls.length).toBeGreaterThan(asked);
    });
    expect(await screen.findByText(t("status.node.offline"))).toBeInTheDocument();
  });
});
