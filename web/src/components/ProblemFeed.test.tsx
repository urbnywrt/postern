import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp, renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { ProblemFeed } from "./ProblemFeed";

const now = () => Math.floor(Date.now() / 1000);
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));

function open() {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [{ id: "node-a", name: "Frankfurt" }],
    proxies: [{ id: "proxy-1", nodeId: "node-a", name: "Family" }],
  });
  panel.diagnostics.problems = [
    {
      severity: "error",
      kind: "check",
      nodeId: "node-a",
      nodeName: "Frankfurt",
      proxyId: "proxy-1",
      proxyName: "Family",
      summary: "the engine is not ready",
      hint: "look at the engine log",
      sinceUnix: BigInt(now() - 120),
      checkId: "engine.ready",
      target: "proxy:proxy-1",
      fix: "recreate_instance",
      fixAvailable: true,
    },
    { severity: "error", kind: "node.offline", nodeId: "node-a", nodeName: "Frankfurt", summary: "the node is offline", sinceUnix: BigInt(now() - 3600) },
    {
      severity: "warning",
      kind: "edge.outdated",
      nodeId: "node-a",
      nodeName: "Frankfurt",
      summary: "the edge runs 1.2.0, the agent 1.3.0",
      checkId: "panel.versions",
      fix: "roll_edge",
      fixAvailable: true,
    },
    { severity: "warning", kind: "geoip.stale", summary: "the country database is 70 days old" },
  ];
  panel.diagnostics.setLatest("node-a", [
    { id: "engine.ready", layer: "engine", target: "proxy:proxy-1", status: "fail", fix: "recreate_instance", fixAvailable: true },
  ]);
  return { panel, user: userEvent.setup() };
}

describe("ProblemFeed", () => {
  it("lists each problem with its severity, since when, and a link to its proxy, node or the settings", async () => {
    const { panel } = open();
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    expect(await feed.findByText("the engine is not ready")).toBeInTheDocument();
    expect(feed.getByRole("link", { name: "Family" })).toHaveAttribute("href", "/proxies/proxy-1");
    expect(feed.getAllByRole("link", { name: "Frankfurt" })[0]).toHaveAttribute("href", "/nodes/node-a/diagnostics");
    expect(feed.getByRole("link", { name: t("insights.problems.panel") })).toHaveAttribute("href", "/settings");
    expect(feed.getAllByText(t("insights.problems.severity.error"))).toHaveLength(2);
    expect(feed.getByText(t("insights.diagnostics.since", { when: "2 minutes ago" }))).toBeInTheDocument();
    expect(feed.getByText("look at the engine log")).toBeInTheDocument();
  });

  it("applies the fix of a problem from the light checks, after the confirmation", async () => {
    const { panel, user } = open();
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    await user.click(await feed.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.recreate_instance") }) }));
    const confirm = within(await screen.findByRole("dialog"));
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.applied", { generation: "8" }))).toBeInTheDocument();
    expect(panel.rpc.applyFix.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", checkId: "engine.ready", target: "proxy:proxy-1", offeredRunId: "" });
    // The check before the fix is opened on the page of the node.
    expect(confirm.getByRole("link", { name: t("insights.diagnostics.fix.openBefore") }).getAttribute("href")).toMatch(/^\/nodes\/node-a\/diagnostics\?run=run-/);
  });

  it("rolls an outdated edge from the feed, through the check that the panel names for it", async () => {
    const { panel, user } = open();
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    await user.click(await feed.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.roll_edge") }) }));
    const confirm = within(await screen.findByRole("dialog"));
    expect(confirm.getByText(t("insights.diagnostics.fix.afterwards.roll_edge"))).toBeInTheDocument();
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.applied", { generation: "8" }))).toBeInTheDocument();
    expect(panel.rpc.applyFix.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", checkId: "panel.versions", target: "", fix: "roll_edge", offeredRunId: "" });
  });

  it("hides a problem until it changes, counts only the visible ones, and shows it again", async () => {
    const { panel, user } = open();
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    const offline = await feed.findByText("the node is offline");
    expect(feed.getByLabelText(t("insights.problems.count", { count: 4 }))).toBeInTheDocument();
    expect(feed.queryByRole("button", { name: t("insights.problems.hiddenToggle", { count: 1 }) })).not.toBeInTheDocument();

    const row = offline.closest("li");
    if (row === null) throw new Error("the problem is not in a list item");
    await user.click(within(row).getByRole("button", { name: t("insights.problems.hide") }));

    // It moves to the hidden list, which is closed, and the count drops.
    const toggle = await feed.findByRole("button", { name: t("insights.problems.hiddenToggle", { count: 1 }) });
    expect(panel.rpc.hideProblem.mock.calls[0]?.[0]).toMatchObject({ key: "node.offline|node-a|||" });
    expect(await feed.findByLabelText(t("insights.problems.count", { count: 3 }))).toBeInTheDocument();
    await waitFor(() => {
      expect(feed.getByText("the node is offline")).not.toBeVisible();
    });

    await user.click(toggle);
    await waitFor(() => {
      expect(feed.getByText("the node is offline")).toBeVisible();
    });
    expect(feed.getByText(t("insights.problems.hiddenNote"))).toBeVisible();

    await user.click(feed.getByRole("button", { name: t("insights.problems.show") }));
    expect(await feed.findByLabelText(t("insights.problems.count", { count: 4 }))).toBeInTheDocument();
    await waitFor(() => {
      expect(feed.queryByRole("button", { name: t("insights.problems.hiddenToggle", { count: 1 }) })).not.toBeInTheDocument();
    });
    expect(panel.rpc.unhideProblem.mock.calls[0]?.[0]).toMatchObject({ key: "node.offline|node-a|||" });
  });

  it("disables only the action of the problem that is being hidden", async () => {
    const { panel, user } = open();
    let finish: (() => void) | undefined;
    panel.rpc.hideProblem.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = () => {
            resolve({});
          };
        }),
    );
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    const row = (await feed.findByText("the node is offline")).closest("li");
    if (row === null) throw new Error("the problem is not in a list item");
    await user.click(within(row).getByRole("button", { name: t("insights.problems.hide") }));

    await waitFor(() => {
      expect(within(row).getByRole("button", { name: t("insights.problems.hide") })).toBeDisabled();
    });
    const others = feed.getAllByRole("button", { name: t("insights.problems.hide") }).filter((button) => !row.contains(button));
    expect(others).toHaveLength(3);
    for (const button of others) expect(button).toBeEnabled();
    finish?.();
  });

  it("says nothing is wrong when every problem is hidden, and still offers the hidden list", async () => {
    const { panel, user } = open();
    panel.diagnostics.problems = panel.diagnostics.problems.slice(1, 2);
    panel.diagnostics.hidden.set("node.offline|node-a|||", BigInt(now()));
    renderWithProviders(<ProblemFeed />, { transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    expect(await feed.findByText(t("insights.problems.none"))).toBeInTheDocument();
    expect(feed.queryByLabelText(t("insights.problems.count", { count: 0 }))).not.toBeInTheDocument();
    await user.click(feed.getByRole("button", { name: t("insights.problems.hiddenToggle", { count: 1 }) }));
    await waitFor(() => {
      expect(feed.getByText("the node is offline")).toBeVisible();
    });
  });

  it("is on the overview", async () => {
    const { panel } = open();
    renderApp({ route: "/", transport: panel.transport });

    const feed = await region(t("insights.problems.title"));
    expect(await feed.findByText("the node is offline")).toBeInTheDocument();
  });
});
