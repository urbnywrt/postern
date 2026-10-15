import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

// The router loads the page on demand; loading it while the file is collected keeps that out of the tests.
import "./Journal";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const now = () => Math.floor(Date.now() / 1000);
const FIELD = { selector: "input, textarea" };
const DETAILS: Record<string, string> = { check: "engine.ready", client: "<ip>" };
const NO_DETAILS: Record<string, string> = {};

function open() {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [
      { id: "node-a", name: "Frankfurt" },
      { id: "node-b", name: "Amsterdam" },
    ],
  });
  // 60 events, newest first: more than a page of 50.
  panel.diagnostics.events = Array.from({ length: 60 }, (_, i) => ({
    id: `e${String(i)}`,
    tsUnix: BigInt(now() - i * 60),
    nodeId: i % 2 === 0 ? "node-a" : "node-b",
    kind: i === 0 ? "check.failed" : "node.online",
    severity: i === 0 ? "error" : "info",
    message: `event number ${String(i)}`,
    details: i === 0 ? DETAILS : NO_DETAILS,
  }));
  panel.diagnostics.audit = [
    { id: "a1", tsUnix: BigInt(now() - 30), adminId: "admin-1", adminName: "admin", action: "diagnostics.fix", target: "node:node-a", details: { fix: "roll_edge" } },
    { id: "a2", tsUnix: BigInt(now() - 90), adminId: "", adminName: "", action: "proxy.update", target: "proxy:proxy-1" },
  ];
  return { panel, user: userEvent.setup() };
}

describe("Journal", () => {
  it("shows the events newest first and loads more by the cursor", async () => {
    const { panel, user } = open();
    renderApp({ route: "/journal", transport: panel.transport });

    const events = within(await screen.findByRole("table", { name: t("insights.journal.tabs.events") }));
    expect(events.getByText("event number 0")).toBeInTheDocument();
    expect(events.getByText(/check: engine.ready/)).toBeInTheDocument();
    expect(events.queryByText("event number 55")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("insights.journal.loadMore") }));
    expect(await events.findByText("event number 55")).toBeInTheDocument();
    expect(panel.rpc.listJournal.mock.calls.at(-1)?.[0]).toMatchObject({ source: "events", cursor: "50" });
    expect(screen.queryByRole("button", { name: t("insights.journal.loadMore") })).not.toBeInTheDocument();
    expect(screen.getByText(t("insights.journal.end"))).toBeInTheDocument();
  });

  it("filters the events by node, severity and kind when the filter is applied", async () => {
    const { panel, user } = open();
    renderApp({ route: "/journal", transport: panel.transport });
    await screen.findByRole("table", { name: t("insights.journal.tabs.events") });

    await user.click(screen.getByLabelText(t("insights.journal.node"), FIELD));
    await user.click(await screen.findByRole("option", { name: "Frankfurt" }));
    await user.click(screen.getByLabelText(t("insights.journal.severity.label"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("insights.journal.severity.error") }));
    await user.type(screen.getByLabelText(t("insights.journal.kind"), FIELD), "check.");
    await user.click(screen.getByRole("button", { name: t("insights.journal.apply") }));

    await waitFor(() => {
      expect(panel.rpc.listJournal.mock.calls.at(-1)?.[0]).toMatchObject({
        source: "events",
        nodeId: "node-a",
        minSeverity: "error",
        kindPrefix: "check.",
        cursor: "",
      });
    });
    const events = within(await screen.findByRole("table", { name: t("insights.journal.tabs.events") }));
    await waitFor(() => {
      expect(events.queryByText("event number 2")).not.toBeInTheDocument();
    });
    expect(events.getByText("event number 0")).toBeInTheDocument();
  });

  it("shows the audit log with its own filters, and only those", async () => {
    const { panel, user } = open();
    renderApp({ route: "/journal", transport: panel.transport });
    await screen.findByRole("table", { name: t("insights.journal.tabs.events") });

    await user.click(screen.getByRole("tab", { name: t("insights.journal.tabs.audit") }));
    const audit = within(await screen.findByRole("table", { name: t("insights.journal.tabs.audit") }));
    expect(audit.getByText("diagnostics.fix")).toBeInTheDocument();
    expect(audit.getByText(t("insights.journal.system"))).toBeInTheDocument();

    await user.type(screen.getByLabelText(t("insights.journal.action"), FIELD), "diagnostics.");
    await user.click(screen.getByLabelText(t("insights.journal.period.label"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("insights.journal.period.24h") }));
    await user.click(screen.getByRole("button", { name: t("insights.journal.apply") }));

    await waitFor(() => {
      expect(panel.rpc.listJournal.mock.calls.at(-1)?.[0]).toMatchObject({ source: "audit", actionPrefix: "diagnostics." });
    });
    const request = panel.rpc.listJournal.mock.calls.at(-1)?.[0];
    expect(request?.nodeId).toBe("");
    expect(request?.minSeverity).toBe("");
    expect(Number(request?.fromUnix)).toBeGreaterThan(now() - 86_400 - 60);
    await waitFor(() => {
      expect(audit.queryByText("proxy.update")).not.toBeInTheDocument();
    });
  });

  it("is in the navigation", async () => {
    const { panel, user } = open();
    const { router } = renderApp({ route: "/", transport: panel.transport });

    const navigation = within(await screen.findByRole("navigation", { name: t("nav.main") }));
    await user.click(navigation.getByRole("link", { name: t("insights.nav.journal") }));
    expect(await screen.findByRole("heading", { name: t("insights.journal.title"), level: 1 })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/journal");
    expect(navigation.getByRole("link", { name: t("insights.nav.journal") })).toHaveAttribute("data-active", "true");
  });
});
