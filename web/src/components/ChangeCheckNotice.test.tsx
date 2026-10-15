import { create } from "@bufbuild/protobuf";
import { act, screen, waitFor } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NodeSchema } from "../gen/postern/panel/v1/nodes_pb";
import { makeProxy } from "../test/fakeInventory";
import { createFakePanel } from "../test/fakePanel";
import { renderApp, renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { NodeEgressSettings } from "./NodeEgressSettings";
import { ProxyForm } from "./ProxyForm";

const NODE = { id: "node-a", name: "Frankfurt" };
const CHAINS = [{ id: "chain-main", name: "Main" }];
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const now = () => Math.floor(Date.now() / 1000);

async function choose(user: UserEvent, key: TKey, option: string) {
  await user.click(field(key));
  await user.click(await screen.findByRole("option", { name: option }));
}

/** A gate that holds a call of the panel until it is opened: a save that takes its time. */
function gate() {
  const held: { release?: () => void } = {};
  const opened = new Promise<undefined>((resolve) => {
    held.release = () => {
      resolve(undefined);
    };
  });
  return {
    opened,
    open: () => {
      held.release?.();
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ChangeCheckNotice on the egress settings of a node", () => {
  it("says that the node is checked while a slow save waits, then links the check before and, later, after", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], chains: CHAINS });
    const node = create(NodeSchema, NODE);
    renderWithProviders(<NodeEgressSettings node={node} />, { transport: panel.transport, route: "/nodes/node-a" });
    const user = userEvent.setup();

    const slow = gate();
    const original = panel.rpc.setNodeDefaultChain.getMockImplementation();
    panel.rpc.setNodeDefaultChain.mockImplementationOnce(async (req) => {
      // The panel runs the check before the change while the save waits; another
      // admin's change of the node got its own before-run at the same time.
      panel.diagnostics.addRun({ id: "run-before", nodeId: NODE.id, reason: "before_change", change: "node.default_chain chain-main" });
      panel.diagnostics.addRun({ id: "run-other", nodeId: NODE.id, reason: "before_change", change: "node.dns_mode system" });
      await slow.opened;
      if (original === undefined) throw new Error("no implementation");
      return { ...(await original(req)), beforeRunId: "run-before" };
    });

    await choose(user, "nodes.egress.defaultChain", "Main");
    await user.click(screen.getByRole("button", { name: t("nodes.egress.save") }));
    expect(await screen.findByText(t("insights.changeCheck.checking"))).toBeInTheDocument();

    slow.open();
    const before = await screen.findByRole("link", { name: t("insights.changeCheck.open", { what: t("insights.changeCheck.before") }) });
    expect(before).toHaveAttribute("href", "/nodes/node-a?run=run-before");
    expect(screen.queryByText(t("insights.changeCheck.checking"))).not.toBeInTheDocument();
    expect(screen.getByText(t("insights.changeCheck.afterPending"))).toBeInTheDocument();

    // A minute after the node has applied the change, the panel runs the check after it.
    panel.diagnostics.addRun({ id: "run-after", nodeId: NODE.id, reason: "after_change", relatedRunId: "run-before", regressed: true, startedUnix: BigInt(now() + 60) });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(
      await screen.findByRole("link", { name: t("insights.changeCheck.open", { what: t("insights.changeCheck.after") }) }),
    ).toHaveAttribute("href", "/nodes/node-a?run=run-after");
    expect(screen.getByText(t("insights.diagnostics.run.regressed"))).toBeInTheDocument();

    // Once both are there, the runs are not asked for again.
    const asked = panel.rpc.listRuns.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(panel.rpc.listRuns.mock.calls.length).toBe(asked);
  });
});

describe("ChangeCheckNotice on the form of a proxy", () => {
  function openProxy() {
    const proxy = makeProxy({ id: "proxy-c", nodeId: NODE.id, listenerId: "listener-c" });
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE],
      listeners: [{ id: proxy.listenerId, nodeId: NODE.id }],
      proxies: [proxy],
      chains: CHAINS,
    });
    renderWithProviders(<ProxyForm proxy={proxy} onDone={vi.fn()} />, { transport: panel.transport, route: "/proxies/proxy-c" });
    return { panel, user: userEvent.setup() };
  }

  it("says nothing of a check for a change that runs none", async () => {
    const { panel, user } = openProxy();
    await screen.findByDisplayValue(t("proxy.form.chainDefault"));
    await user.type(field("proxy.form.name"), "x");
    await user.click(screen.getByRole("button", { name: t("proxy.form.save") }));
    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByText(t("insights.changeCheck.checking"))).not.toBeInTheDocument();
    expect(screen.queryByText(t("insights.changeCheck.beforeMissing"))).not.toBeInTheDocument();
  });

  it("says that the node is checked while a change of the chain saves, and links the check of the proxy's scope", async () => {
    const { panel, user } = openProxy();
    await screen.findByDisplayValue(t("proxy.form.chainDefault"));
    const slow = gate();
    const original = panel.rpc.updateProxy.getMockImplementation();
    panel.rpc.updateProxy.mockImplementationOnce(async (req) => {
      panel.diagnostics.addRun({ id: "run-p", nodeId: NODE.id, scope: "proxy:proxy-c", reason: "before_change" });
      await slow.opened;
      if (original === undefined) throw new Error("no implementation");
      return { ...(await original(req)), beforeRunId: "run-p" };
    });

    await choose(user, "proxy.form.chain", "Main");
    await user.click(screen.getByRole("button", { name: t("proxy.form.save") }));
    expect(await screen.findByText(t("insights.changeCheck.checking"))).toBeInTheDocument();
    slow.open();

    expect(
      await screen.findByRole("link", { name: t("insights.changeCheck.open", { what: t("insights.changeCheck.before") }) }),
    ).toHaveAttribute("href", "/proxies/proxy-c?run=run-p");
    expect(panel.rpc.listRuns.mock.calls.at(-1)?.[0]).toMatchObject({ proxyId: "proxy-c" });
  });

  it("says that the panel made no check before a change it answered without one", async () => {
    const { user } = openProxy();
    await screen.findByDisplayValue(t("proxy.form.chainDefault"));
    await choose(user, "proxy.form.chain", "Main");
    await user.click(screen.getByRole("button", { name: t("proxy.form.save") }));

    expect(await screen.findByText(t("insights.changeCheck.beforeMissing"))).toBeInTheDocument();
    expect(screen.queryByText(t("insights.changeCheck.afterPending"))).not.toBeInTheDocument();
  });
});

describe("ChangeCheckNotice on the egress page", () => {
  it("links the check before the change on each node that an egress edit changed", async () => {
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE, { id: "node-b", name: "Helsinki" }],
      egresses: [{ id: "egress-s", name: "Socks", kind: "socks5", params: { addr: "198.51.100.9:1080" } }],
    });
    renderApp({ route: "/egress", transport: panel.transport });
    const user = userEvent.setup();
    const original = panel.rpc.updateEgress.getMockImplementation();
    panel.rpc.updateEgress.mockImplementationOnce(async (req) => {
      if (original === undefined) throw new Error("no implementation");
      return { ...(await original(req)), beforeRunIds: { "node-a": "run-a", "node-b": "run-b" } };
    });

    await user.click(await screen.findByRole("button", { name: t("egress.edit", { name: "Socks" }) }));
    const name = await screen.findByLabelText(t("egress.form.name"), FIELD);
    await user.clear(name);
    await user.type(name, "Socks 2");
    await user.click(screen.getByRole("button", { name: t("egress.form.save") }));

    expect(
      await screen.findByRole("link", { name: t("insights.changeCheck.beforeOn", { node: "Frankfurt" }) }),
    ).toHaveAttribute("href", "/nodes/node-a/diagnostics?run=run-a");
    expect(screen.getByRole("link", { name: t("insights.changeCheck.beforeOn", { node: "Helsinki" }) })).toHaveAttribute(
      "href",
      "/nodes/node-b/diagnostics?run=run-b",
    );
  });
});
