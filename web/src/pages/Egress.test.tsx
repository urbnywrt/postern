import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t, type TKey } from "../test/t";

const NODE = { id: "node-a", name: "Frankfurt", defaultChainId: "chain-main" };
const EGRESSES = [
  { id: "eg-sub", name: "Subscription", kind: "xray-subscription", masked: "https://sub.example.com", params: { select: "first" } },
  { id: "eg-psiphon", name: "Psiphon DE", kind: "psiphon", params: { country: "DE" } },
  { id: "eg-socks", name: "Office", kind: "socks5", nodeId: NODE.id, params: { addr: "198.51.100.9:1080", username: "user" } },
];
const CHAINS = [{ id: "chain-main", name: "Main", memberIds: ["eg-sub", "eg-psiphon"], defaultOf: [NODE.id] }];

function openEgress() {
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], egresses: EGRESSES, chains: CHAINS });
  renderApp({ route: "/egress", transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const section = (key: TKey) => screen.getByRole("region", { name: t(key) });

describe("Egress", () => {
  it("lists the egresses, without secrets, and labels psiphon experimental", async () => {
    openEgress();
    const egresses = await screen.findByRole("region", { name: t("egress.egresses") });
    expect(await within(egresses).findByText("Subscription")).toBeInTheDocument();
    expect(within(egresses).getByText(`https://sub.example.com · ${t("egress.form.selectFirst")}`)).toBeInTheDocument();
    expect(within(egresses).getByText("user@198.51.100.9:1080")).toBeInTheDocument();
    expect(within(egresses).getByText(NODE.name)).toBeInTheDocument();
    expect(within(egresses).getAllByText(t("egress.experimental"))).toHaveLength(1);
    // The chains that have each egress.
    expect(within(egresses).getAllByText("Main")).toHaveLength(2);
  });

  it("lists the chains with their members in order and who uses them, and labels psiphon experimental in words", async () => {
    openEgress();
    await screen.findByRole("region", { name: t("chain.title") });
    const chains = section("chain.title");
    expect(await within(chains).findByText(`Subscription → Psiphon DE (${t("egress.experimental")})`)).toBeInTheDocument();
    expect(within(chains).getByText(t("chain.usedByNodes", { count: 1 }))).toBeInTheDocument();
  });

  it("does not call the members of the chains gone when the panel cannot list the egresses", async () => {
    const { panel } = openEgress();
    panel.rpc.listEgresses.mockImplementation(() => {
      throw new ConnectError("the panel could not list the egresses", Code.Internal);
    });

    const chains = await screen.findByRole("region", { name: t("chain.title") });
    expect(await within(chains).findByText("eg-sub → eg-psiphon")).toBeInTheDocument();
    expect(within(chains).queryByText(t("chain.form.missing"), { exact: false })).not.toBeInTheDocument();
  });

  it("asks the nodes to fetch a subscription again", async () => {
    const { panel, user } = openEgress();
    const button = await screen.findByRole("button", { name: t("egress.refresh", { name: "Subscription" }) });
    // Only a subscription can be fetched again.
    expect(screen.queryByRole("button", { name: t("egress.refresh", { name: "Office" }) })).not.toBeInTheDocument();
    await user.click(button);
    await waitFor(() => {
      expect(panel.rpc.refreshSubscription).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.refreshSubscription.mock.calls[0]?.[0]).toMatchObject({ id: "eg-sub" });
    expect(await screen.findByText(t("egress.refreshed"))).toBeInTheDocument();
  });

  it("is reached from the navigation", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE] });
    renderApp({ route: "/", transport: panel.transport });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("link", { name: t("nav.egress") }));
    expect(await screen.findByRole("heading", { level: 1, name: t("egress.title") })).toBeInTheDocument();
  });
});
