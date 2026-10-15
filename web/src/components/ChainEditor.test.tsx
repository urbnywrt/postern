import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { type Chain, type ChainCheckSchema, CreateChainRequestSchema } from "../gen/postern/panel/v1/egress_pb";
import { makeChain } from "../test/fakeEgress";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { ChainEditor } from "./ChainEditor";

const NODE = { id: "node-a", name: "Frankfurt" };
const EGRESSES = [
  { id: "eg-a", name: "Alpha", kind: "socks5", params: { addr: "198.51.100.9:1080" } },
  { id: "eg-b", name: "Bravo", kind: "xray-uri", masked: "vless://vless.example.com:443" },
  { id: "eg-c", name: "Charlie", kind: "warp" },
  { id: "eg-own", name: "Own", kind: "direct", nodeId: NODE.id, params: { interface: "wg0" } },
  { id: "eg-psiphon", name: "Psiphon DE", kind: "psiphon", params: { country: "DE" } },
];

type User = ReturnType<typeof userEvent.setup>;

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);

async function choose(user: User, key: TKey, option: string) {
  await user.click(field(key));
  await user.click(await screen.findByRole("option", { name: option }));
}

function open(chain?: Chain) {
  const onDone = vi.fn<(chain: Chain) => void>();
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], egresses: EGRESSES, chains: chain ? [chain] : [] });
  renderWithProviders(<ChainEditor chain={chain} onDone={onDone} onCancel={vi.fn()} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup() };
}

const memberList = () => screen.queryByRole("list", { name: t("chain.form.members") });

/** The members, in their order: each item of the list is named by its egress. */
function members(): string[] {
  const list = memberList();
  if (list === null) {
    return [];
  }
  const items = within(list).getAllByRole("listitem");
  const names = EGRESSES.map((egress) => egress.name).concat(t("chain.form.missing"));
  return items.map((item) => names.find((name) => within(list).queryByRole("listitem", { name }) === item) ?? "?");
}

const button = (key: TKey, name: string) => screen.getByRole("button", { name: t(key, { name }) });

async function ready() {
  // The egresses are there once the field that adds them can be opened.
  await waitFor(() => {
    expect(field("chain.form.add")).toBeEnabled();
  });
}

describe("ChainEditor: the order of the members", () => {
  it("adds the egresses in the order they are chosen, and moves and takes them out", async () => {
    const { panel, user, onDone } = open();
    await ready();

    await user.type(field("chain.form.name"), "Main");
    await choose(user, "chain.form.add", "Alpha");
    await choose(user, "chain.form.add", "Bravo");
    await choose(user, "chain.form.add", "Charlie");
    expect(members()).toEqual(["Alpha", "Bravo", "Charlie"]);

    await user.click(button("chain.form.moveUp", "Charlie"));
    expect(members()).toEqual(["Alpha", "Charlie", "Bravo"]);
    await user.click(button("chain.form.moveDown", "Alpha"));
    expect(members()).toEqual(["Charlie", "Alpha", "Bravo"]);
    await user.click(button("chain.form.remove", "Charlie"));
    expect(members()).toEqual(["Alpha", "Bravo"]);

    await user.click(screen.getByRole("button", { name: t("chain.form.create") }));
    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    // The check of the node: all zero, and no datacenters of its own.
    expect(panel.rpc.createChain.mock.calls[0]?.[0]).toEqual(
      create(CreateChainRequestSchema, { name: "Main", nodeId: "", memberIds: ["eg-a", "eg-b"], check: {} }),
    );
  });

  it("cannot move the first member up or the last one down", async () => {
    const { user } = open();
    await ready();
    await choose(user, "chain.form.add", "Alpha");
    await choose(user, "chain.form.add", "Bravo");

    expect(button("chain.form.moveUp", "Alpha")).toBeDisabled();
    expect(button("chain.form.moveDown", "Alpha")).toBeEnabled();
    expect(button("chain.form.moveUp", "Bravo")).toBeEnabled();
    expect(button("chain.form.moveDown", "Bravo")).toBeDisabled();
  });

  it("offers each egress once", async () => {
    const { user } = open();
    await ready();
    await choose(user, "chain.form.add", "Alpha");

    await user.click(field("chain.form.add"));
    expect(screen.queryByRole("option", { name: "Alpha" })).not.toBeInTheDocument();
    expect(await screen.findByRole("option", { name: "Bravo" })).toBeInTheDocument();
  });

  it("offers a chain of every node the egresses of every node only, and a chain of a node its own as well", async () => {
    const { user } = open();
    await ready();

    await user.click(field("chain.form.add"));
    expect(await screen.findByRole("option", { name: "Charlie" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Own" })).not.toBeInTheDocument();
    await user.keyboard("{Escape}");

    await choose(user, "chain.form.node", NODE.name);
    await choose(user, "chain.form.add", "Own");
    expect(members()).toEqual(["Own"]);
  });

  it("takes out the egresses of a node when the chain is no longer of that node", async () => {
    const { user } = open();
    await ready();
    await choose(user, "chain.form.node", NODE.name);
    await choose(user, "chain.form.add", "Own");
    await choose(user, "chain.form.add", "Alpha");
    expect(members()).toEqual(["Own", "Alpha"]);

    await choose(user, "chain.form.node", t("egress.everyNode"));
    expect(members()).toEqual(["Alpha"]);
  });

  it("labels a psiphon member experimental, in words", async () => {
    const { user } = open();
    await ready();
    await choose(user, "chain.form.add", "Psiphon DE");
    await choose(user, "chain.form.add", "Alpha");

    const list = memberList();
    if (list === null) {
      throw new Error("no members");
    }
    const psiphon = within(list).getByRole("listitem", { name: "Psiphon DE" });
    expect(within(psiphon).getByText(t("egress.experimental"))).toBeInTheDocument();
    const alpha = within(list).getByRole("listitem", { name: "Alpha" });
    expect(within(alpha).queryByText(t("egress.experimental"))).not.toBeInTheDocument();
  });

  it("refuses a chain without members before it calls the panel", async () => {
    const { panel, user } = open();
    await ready();
    await user.type(field("chain.form.name"), "Empty");
    await user.click(screen.getByRole("button", { name: t("chain.form.create") }));

    expect(await screen.findByText(t("chain.form.noMembers"))).toBeInTheDocument();
    expect(panel.rpc.createChain).not.toHaveBeenCalled();
  });

  it("keeps the order of a chain that it edits, and sends the members only when they changed", async () => {
    const chain = makeChain({ id: "chain-x", name: "Old name", memberIds: ["eg-c", "eg-a"] });
    const { panel, user } = open(chain);
    await ready();
    expect(members()).toEqual(["Charlie", "Alpha"]);

    await user.clear(field("chain.form.name"));
    await user.type(field("chain.form.name"), "New name");
    await user.click(screen.getByRole("button", { name: t("chain.form.save") }));
    await waitFor(() => {
      expect(panel.rpc.updateChain).toHaveBeenCalledTimes(1);
    });
    const first = panel.rpc.updateChain.mock.calls[0]?.[0];
    expect(first).toMatchObject({ id: "chain-x", name: "New name" });
    expect(first?.members).toBeUndefined();

    await user.click(button("chain.form.moveUp", "Alpha"));
    await user.click(screen.getByRole("button", { name: t("chain.form.save") }));
    await waitFor(() => {
      expect(panel.rpc.updateChain).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.updateChain.mock.calls[1]?.[0]?.members?.ids).toEqual(["eg-a", "eg-c"]);
  });

  it("says why when the panel cannot list the egresses, and does not call the members gone", async () => {
    const chain = makeChain({ id: "chain-x", name: "Main", memberIds: ["eg-a"] });
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], egresses: EGRESSES, chains: [chain] });
    panel.rpc.listEgresses.mockImplementation(() => {
      throw new ConnectError("the panel could not list the egresses", Code.Internal);
    });
    renderWithProviders(<ChainEditor chain={chain} onDone={vi.fn()} />, { transport: panel.transport });

    expect(await screen.findByText("the panel could not list the egresses")).toBeInTheDocument();
    expect(screen.queryByText(t("chain.form.missing"))).not.toBeInTheDocument();
  });
});

describe("ChainEditor: the health check", () => {
  type CheckInit = MessageInitShape<typeof ChainCheckSchema>;
  const FIELDS: [TKey, number, string, CheckInit][] = [
    ["chain.form.interval", 3600, t("validation.checkInterval", { max: 3600 }), { intervalSeconds: 3600 }],
    ["chain.form.timeout", 60, t("validation.checkTimeout", { max: 60 }), { timeoutSeconds: 60 }],
    ["chain.form.failThreshold", 100, t("validation.checkThreshold", { max: 100 }), { failThreshold: 100 }],
    ["chain.form.recoverThreshold", 100, t("validation.checkThreshold", { max: 100 }), { recoverThreshold: 100 }],
  ];

  it.each(FIELDS)("takes %s up to %i and refuses more before it calls the panel", async (key, max, message, check) => {
    const { panel, user, onDone } = open();
    await ready();
    await user.type(field("chain.form.name"), "Checked");
    await choose(user, "chain.form.add", "Alpha");

    await user.clear(field(key));
    await user.type(field(key), String(max + 1));
    await user.click(screen.getByRole("button", { name: t("chain.form.create") }));
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(panel.rpc.createChain).not.toHaveBeenCalled();

    await user.clear(field(key));
    await user.type(field(key), String(max));
    await user.click(screen.getByRole("button", { name: t("chain.form.create") }));
    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createChain.mock.calls[0]?.[0]).toEqual(
      create(CreateChainRequestSchema, { name: "Checked", nodeId: "", memberIds: ["eg-a"], check }),
    );
  });
});
