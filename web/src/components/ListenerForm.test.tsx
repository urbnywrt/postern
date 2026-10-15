import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Listener } from "../gen/postern/panel/v1/proxies_pb";
import { createFakePanel } from "../test/fakePanel";
import { makeListener } from "../test/fakeInventory";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { ListenerForm } from "./ListenerForm";

const NODE = { id: "node-a", name: "Frankfurt" };

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const addButton = () => screen.getByRole("button", { name: t("listener.form.create") });
const saveButton = () => screen.getByRole("button", { name: t("listener.form.save") });

type User = ReturnType<typeof userEvent.setup>;

function openCreateForm() {
  const onDone = vi.fn<(listener: Listener) => void>();
  const panel = createFakePanel({ signedIn: true, nodes: [NODE] });
  renderWithProviders(<ListenerForm nodeId={NODE.id} onDone={onDone} onCancel={vi.fn()} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup() };
}

function openEditForm(listener: Listener) {
  const onDone = vi.fn<(listener: Listener) => void>();
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [listener] });
  renderWithProviders(<ListenerForm listener={listener} onDone={onDone} onCancel={vi.fn()} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup() };
}

async function choose(user: User, key: TKey, option: string) {
  await user.click(field(key));
  await user.click(await screen.findByRole("option", { name: option }));
}

describe("ListenerForm: the port", () => {
  it.each([
    ["is empty", "", "validation.required"],
    ["is 0", "0", "validation.port"],
    ["is above 65535", "65536", "validation.port"],
    ["is negative", "-443", "validation.port"],
    ["has a decimal point", "443.5", "validation.port"],
    ["is not a number", "https", "validation.port"],
  ] as const)("refuses a port that %s, before it calls the panel", async (_name, port, message) => {
    const { panel, user } = openCreateForm();

    if (port !== "") {
      await user.type(field("listener.form.port"), port);
    }
    await user.click(addButton());

    expect(await screen.findByText(t(message))).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });

  it.each(["1", "443", "8443", "19999", "41000", "65535"])("accepts port %s on 0.0.0.0", async (port) => {
    const { panel, user } = openCreateForm();

    await user.type(field("listener.form.port"), port);
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({ port: Number(port) });
  });

  it.each(["20000", "25000", "30000", "40999"])(
    "refuses port %s on 0.0.0.0 and on 127.0.0.1: the node keeps it for its own services",
    async (port) => {
      const { panel, user } = openCreateForm();

      // 0.0.0.0 is the default, and an empty address is the same.
      await user.type(field("listener.form.port"), port);
      await user.click(addButton());
      expect(await screen.findByText(/20000 to 40999/)).toBeInTheDocument();
      expect(panel.rpc.createListener).not.toHaveBeenCalled();

      await user.clear(field("listener.form.bindIp"));
      await user.type(field("listener.form.bindIp"), "127.0.0.1");
      expect(screen.getByText(/20000 to 40999/)).toBeInTheDocument();
      await user.click(addButton());
      expect(panel.rpc.createListener).not.toHaveBeenCalled();
    },
  );

  it("takes a port of the internal range on a specific address, which does not collide", async () => {
    const { panel, user } = openCreateForm();

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.bindIp"), "203.0.113.7");
    await user.type(field("listener.form.port"), "25000");
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({ bindIp: "203.0.113.7", port: 25000 });
  });

  it("looks at the address as it is typed: an address that is not 0.0.0.0 or 127.0.0.1 lifts the refusal", async () => {
    const { user } = openCreateForm();

    await user.type(field("listener.form.port"), "25000");
    await user.click(addButton());
    expect(await screen.findByText(/20000 to 40999/)).toBeInTheDocument();

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.bindIp"), "203.0.113.7");
    expect(screen.queryByText(/20000 to 40999/)).not.toBeInTheDocument();
  });
});

describe("ListenerForm: the addresses", () => {
  it.each([
    ["an IPv6 address", "::1"],
    ["a multicast address", "224.0.0.1"],
    ["a link-local address", "169.254.0.1"],
    ["a host name", "node.example.com"],
    ["an address that is cut short", "203.0.113"],
  ])("refuses %s as the bind address", async (_name, address) => {
    const { panel, user } = openCreateForm();

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.bindIp"), address);
    await user.type(field("listener.form.port"), "443");
    await user.click(addButton());

    expect(await screen.findByText(t("validation.bindIp"))).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });

  it("takes an empty bind address for 0.0.0.0", async () => {
    const { panel, user } = openCreateForm();

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.port"), "443");
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({ bindIp: "" });
  });

  it("refuses a link host that is neither an IP address nor a host name", async () => {
    const { panel, user } = openCreateForm();

    await user.type(field("listener.form.port"), "443");
    await user.type(field("listener.form.linkHostOverride"), "https://links.example.com");
    await user.click(addButton());

    expect(await screen.findByText(t("validation.host"))).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });

  it("refuses a mask target that is not a host or host:port", async () => {
    const { panel, user } = openCreateForm();

    await user.type(field("listener.form.port"), "443");
    await user.type(field("listener.form.maskTarget"), "https://www.example.com");
    await user.click(addButton());

    expect(await screen.findByText(t("validation.maskTarget"))).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });

  it("refuses a mask target on the internal ports of the node", async () => {
    const { panel, user } = openCreateForm();

    await user.type(field("listener.form.port"), "443");
    await user.type(field("listener.form.maskTarget"), "127.0.0.1:25000");
    await user.click(addButton());

    expect(await screen.findByText(/40999 on the loopback/)).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });

  it("asks for a mask target only where strangers are relayed to one", async () => {
    const { panel, user } = openCreateForm();

    expect(field("listener.form.maskTarget")).toBeInTheDocument();
    await choose(user, "listener.form.strangerAction", t("listener.stranger.reject"));
    expect(screen.queryByLabelText(t("listener.form.maskTarget"), FIELD)).not.toBeInTheDocument();

    await user.type(field("listener.form.port"), "443");
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({ strangerAction: "reject", maskTarget: "" });
  });
});

describe("ListenerForm: adding a listener", () => {
  it("starts with 0.0.0.0, mask and drop, which are what the panel would pick", async () => {
    const { panel, user } = openCreateForm();

    expect(field("listener.form.bindIp")).toHaveValue("0.0.0.0");
    await user.type(field("listener.form.port"), "443");
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({
      nodeId: NODE.id,
      bindIp: "0.0.0.0",
      port: 443,
      linkHostOverride: "",
      strangerAction: "mask",
      maskTarget: "",
      nonTlsAction: "drop",
    });
  });

  it("sends what was typed and chosen, and hands the listener on", async () => {
    const { panel, user, onDone } = openCreateForm();

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.bindIp"), " 203.0.113.7 ");
    await user.type(field("listener.form.port"), "8443");
    await user.type(field("listener.form.linkHostOverride"), "links.example.com");
    await user.type(field("listener.form.maskTarget"), "www.example.com:8443");
    await choose(user, "listener.form.nonTlsAction", t("listener.nonTls.http400"));
    await user.click(addButton());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({
      nodeId: NODE.id,
      bindIp: "203.0.113.7",
      port: 8443,
      linkHostOverride: "links.example.com",
      strangerAction: "mask",
      maskTarget: "www.example.com:8443",
      nonTlsAction: "http400",
    });
    expect(onDone.mock.calls[0]?.[0]).toMatchObject({ port: 8443, bindIp: "203.0.113.7" });
  });

  it("shows the message of the panel when it refuses, and keeps what was typed", async () => {
    const { panel, user, onDone } = openCreateForm();
    panel.rpc.createListener.mockImplementation(() => {
      throw new ConnectError("another listener of the node has this address", Code.AlreadyExists);
    });

    await user.type(field("listener.form.port"), "443");
    await user.click(addButton());

    expect(await screen.findByText("another listener of the node has this address")).toBeInTheDocument();
    expect(field("listener.form.port")).toHaveValue("443");
    expect(onDone).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(addButton()).toBeEnabled();
    });
  });
});

describe("ListenerForm: changing a listener", () => {
  const listener = makeListener({
    id: "listener-x",
    nodeId: NODE.id,
    bindIp: "203.0.113.7",
    port: 443,
    linkHostOverride: "links.example.com",
    strangerAction: "mask",
    maskTarget: "www.example.com",
    nonTlsAction: "drop",
  });

  it("starts from the listener", () => {
    openEditForm(listener);

    expect(field("listener.form.bindIp")).toHaveValue("203.0.113.7");
    expect(field("listener.form.port")).toHaveValue("443");
    expect(field("listener.form.linkHostOverride")).toHaveValue("links.example.com");
    expect(field("listener.form.maskTarget")).toHaveValue("www.example.com");
  });

  it("sends only what was changed", async () => {
    const { panel, user, onDone } = openEditForm(listener);

    await user.clear(field("listener.form.port"));
    await user.type(field("listener.form.port"), "8443");
    await user.click(saveButton());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    const request = panel.rpc.updateListener.mock.calls[0]?.[0];
    expect(request).toMatchObject({ id: "listener-x", port: 8443 });
    expect(request?.bindIp).toBeUndefined();
    expect(request?.linkHostOverride).toBeUndefined();
    expect(request?.strangerAction).toBeUndefined();
    expect(request?.maskTarget).toBeUndefined();
    expect(request?.nonTlsAction).toBeUndefined();
  });

  it("can empty the link host and the mask target", async () => {
    const { panel, user } = openEditForm(listener);

    await user.clear(field("listener.form.linkHostOverride"));
    await user.clear(field("listener.form.maskTarget"));
    await user.click(saveButton());

    await waitFor(() => {
      expect(panel.rpc.updateListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateListener.mock.calls[0]?.[0]).toMatchObject({ linkHostOverride: "", maskTarget: "" });
  });

  it("clears the mask target when the listener stops relaying strangers", async () => {
    const { panel, user } = openEditForm(listener);

    await choose(user, "listener.form.strangerAction", t("listener.stranger.drop"));
    await user.click(saveButton());

    await waitFor(() => {
      expect(panel.rpc.updateListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateListener.mock.calls[0]?.[0]).toMatchObject({ strangerAction: "drop", maskTarget: "" });
  });

  it("checks a port against the address that the form has now", async () => {
    const { panel, user } = openEditForm(listener);

    await user.clear(field("listener.form.bindIp"));
    await user.type(field("listener.form.bindIp"), "0.0.0.0");
    await user.clear(field("listener.form.port"));
    await user.type(field("listener.form.port"), "25000");
    await user.click(saveButton());

    expect(await screen.findByText(/20000 to 40999/)).toBeInTheDocument();
    expect(panel.rpc.updateListener).not.toHaveBeenCalled();
  });

  it("calls nothing when nothing changed", async () => {
    const { panel, user, onDone } = openEditForm(listener);

    await user.click(saveButton());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateListener).not.toHaveBeenCalled();
  });
});

describe("ListenerForm: an http-upstream listener", () => {
  it("binds 127.0.0.1, names the web servers in front, and sends the kind with them", async () => {
    const { panel, user } = openCreateForm();
    await choose(user, "listener.form.kind", t("listener.kind.http-upstream"));
    expect(field("listener.form.bindIp")).toHaveValue("127.0.0.1");
    // The settings of a public port are not asked for.
    expect(screen.queryByLabelText(t("listener.form.strangerAction"), FIELD)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(t("listener.form.linkHostOverride"), FIELD)).not.toBeInTheDocument();

    await user.type(field("listener.form.port"), "8089");
    await user.clear(field("listener.form.trustedCidrs"));
    await user.type(field("listener.form.trustedCidrs"), "127.0.0.1/32\n172.17.0.0/16");
    await user.click(addButton());

    await waitFor(() => {
      expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({
      kind: "http-upstream",
      bindIp: "127.0.0.1",
      port: 8089,
      trustedCidrs: ["127.0.0.1/32", "172.17.0.0/16"],
    });
  });

  it("refuses a public address among the trusted web servers, and an empty list, before it calls the panel", async () => {
    const { panel, user } = openCreateForm();
    await choose(user, "listener.form.kind", t("listener.kind.http-upstream"));
    await user.type(field("listener.form.port"), "8089");
    await user.clear(field("listener.form.trustedCidrs"));
    await user.click(addButton());
    expect(await screen.findByText(t("validation.trustedCidrsRequired"))).toBeInTheDocument();

    await user.type(field("listener.form.trustedCidrs"), "203.0.113.0/24");
    expect(await screen.findByText(t("validation.trustedCidr"))).toBeInTheDocument();
    expect(panel.rpc.createListener).not.toHaveBeenCalled();
  });
});
