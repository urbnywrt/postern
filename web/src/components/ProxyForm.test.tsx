import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { createFakePanel } from "../test/fakePanel";
import { makeProxy } from "../test/fakeInventory";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { ProxyForm } from "./ProxyForm";

const NODE = { id: "node-a", name: "Frankfurt" };
// Made-up secrets are made by repetition: they cannot be taken for real ones. Both cases of hex are allowed.
const SECRET = "aB".repeat(16);

type User = ReturnType<typeof userEvent.setup>;

/** A panel with one node and one listener, and the form of a new proxy on that node. */
function openCreateForm({ listeners = 1 }: { listeners?: number } = {}) {
  const onDone = vi.fn<(proxy: Proxy) => void>();
  const panel = createFakePanel({
    signedIn: true,
    nodes: [NODE],
    listeners: Array.from({ length: listeners }, (_, i) => ({ id: `listener-${String(i + 1)}`, nodeId: NODE.id, port: 443 + i })),
  });
  const view = renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={onDone} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup(), ...view };
}

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const submit = () => screen.getByRole("button", { name: t("proxy.form.create") });

async function ready() {
  // The only listener of the node is taken without being asked.
  await screen.findByDisplayValue("0.0.0.0:443");
}

async function typeInto(user: User, key: TKey, text: string) {
  await user.type(field(key), text);
}

describe("ProxyForm: a new proxy", () => {
  it("refuses a secret that is not 32 hexadecimal digits, before it calls the panel", async () => {
    const { panel, user } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.secret", "not-a-secret");
    await user.click(submit());

    expect(await screen.findByText(t("validation.secret"))).toBeInTheDocument();
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();
  });

  it.each([
    ["31 digits", "a".repeat(31)],
    ["33 digits", "a".repeat(33)],
    ["a letter beyond f", `${"a".repeat(31)}g`],
    ["the link form with its ee prefix", `ee${SECRET}`],
  ])("refuses a secret of %s", async (_name, secret) => {
    const { panel, user } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.secret", secret);
    await user.click(submit());

    expect(await screen.findByText(t("validation.secret"))).toBeInTheDocument();
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();
  });

  it.each([
    ["a dot at the end", "www.example.com."],
    ["an underscore", "my_proxy.example.com"],
    ["letters that are not ASCII", "пример.рф"],
    ["an IP address", "203.0.113.7"],
    ["a port", "www.example.com:443"],
    ["a scheme", "https://www.example.com"],
  ])("refuses a domain with %s", async (_name, domain) => {
    const { panel, user } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.domain", domain);
    await user.click(submit());

    expect(await screen.findByText(t("validation.domain"))).toBeInTheDocument();
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();
  });

  it("points out every mistake at once, and takes the message away when the field is fixed", async () => {
    const { user } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.secret", "nope");
    await typeInto(user, "proxy.form.domain", "bad_domain");
    await typeInto(user, "proxy.form.adTag", "nope");
    await user.click(submit());

    expect(await screen.findByText(t("validation.secret"))).toBeInTheDocument();
    expect(screen.getByText(t("validation.domain"))).toBeInTheDocument();
    expect(screen.getByText(t("validation.adTag"))).toBeInTheDocument();

    await user.clear(field("proxy.form.secret"));
    await user.type(field("proxy.form.secret"), SECRET);
    expect(screen.queryByText(t("validation.secret"))).not.toBeInTheDocument();
    expect(screen.getByText(t("validation.domain"))).toBeInTheDocument();
  });

  it("refuses limits that are not whole numbers", async () => {
    const { panel, user } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.devices", "-1");
    await typeInto(user, "proxy.form.connsTotal", "1.5");
    await typeInto(user, "proxy.form.connsPerIp", "many");
    await user.click(submit());

    expect(await screen.findAllByText(/^Enter a whole number from 0 to /)).toHaveLength(3);
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();
  });

  it("creates the proxy with what was typed, and hands it on", async () => {
    const { panel, user, onDone } = openCreateForm();
    await ready();

    await typeInto(user, "proxy.form.name", "  Family  ");
    await typeInto(user, "proxy.form.note", "for the cousins");
    await typeInto(user, "proxy.form.domain", " www.Example.com ");
    await typeInto(user, "proxy.form.secret", ` ${SECRET} `);
    await typeInto(user, "proxy.form.devices", "3");
    await typeInto(user, "proxy.form.connsTotal", "100");
    await typeInto(user, "proxy.form.adTag", "f".repeat(32));
    await user.click(submit());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy).toHaveBeenCalledTimes(1);
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({
      nodeId: NODE.id,
      listenerId: "listener-1",
      name: "Family",
      note: "for the cousins",
      domain: "www.Example.com", // the case is kept, the spaces are not
      secret: SECRET,
      limits: { devices: 3, connsTotal: 100, connsPerIp: 0 },
      adTag: "f".repeat(32),
    });
    expect(onDone.mock.calls[0]?.[0]).toMatchObject({ name: "Family", domain: "www.Example.com" });
  });

  it("leaves the domain and the secret empty for the panel to fill in", async () => {
    const { panel, user, onDone } = openCreateForm();
    await ready();

    await user.click(submit());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({
      name: "",
      domain: "",
      secret: "",
      adTag: "",
      useMiddleProxy: "auto",
      limits: { devices: 0, connsTotal: 0, connsPerIp: 0 },
    });
  });

  it("starts on automatic middle proxies, and sends the one that was chosen", async () => {
    const { panel, user, onDone } = openCreateForm();
    await ready();
    expect(field("proxy.form.useMiddleProxy")).toHaveValue(t("proxy.form.middleProxyAuto"));

    await user.click(field("proxy.form.useMiddleProxy"));
    await user.click(await screen.findByRole("option", { name: t("proxy.form.middleProxyOff") }));
    expect(field("proxy.form.useMiddleProxy")).toHaveValue(t("proxy.form.middleProxyOff"));
    await user.click(submit());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({ useMiddleProxy: "off" });
    expect(onDone.mock.calls[0]?.[0]).toMatchObject({ useMiddleProxy: "off" });
  });

  it("offers automatic, on and off, and no empty choice", async () => {
    const { user } = openCreateForm();
    await ready();

    await user.click(field("proxy.form.useMiddleProxy"));
    const options = await screen.findAllByRole("option");
    const names = options.map((option) => option.textContent);
    expect(names).toEqual([t("proxy.form.middleProxyAuto"), t("proxy.form.middleProxyOn"), t("proxy.form.middleProxyOff")]);
  });

  it("calls the devices limit unique IPs", async () => {
    openCreateForm();
    await ready();

    expect(screen.getByLabelText("Unique IPs")).toBeInTheDocument();
    expect(field("proxy.form.devices")).toBe(screen.getByLabelText("Unique IPs"));
  });

  it("asks which listener when the node has several, and does not guess", async () => {
    const { panel, user } = openCreateForm({ listeners: 2 });
    await screen.findByLabelText(t("proxy.form.listener"), FIELD);
    expect(screen.queryByDisplayValue("0.0.0.0:443")).not.toBeInTheDocument();

    await user.click(submit());
    expect(await screen.findByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();

    await user.click(field("proxy.form.listener"));
    await user.click(await screen.findByRole("option", { name: "0.0.0.0:444" }));
    await user.click(submit());

    await waitFor(() => {
      expect(panel.rpc.createProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({ listenerId: "listener-2" });
  });

  it("says so when the node has no listener, and does not offer to create", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE] });
    renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={vi.fn()} />, { transport: panel.transport });

    expect(await screen.findByText(t("proxy.form.noListeners"))).toBeInTheDocument();
    expect(submit()).toBeDisabled();
  });

  it("shows the message of the panel when it refuses, and keeps what was typed", async () => {
    const { panel, user, onDone } = openCreateForm();
    panel.rpc.createProxy.mockImplementation(() => {
      throw new ConnectError("another proxy of the listener has this domain", Code.AlreadyExists);
    });
    await ready();

    await typeInto(user, "proxy.form.domain", "www.example.com");
    await user.click(submit());

    expect(await screen.findByText("another proxy of the listener has this domain")).toBeInTheDocument();
    expect(field("proxy.form.domain")).toHaveValue("www.example.com");
    expect(onDone).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(submit()).toBeEnabled();
    });
  });

  it("lets the admin choose the node when it is not given, then offers the listeners of that node", async () => {
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE, { id: "node-b", name: "Amsterdam" }],
      listeners: [
        { id: "listener-a", nodeId: NODE.id, port: 443 },
        { id: "listener-b", nodeId: "node-b", port: 8443 },
      ],
    });
    const onDone = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<ProxyForm onDone={onDone} />, { transport: panel.transport });

    await user.click(await screen.findByLabelText(t("proxy.form.node"), FIELD));
    await user.click(await screen.findByRole("option", { name: "Amsterdam" }));
    await screen.findByDisplayValue("0.0.0.0:8443");
    await user.click(submit());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-b", listenerId: "listener-b" });
  });
});

describe("ProxyForm: the settings of a proxy", () => {
  function openEditForm(proxy: Proxy) {
    const onDone = vi.fn<(proxy: Proxy) => void>();
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE],
      listeners: [{ id: proxy.listenerId, nodeId: NODE.id }],
      proxies: [proxy],
    });
    renderWithProviders(<ProxyForm proxy={proxy} onDone={onDone} />, { transport: panel.transport });
    return { panel, onDone, user: userEvent.setup() };
  }
  const saved = () => screen.getByRole("button", { name: t("proxy.form.save") });

  const proxy = makeProxy({
    id: "proxy-x",
    nodeId: NODE.id,
    listenerId: "listener-x",
    name: "Family",
    note: "for the cousins",
    domain: "www.example.com",
    adTag: "",
    limits: { devices: 5, connsTotal: 0, connsPerIp: 2 },
  });

  it("starts from the proxy, and has no secret and no listener to change", () => {
    openEditForm(proxy);

    expect(field("proxy.form.name")).toHaveValue("Family");
    expect(field("proxy.form.note")).toHaveValue("for the cousins");
    expect(field("proxy.form.domain")).toHaveValue("www.example.com");
    expect(field("proxy.form.devices")).toHaveValue("5");
    expect(field("proxy.form.connsTotal")).toHaveValue("0");
    expect(field("proxy.form.connsPerIp")).toHaveValue("2");
    expect(screen.queryByLabelText(t("proxy.form.secret"), FIELD)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(t("proxy.form.listener"), FIELD)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(t("proxy.form.node"), FIELD)).not.toBeInTheDocument();
  });

  it("sends only what was changed", async () => {
    const { panel, user, onDone } = openEditForm(proxy);

    await user.clear(field("proxy.form.name"));
    await user.type(field("proxy.form.name"), "Friends");
    await user.click(saved());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    const request = panel.rpc.updateProxy.mock.calls[0]?.[0];
    expect(request).toMatchObject({ id: "proxy-x", name: "Friends" });
    // Fields that were not touched are not in the request: it would otherwise
    // overwrite a change that somebody else made in the meantime.
    expect(request?.note).toBeUndefined();
    expect(request?.domain).toBeUndefined();
    expect(request?.adTag).toBeUndefined();
    expect(request?.useMiddleProxy).toBeUndefined();
    expect(request?.limits).toBeUndefined();
  });

  it("shows the middle-proxy setting of the proxy, and sends it alone when it is the one thing that changed", async () => {
    const { panel, user, onDone } = openEditForm(makeProxy({ ...proxy, id: "proxy-m", useMiddleProxy: "on" }));
    expect(field("proxy.form.useMiddleProxy")).toHaveValue(t("proxy.form.middleProxyOn"));

    await user.click(field("proxy.form.useMiddleProxy"));
    await user.click(await screen.findByRole("option", { name: t("proxy.form.middleProxyAuto") }));
    await user.click(saved());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    const request = panel.rpc.updateProxy.mock.calls[0]?.[0];
    expect(request).toMatchObject({ id: "proxy-m", useMiddleProxy: "auto" });
    expect(request?.name).toBeUndefined();
    expect(request?.adTag).toBeUndefined();
    expect(request?.limits).toBeUndefined();
    expect(onDone.mock.calls[0]?.[0]).toMatchObject({ useMiddleProxy: "auto" });
  });

  it("takes a proxy without a setting for automatic, and does not send it back as a change", async () => {
    const { panel, user, onDone } = openEditForm(makeProxy({ ...proxy, id: "proxy-n", useMiddleProxy: "" }));
    expect(field("proxy.form.useMiddleProxy")).toHaveValue(t("proxy.form.middleProxyAuto"));

    await user.click(saved());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy).not.toHaveBeenCalled();
  });

  it("sends the three limits together when one of them changed", async () => {
    const { panel, user } = openEditForm(proxy);

    await user.clear(field("proxy.form.connsTotal"));
    await user.type(field("proxy.form.connsTotal"), "50");
    await user.click(saved());

    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0].limits).toMatchObject({ devices: 5, connsTotal: 50, connsPerIp: 2 });
  });

  it("takes an empty limit for no limit", async () => {
    const { panel, user } = openEditForm(proxy);

    await user.clear(field("proxy.form.devices"));
    await user.click(saved());

    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0].limits).toMatchObject({ devices: 0, connsTotal: 0, connsPerIp: 2 });
  });

  it("sends a new domain and an ad tag, trimmed, and an emptied ad tag as empty", async () => {
    const withTag = makeProxy({ ...proxy, id: "proxy-y", adTag: "a".repeat(32) });
    const { panel, user } = openEditForm(withTag);

    await user.clear(field("proxy.form.domain"));
    await user.type(field("proxy.form.domain"), " www.example.org ");
    await user.clear(field("proxy.form.adTag"));
    await user.click(saved());

    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]).toMatchObject({ domain: "www.example.org", adTag: "" });
  });

  it("calls nothing when nothing changed", async () => {
    const { panel, user, onDone } = openEditForm(proxy);

    await user.click(saved());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy).not.toHaveBeenCalled();
  });

  it("refuses a bad domain and a bad ad tag here as well", async () => {
    const { panel, user } = openEditForm(proxy);

    await user.clear(field("proxy.form.domain"));
    await user.type(field("proxy.form.domain"), "www.example.com.");
    await user.type(field("proxy.form.adTag"), "xyz");
    await user.click(saved());

    expect(await screen.findByText(t("validation.domain"))).toBeInTheDocument();
    expect(screen.getByText(t("validation.adTag"))).toBeInTheDocument();
    expect(panel.rpc.updateProxy).not.toHaveBeenCalled();
  });

  it("calls the devices limit unique IPs here too", () => {
    openEditForm(proxy);
    expect(screen.getByLabelText("Unique IPs")).toBeInTheDocument();
  });
});

describe("ProxyForm: the egress chains", () => {
  const CHAINS = [
    { id: "chain-main", name: "Main" },
    { id: "chain-me", name: "Middle proxies through WARP" },
    { id: "chain-other", name: "Of another node", nodeId: "node-z" },
  ];

  async function choose(user: User, key: TKey, option: string) {
    await user.click(field(key));
    await user.click(await screen.findByRole("option", { name: option }));
  }

  it("creates a proxy with a chain and a chain for the middle proxies, from the chains that its node can use", async () => {
    const onDone = vi.fn<(proxy: Proxy) => void>();
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE, { id: "node-z", name: "Z" }],
      listeners: [{ id: "listener-1", nodeId: NODE.id, port: 443 }],
      chains: CHAINS,
    });
    renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={onDone} />, { transport: panel.transport });
    const user = userEvent.setup();
    await ready();
    expect(field("proxy.form.chain")).toHaveValue(t("proxy.form.chainDefault"));

    await user.click(field("proxy.form.chain"));
    expect(screen.queryByRole("option", { name: "Of another node" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("option", { name: "Main" }));
    await choose(user, "proxy.form.scopeMe", "Middle proxies through WARP");
    await user.click(submit());

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({
      egressChainId: "chain-main",
      egressScopeChains: { me: "chain-me" },
    });
  });

  it("sends the chains of a proxy only when they changed, and the default again as empty", async () => {
    const proxy = makeProxy({
      id: "proxy-c",
      nodeId: NODE.id,
      listenerId: "listener-c",
      egressChainId: "chain-main",
      egressScopeChains: { fetch: "chain-me" },
    });
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE],
      listeners: [{ id: proxy.listenerId, nodeId: NODE.id }],
      proxies: [proxy],
      chains: CHAINS,
    });
    renderWithProviders(<ProxyForm proxy={proxy} onDone={vi.fn()} />, { transport: panel.transport });
    const user = userEvent.setup();
    await screen.findByDisplayValue("Main");

    await user.clear(field("proxy.form.name"));
    await user.type(field("proxy.form.name"), "Renamed");
    await user.click(screen.getByRole("button", { name: t("proxy.form.save") }));
    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]?.egressChainId).toBeUndefined();
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]?.egressScopeChains).toBeUndefined();

    await choose(user, "proxy.form.chain", t("proxy.form.chainDefault"));
    await choose(user, "proxy.form.scopeFetch", t("proxy.form.scopeSame"));
    await user.click(screen.getByRole("button", { name: t("proxy.form.save") }));
    await waitFor(() => {
      expect(panel.rpc.updateProxy).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.updateProxy.mock.calls[1]?.[0]).toMatchObject({ egressChainId: "", egressScopeChains: { chains: {} } });
  });

  it("puts the chains back to those of the node when the node changes: a chain of one node is not for another", async () => {
    const onDone = vi.fn<(proxy: Proxy) => void>();
    const panel = createFakePanel({
      signedIn: true,
      nodes: [NODE, { id: "node-b", name: "Amsterdam" }],
      listeners: [
        { id: "listener-a", nodeId: NODE.id, port: 443 },
        { id: "listener-b", nodeId: "node-b", port: 8443 },
      ],
      chains: [
        { id: "chain-own", name: "Own of Frankfurt", nodeId: NODE.id },
        { id: "chain-main", name: "Main" },
      ],
    });
    renderWithProviders(<ProxyForm onDone={onDone} />, { transport: panel.transport });
    const user = userEvent.setup();

    await user.click(await screen.findByLabelText(t("proxy.form.node"), FIELD));
    await user.click(await screen.findByRole("option", { name: NODE.name }));
    await screen.findByDisplayValue("0.0.0.0:443");
    await choose(user, "proxy.form.chain", "Own of Frankfurt");
    await choose(user, "proxy.form.scopeMe", "Own of Frankfurt");
    await choose(user, "proxy.form.scopeFetch", "Main");

    await choose(user, "proxy.form.node", "Amsterdam");
    await screen.findByDisplayValue("0.0.0.0:8443");
    expect(field("proxy.form.chain")).toHaveValue(t("proxy.form.chainDefault"));
    expect(field("proxy.form.scopeMe")).toHaveValue(t("proxy.form.scopeSame"));
    expect(field("proxy.form.scopeFetch")).toHaveValue(t("proxy.form.scopeSame"));

    await user.click(submit());
    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    const sent = panel.rpc.createProxy.mock.calls[0]?.[0];
    expect(sent?.nodeId).toBe("node-b");
    expect(sent?.egressChainId).toBe("");
    expect(sent?.egressScopeChains).toEqual({});
  });

  it("says why when the panel cannot list the chains", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [{ id: "listener-1", nodeId: NODE.id, port: 443 }] });
    panel.rpc.listChains.mockImplementation(() => {
      throw new ConnectError("the panel could not list the chains", Code.Internal);
    });
    renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={vi.fn()} />, { transport: panel.transport });

    expect(await screen.findByText("the panel could not list the chains")).toBeInTheDocument();
  });
});

describe("ProxyForm: a node without an address", () => {
  const listeners = [{ id: "listener-1", nodeId: NODE.id, port: 443 }];

  it("warns that the links would have no host, for the node of the page", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [{ ...NODE, mgmtHost: "", linkHost: "" }], listeners });
    renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={vi.fn()} />, { transport: panel.transport });

    expect(await screen.findByText(t("proxy.form.noHost"))).toBeInTheDocument();
  });

  it("warns for a node that is picked, too", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [{ ...NODE, mgmtHost: "", linkHost: "" }], listeners });
    renderWithProviders(<ProxyForm onDone={vi.fn()} />, { transport: panel.transport });

    expect(await screen.findByText(t("proxy.form.noHost"))).toBeInTheDocument();
  });

  it("says nothing for a node that has an address", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners });
    renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={vi.fn()} />, { transport: panel.transport });

    await ready();
    await waitFor(() => {
      expect(panel.rpc.getNode).toHaveBeenCalled();
    });
    expect(screen.queryByText(t("proxy.form.noHost"))).not.toBeInTheDocument();
  });
});
