import { Code, ConnectError } from "@connectrpc/connect";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

// The router loads the page on demand, and the first load of the chart library is slow
// in a test run. Loading it here, while the file is collected, keeps that out of the tests.
import "./ProxyDetail";

import { proxyKeys } from "../api/hooks/keys";
import { QR_SVG } from "../test/fakeInventory";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const now = () => Math.floor(Date.now() / 1000);
// A Select or a Modal can repeat a label, so a field is asked for by its input.
const FIELD = { selector: "input, textarea" };

// A made-up secret, by repetition: it cannot be taken for a real one.
const SECRET = "ab".repeat(16);
// ee, the secret and the domain in hex: that is how the links of the panel are made.
const TG_LINK = `tg://proxy?server=203.0.113.7&port=443&secret=ee${SECRET}66616d2e6578616d706c652e636f6d`;
const HTTPS_LINK = TG_LINK.replace("tg://proxy", "https://t.me/proxy");

const PROXY_STATUS = { phase: "serving", reason: "", runningVersion: "3.5.13", instanceGeneration: 5n, reportedUnix: 0n };
const NODE = { id: "node-a", name: "Frankfurt", linkHost: "203.0.113.7" };
const LISTENER = { id: "listener-a", nodeId: "node-a", bindIp: "0.0.0.0", port: 443 };
const PROXY = {
  id: "proxy-1",
  nodeId: "node-a",
  listenerId: "listener-a",
  name: "Family",
  note: "for the cousins",
  domain: "fam.example.com",
  limits: { devices: 5, connsTotal: 0, connsPerIp: 2 },
  engine: "telemt",
  engineVersion: "3.5.13",
};

function openProxy(options: Parameters<typeof createFakePanel>[0] = {}, id = "proxy-1") {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [NODE],
    listeners: [LISTENER],
    proxies: [PROXY],
    ...options,
  });
  panel.inventory.links.set("proxy-1", { tg: TG_LINK, https: HTTPS_LINK, qrSvg: QR_SVG });
  const view = renderApp({ route: `/proxies/${id}`, transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));
const ready = () => screen.findByRole("heading", { name: "Family", level: 1 });

afterEach(() => {
  vi.useRealTimers();
  Reflect.deleteProperty(window, "isSecureContext");
});

describe("ProxyDetail: the proxy", () => {
  it("is titled by the name of the proxy, and says where it is", async () => {
    openProxy();

    expect(await ready()).toBeInTheDocument();
    const info = await region(t("proxy.detail.info"));
    // The node and the listener are asked for after the proxy.
    expect(await info.findByRole("link", { name: "Frankfurt" })).toHaveAttribute("href", "/nodes/node-a");
    expect(await info.findByText("0.0.0.0:443")).toBeInTheDocument();
    expect(info.getByText("fam.example.com")).toBeInTheDocument();
    expect(info.getByText("telemt 3.5.13")).toBeInTheDocument();
    expect(info.getByText("for the cousins")).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByRole("link", { name: t("proxies.title") })).toHaveAttribute("href", "/proxies");
  });

  it("names its chain, and its chains for the middle proxies and for the downloads", async () => {
    openProxy({
      proxies: [{ ...PROXY, egressChainId: "chain-main", egressScopeChains: { me: "chain-me", fetch: "chain-dl" } }],
      chains: [
        { id: "chain-main", name: "Main" },
        { id: "chain-me", name: "Through WARP" },
        { id: "chain-dl", name: "Downloads out" },
      ],
    });

    const info = await region(t("proxy.detail.info"));
    expect(await info.findByText("Through WARP")).toBeInTheDocument();
    expect(info.getByText(t("proxy.detail.scopeMe"))).toBeInTheDocument();
    expect(info.getByText("Downloads out")).toBeInTheDocument();
    expect(info.getByText(t("proxy.detail.scopeFetch"))).toBeInTheDocument();
    expect(info.getByText("Main")).toBeInTheDocument();
  });

  it("leaves out the scope chains of a proxy that has none", async () => {
    openProxy({ proxies: [{ ...PROXY, egressChainId: "chain-main" }], chains: [{ id: "chain-main", name: "Main" }] });

    const info = await region(t("proxy.detail.info"));
    expect(await info.findByText("Main")).toBeInTheDocument();
    expect(info.queryByText(t("proxy.detail.scopeMe"))).not.toBeInTheDocument();
    expect(info.queryByText(t("proxy.detail.scopeFetch"))).not.toBeInTheDocument();
  });

  it("says why when the panel cannot list the chains", async () => {
    const { panel } = openProxy({ proxies: [{ ...PROXY, egressChainId: "chain-main" }], chains: [{ id: "chain-main", name: "Main" }] });
    panel.rpc.listChains.mockImplementation(() => {
      throw new ConnectError("the panel could not list the chains", Code.Internal);
    });

    const info = await region(t("proxy.detail.info"));
    expect(await info.findByText("the panel could not list the chains")).toBeInTheDocument();
  });

  it("is titled by its domain when it has no name", async () => {
    openProxy({ proxies: [{ ...PROXY, name: "" }] });

    expect(await screen.findByRole("heading", { name: "fam.example.com", level: 1 })).toBeInTheDocument();
  });

  it("says that there is no such proxy, with a way back", async () => {
    openProxy({}, "no-such-proxy");

    expect(await screen.findByText(t("errors.notFoundTitle"))).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByRole("link", { name: t("proxies.title") })).toHaveAttribute("href", "/proxies");
  });

  it("pauses and resumes the proxy from its page", async () => {
    const { panel, user } = openProxy();
    await ready();

    const toggle = screen.getByRole("switch", { name: t("proxy.detail.enabled") });
    expect(toggle).toBeChecked();
    await user.click(toggle);

    await waitFor(() => {
      expect(panel.rpc.setProxyEnabled).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.setProxyEnabled.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1", enabled: false });
    await waitFor(() => {
      expect(screen.getByRole("switch", { name: t("proxy.detail.enabled") })).not.toBeChecked();
    });
  });
});

describe("ProxyDetail: the links", () => {
  it("shows the tg link and the https link, whole", async () => {
    openProxy();

    const links = await region(t("proxy.detail.links"));
    expect(await links.findByText(TG_LINK)).toBeInTheDocument();
    expect(links.getByText(HTTPS_LINK)).toBeInTheDocument();
    expect(links.getByText(t("proxy.links.tg"))).toBeInTheDocument();
    expect(links.getByText(t("proxy.links.https"))).toBeInTheDocument();
  });

  it("copies the tg link", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const { user } = openProxy();

    const links = await region(t("proxy.detail.links"));
    await user.click(await links.findByRole("button", { name: t("proxy.links.copyTg") }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(TG_LINK);
  });

  it("copies the https link", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const { user } = openProxy();

    const links = await region(t("proxy.detail.links"));
    await user.click(await links.findByRole("button", { name: t("proxy.links.copyHttps") }));

    expect(await navigator.clipboard.readText()).toBe(HTTPS_LINK);
  });

  it("shows the QR code that the panel made as an image, never as markup of the page", async () => {
    openProxy();

    const links = await region(t("proxy.detail.links"));
    const picture = await links.findByRole("img", { name: t("proxy.links.qrAlt") });
    expect(picture.tagName.toLowerCase()).toBe("img");
    const source = picture.getAttribute("src") ?? "";
    expect(source.startsWith("data:image/svg+xml;base64,")).toBe(true);
    // The image is the SVG of the panel, byte for byte.
    expect(atob(source.slice("data:image/svg+xml;base64,".length))).toBe(QR_SVG);
    // None of it is in the page as an element: no SVG, no path of the QR code.
    expect(document.querySelector('path[fill="#000"]')).toBeNull();
    expect(picture.closest("svg")).toBeNull();
    // Black modules on a transparent image: the page puts white behind them, in either theme.
    expect(picture.parentElement).toHaveStyle({ backgroundColor: "rgb(255, 255, 255)" });
  });

  it("shows no image for an answer that is not an SVG, and still shows the links", async () => {
    const { panel } = openProxy();
    panel.inventory.links.set("proxy-1", { tg: TG_LINK, https: HTTPS_LINK, qrSvg: "<html><body>not a picture</body></html>" });

    const links = await region(t("proxy.detail.links"));
    expect(await links.findByText(TG_LINK)).toBeInTheDocument();
    expect(links.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.queryByText("not a picture")).not.toBeInTheDocument();
  });

  it("says why when the panel cannot make the links, and tries again on request", async () => {
    const { panel, user } = openProxy();
    panel.rpc.getProxyLinks.mockImplementationOnce(() => {
      throw new ConnectError("the node has no host for links", Code.FailedPrecondition);
    });

    const links = await region(t("proxy.detail.links"));
    expect(await links.findByText("the node has no host for links")).toBeInTheDocument();
    // The rest of the page does not wait for the links.
    expect(screen.getByRole("heading", { name: "Family", level: 1 })).toBeInTheDocument();

    await user.click(links.getByRole("button", { name: t("common.retry") }));
    expect(await links.findByText(TG_LINK)).toBeInTheDocument();
  });

  it("does not keep the links, which carry the secret, once the page is left", async () => {
    const { user, queryClient } = openProxy();
    const links = await region(t("proxy.detail.links"));
    await links.findByText(TG_LINK);
    expect(queryClient.getQueryCache().find({ queryKey: proxyKeys.links("proxy-1") })).toBeDefined();

    await user.click(within(screen.getByRole("main")).getByRole("link", { name: t("proxies.title") }));
    await screen.findByRole("heading", { name: t("proxies.title"), level: 1 });

    await waitFor(() => {
      expect(queryClient.getQueryCache().find({ queryKey: proxyKeys.links("proxy-1") })).toBeUndefined();
    });
  });
});

describe("ProxyDetail: live statistics", () => {
  it("shows the last minute that the node reported, and when", async () => {
    const { panel } = openProxy();
    panel.inventory.live.set("proxy-1", {
      minute: {
        minuteUnix: BigInt(now() - 120),
        up: 2_000_000n,
        down: 15_000_000n,
        connsNew: 6,
        connsPeak: 9,
        devices: 4,
        connsActive: 7,
      },
      status: { phase: "serving", reason: "", runningVersion: "3.5.13", instanceGeneration: 5n, reportedUnix: BigInt(now()) },
    });

    const live = await region(t("proxy.detail.live"));
    expect(await live.findByText("15 MB")).toBeInTheDocument(); // download
    expect(live.getByText("2 MB")).toBeInTheDocument(); // upload
    expect(live.getByText("7")).toBeInTheDocument(); // connections now
    expect(live.getByText("9")).toBeInTheDocument(); // peak
    expect(live.getByText("6")).toBeInTheDocument(); // new
    expect(live.getByText("4")).toBeInTheDocument(); // unique IPs
    expect(live.getByText("2 minutes ago")).toBeInTheDocument();
    expect(live.getByText(t("proxy.live.devices"))).toBeInTheDocument();
    expect(live.getByText(t("status.proxy.serving"))).toBeInTheDocument();
  });

  it("calls the unique clients of a proxy unique IPs, as the limit is called", async () => {
    openProxy();

    const live = await region(t("proxy.detail.live"));
    expect(await live.findByText("Unique IPs")).toBeInTheDocument();
  });

  it("asks the panel again every 10 seconds, and shows what it says", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { panel } = openProxy();
    const live = await region(t("proxy.detail.live"));
    await live.findByText("12 MB");
    const asked = panel.rpc.proxyLive.mock.calls.length;

    panel.inventory.live.set("proxy-1", {
      minute: {
        minuteUnix: BigInt(now()),
        up: 1n,
        down: 3_000_000_000n,
        connsNew: 0,
        connsPeak: 0,
        devices: 0,
        connsActive: 0,
      },
      status: PROXY_STATUS,
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    await waitFor(() => {
      expect(panel.rpc.proxyLive.mock.calls.length).toBeGreaterThan(asked);
    });
    expect(await live.findByText("3 GB")).toBeInTheDocument();
    expect(live.queryByText("12 MB")).not.toBeInTheDocument();
  });

  it("says that the node has reported nothing yet, instead of showing zeros", async () => {
    const { panel } = openProxy();
    panel.inventory.live.set("proxy-1", { status: PROXY_STATUS });

    const live = await region(t("proxy.detail.live"));
    expect(await live.findByText(t("proxy.live.empty"))).toBeInTheDocument();
    expect(live.queryByText(t("proxy.live.devices"))).not.toBeInTheDocument();
  });

  it("says why a proxy failed", async () => {
    const { panel } = openProxy();
    panel.inventory.live.set("proxy-1", {
      status: { phase: "failed", reason: "artifact missing: telemt 3.5.13", runningVersion: "", instanceGeneration: 5n, reportedUnix: BigInt(now()) },
    });

    const live = await region(t("proxy.detail.live"));
    expect(await live.findByText("artifact missing: telemt 3.5.13")).toBeInTheDocument();
    expect(live.getByText(t("status.proxy.failed"))).toBeInTheDocument();
  });

  it("says why when the panel cannot give the numbers, and keeps the rest of the page", async () => {
    const { panel } = openProxy();
    panel.rpc.proxyLive.mockImplementation(() => {
      throw new ConnectError("the stats are not available", Code.Internal);
    });

    const live = await region(t("proxy.detail.live"));
    expect(await live.findByText("the stats are not available")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Family", level: 1 })).toBeInTheDocument();
  });
});

describe("ProxyDetail: statistics", () => {
  it("shows the statistics of the last 24 hours to begin with, and how much was sent and received", async () => {
    const { panel } = openProxy();
    const end = now() - (now() % 60);
    panel.inventory.series.set("proxy-1", {
      stepSeconds: 60,
      fromUnix: BigInt(end - 86_400),
      toUnix: BigInt(end),
      points: [
        { tsUnix: BigInt(end - 180), up: 1_000_000n, down: 20_000_000n, connsNew: 1, connsPeak: 2, devices: 1 },
        { tsUnix: BigInt(end - 120), up: 2_000_000n, down: 30_000_000n, connsNew: 2, connsPeak: 3, devices: 2 },
      ],
    });

    expect(await screen.findByRole("heading", { name: t("insights.stats.title"), level: 2 })).toBeInTheDocument();
    const traffic = await region(t("insights.stats.traffic.title"));
    expect(await traffic.findByText("50 MB")).toBeInTheDocument(); // download in total
    expect(traffic.getByText("3 MB")).toBeInTheDocument(); // upload in total
    expect(panel.rpc.proxySeries.mock.calls[0]?.[0]).toMatchObject({ proxyId: "proxy-1", range: "24h" });
  });

  it("says why when the panel cannot give the series", async () => {
    const { panel } = openProxy();
    panel.rpc.proxySeries.mockImplementation(() => {
      throw new ConnectError("the series are not available", Code.Internal);
    });

    expect(await screen.findByText("the series are not available")).toBeInTheDocument();
  });
});

describe("ProxyDetail: the settings", () => {
  it("saves a new name, and the title of the page follows", async () => {
    const { panel, user } = openProxy();
    const settings = await region(t("proxy.detail.settings"));

    await user.clear(settings.getByLabelText(t("proxy.form.name"), FIELD));
    await user.type(settings.getByLabelText(t("proxy.form.name"), FIELD), "Friends");
    await user.click(settings.getByRole("button", { name: t("proxy.form.save") }));

    expect(await screen.findByRole("heading", { name: "Friends", level: 1 })).toBeInTheDocument();
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1", name: "Friends" });
    expect(await screen.findByText(t("proxy.form.saved"))).toBeInTheDocument();
  });

  it("asks for the links again when the domain changes, because the links carry it", async () => {
    const { panel, user } = openProxy();
    const settings = await region(t("proxy.detail.settings"));
    const links = await region(t("proxy.detail.links"));
    await links.findByText(TG_LINK);
    const asked = panel.rpc.getProxyLinks.mock.calls.length;

    panel.inventory.links.set("proxy-1", { tg: "tg://proxy?server=new", https: "https://t.me/proxy?server=new", qrSvg: QR_SVG });
    await user.clear(settings.getByLabelText(t("proxy.form.domain"), FIELD));
    await user.type(settings.getByLabelText(t("proxy.form.domain"), FIELD), "other.example.com");
    await user.click(settings.getByRole("button", { name: t("proxy.form.save") }));

    expect(await links.findByText("tg://proxy?server=new")).toBeInTheDocument();
    expect(panel.rpc.getProxyLinks.mock.calls.length).toBeGreaterThan(asked);
    expect(panel.rpc.updateProxy.mock.calls[0]?.[0]).toMatchObject({ domain: "other.example.com" });
  });

  it("shows the limits, with devices called unique IPs", async () => {
    openProxy();
    const settings = await region(t("proxy.detail.settings"));

    expect(await settings.findByLabelText("Unique IPs", FIELD)).toHaveValue("5");
    expect(settings.getByLabelText(t("proxy.form.connsPerIp"), FIELD)).toHaveValue("2");
  });
});

describe("ProxyDetail: deleting", () => {
  it("deletes the proxy after a confirmation, and goes back to the list", async () => {
    const { panel, user, router } = openProxy();
    await ready();

    await user.click(screen.getByRole("button", { name: t("proxy.delete.action") }));
    const dialog = await screen.findByRole("dialog", { name: t("proxy.delete.title") });
    expect(panel.rpc.deleteProxy).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("proxy.delete.confirm") }));

    await waitFor(() => {
      expect(panel.rpc.deleteProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.deleteProxy.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1" });
    expect(await screen.findByRole("heading", { name: t("proxies.title"), level: 1 })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/proxies");
    expect(await screen.findByText(t("proxy.delete.done"))).toBeInTheDocument();
  });

  it("names the proxy in the question, and does nothing when the admin cancels", async () => {
    const { panel, user } = openProxy();
    await ready();

    await user.click(screen.getByRole("button", { name: t("proxy.delete.action") }));
    const dialog = await screen.findByRole("dialog", { name: t("proxy.delete.title") });
    expect(within(dialog).getByText(t("proxy.delete.message", { name: "Family" }))).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));

    expect(panel.rpc.deleteProxy).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Family", level: 1 })).toBeInTheDocument();
  });

  it("shows the message of the panel when it refuses, and stays", async () => {
    const { panel, user } = openProxy();
    panel.rpc.deleteProxy.mockImplementation(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });
    await ready();

    await user.click(screen.getByRole("button", { name: t("proxy.delete.action") }));
    const dialog = await screen.findByRole("dialog", { name: t("proxy.delete.title") });
    await user.click(within(dialog).getByRole("button", { name: t("proxy.delete.confirm") }));

    expect(await screen.findByText("the database is locked")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Family", level: 1 })).toBeInTheDocument();
  });
});

describe("a new proxy", () => {
  it("lands on its page, where the links are, once it is made", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [LISTENER] });
    const user = userEvent.setup();
    const { router } = renderApp({ route: "/proxies", transport: panel.transport });

    await user.click(await screen.findByRole("button", { name: t("proxies.add") }));
    const dialog = await screen.findByRole("dialog", { name: t("proxies.addTitle") });
    await within(dialog).findByDisplayValue("0.0.0.0:443");
    await user.type(within(dialog).getByLabelText(t("proxy.form.name"), FIELD), "Cousins");
    await user.click(within(dialog).getByRole("button", { name: t("proxy.form.create") }));

    expect(await screen.findByRole("heading", { name: "Cousins", level: 1 })).toBeInTheDocument();
    expect(router.state.location.pathname).toMatch(/^\/proxies\/.+/);
    const links = await region(t("proxy.detail.links"));
    expect(await links.findByText(/^tg:\/\/proxy\?server=203\.0\.113\.7&port=443&secret=ee/)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("ProxyDetail: a WEB proxy", () => {
  const UPSTREAM = { id: "listener-up", nodeId: "node-a", kind: "http-upstream", bindIp: "127.0.0.1", port: 8089, trustedCidrs: ["127.0.0.1/32"] };
  const WEB = { ...PROXY, type: "web", domain: "site.example.com", web: { basePath: "tg", secretMode: "dd", carrier: "https" } };

  it("behind a web server: says so, and shows the snippets for Caddy and nginx", async () => {
    openProxy({ listeners: [LISTENER, UPSTREAM], proxies: [{ ...WEB, listenerId: "listener-up" }] });
    const info = await region(t("proxy.detail.info"));
    expect(await info.findByText(`127.0.0.1:8089 (${t("listener.kind.http-upstream")})`)).toBeInTheDocument();
    expect(info.getByText("https://site.example.com/tg")).toBeInTheDocument();
    expect(info.getByText(t("proxy.detail.certificateUpstream"))).toBeInTheDocument();

    const snippets = await region(t("proxy.snippets.title"));
    const caddy = await snippets.findByText(/handle \/tg\/\* \{/);
    expect(caddy.textContent).toContain("reverse_proxy 127.0.0.1:8089");
    expect(snippets.getByText(/location = \/tg \{/)).toBeInTheDocument();
    expect(snippets.getByRole("button", { name: t("proxy.snippets.copyNginx") })).toBeInTheDocument();
  });

  it("on a public port: names the certificate and shows no snippets", async () => {
    openProxy({ proxies: [{ ...WEB, web: { ...WEB.web, certMode: "imported", certSha256: "ab".repeat(32), certNotAfterUnix: BigInt(now() + 86_400) } }] });
    const info = await region(t("proxy.detail.info"));
    expect(await info.findByText(/Imported, valid until/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: t("proxy.snippets.title") })).not.toBeInTheDocument();
  });
});
