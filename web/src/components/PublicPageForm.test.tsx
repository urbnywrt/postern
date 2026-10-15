import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { PublicPageSchema } from "../gen/postern/panel/v1/publicpage_pb";
import { ADMIN_HOST_REFUSED, createFakePanel, type FakePanelOptions } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { PublicPageForm } from "./PublicPageForm";

const NODE = { id: "node-a", name: "Frankfurt" };
const LISTENER = { id: "listener-a", nodeId: NODE.id };
const PROXIES = [
  { id: "proxy-a", nodeId: NODE.id, listenerId: LISTENER.id, name: "Alpha", domain: "alpha.example.com" },
  { id: "proxy-b", nodeId: NODE.id, listenerId: LISTENER.id, name: "Beta", domain: "beta.example.com" },
  { id: "proxy-c", nodeId: NODE.id, listenerId: LISTENER.id, name: "", domain: "gamma.example.com" },
];

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
// A Switch keeps its input inside the label, next to the hint: its name begins with the label.
const toggle = (key: TKey) => screen.getByRole("switch", { name: (name) => name.startsWith(t(key)) });
const saveButton = () => screen.getByRole("button", { name: t("insights.publicPage.save") });
const itemRows = () => screen.queryAllByRole("listitem");
/** The queries of one row of the items, by its place. */
function row(index: number) {
  const element = itemRows()[index];
  if (element === undefined) {
    throw new Error(`there is no item ${String(index)}`);
  }
  return within(element);
}
const publicNames = () =>
  itemRows().map((element) => within(element).getByLabelText<HTMLInputElement>(t("insights.publicPage.publicName")).value);

type User = ReturnType<typeof userEvent.setup>;

async function open(options: Omit<FakePanelOptions, "signedIn"> = {}) {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [NODE],
    listeners: [LISTENER],
    proxies: PROXIES,
    ...options,
  });
  renderWithProviders(<PublicPageForm />, { transport: panel.transport });
  // The form is on the screen once the stored page has arrived.
  await screen.findByLabelText(t("insights.publicPage.host"), FIELD);
  return { panel, user: userEvent.setup() };
}

async function addProxy(user: User, option: RegExp) {
  await user.click(field("insights.publicPage.addProxy"));
  await user.click(await screen.findByRole("option", { name: option }));
  await user.click(screen.getByRole("button", { name: t("insights.publicPage.add") }));
}

function sentPage(panel: Awaited<ReturnType<typeof open>>["panel"], call = 0) {
  return panel.rpc.updatePublicPage.mock.calls[call]?.[0].page;
}

describe("PublicPageForm: what is stored", () => {
  it("starts from the stored page, with indexing off and mark by default", async () => {
    await open({
      publicPage: {
        host: "proxies.example.test",
        title: "Our proxies",
        bodyMd: "Welcome",
        items: [{ proxyId: "proxy-b", publicName: "Second", publicNote: "Berlin" }],
      },
    });

    expect(field("insights.publicPage.host")).toHaveValue("proxies.example.test");
    expect(field("insights.publicPage.pageTitle")).toHaveValue("Our proxies");
    expect(field("insights.publicPage.body")).toHaveValue("Welcome");
    expect(toggle("insights.publicPage.enabled")).not.toBeChecked();
    expect(toggle("insights.publicPage.allowIndexing")).not.toBeChecked();
    expect(field("insights.publicPage.unavailable")).toHaveValue(t("insights.publicPage.unavailableMark"));
    expect(field("insights.publicPage.defaultLocale")).toHaveValue("Русский");
    expect(itemRows()).toHaveLength(1);
    expect(row(0).getByLabelText(t("insights.publicPage.publicName"))).toHaveValue("Second");
    expect(row(0).getByLabelText(t("insights.publicPage.publicNote"))).toHaveValue("Berlin");
  });

  it("warns that everything on the page is public, secrets included", async () => {
    await open();
    expect(screen.getByText(t("insights.publicPage.warning"))).toBeInTheDocument();
  });

  it("links to https://<host>/ once the page is served, and not before", async () => {
    await open({ publicPage: { enabled: true, host: "proxies.example.test" } });
    const link = screen.getByRole("link", { name: t("insights.publicPage.openLink") });
    expect(link).toHaveAttribute("href", "https://proxies.example.test/");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("shows no link while the page is off", async () => {
    await open({ publicPage: { enabled: false, host: "proxies.example.test" } });
    expect(screen.queryByRole("link", { name: t("insights.publicPage.openLink") })).not.toBeInTheDocument();
  });
});

describe("PublicPageForm: validation", () => {
  it("refuses to serve the page without a host, before it calls the panel", async () => {
    const { panel, user } = await open();

    await user.click(toggle("insights.publicPage.enabled"));
    await user.click(saveButton());

    expect(await screen.findByText(t("insights.publicPage.validation.hostRequired"))).toBeInTheDocument();
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
  });

  it.each([
    ["one label", "proxies"],
    ["an IP address", "203.0.113.7"],
    ["a port", "proxies.example.test:8443"],
    ["a scheme", "https://proxies.example.test"],
    ["a dot at the end", "proxies.example.test."],
  ])("refuses a host that has %s", async (_name, host) => {
    const { panel, user } = await open();

    await user.type(field("insights.publicPage.host"), host);
    await user.click(saveButton());

    expect(await screen.findByText(t("insights.publicPage.validation.host"))).toBeInTheDocument();
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
  });

  it("refuses a title of more than 120 bytes", async () => {
    const { panel, user } = await open();

    await user.click(field("insights.publicPage.pageTitle"));
    await user.paste("ж".repeat(61)); // 122 bytes in UTF-8, 61 characters
    await user.click(saveButton());

    expect(await screen.findByText(t("insights.publicPage.validation.bytesLong", { max: 120 }))).toBeInTheDocument();
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
  });

  it("refuses a public name of more than 64 characters and a note of more than 280", async () => {
    const { panel, user } = await open();

    await addProxy(user, /Alpha/);
    const name = row(0).getByLabelText(t("insights.publicPage.publicName"));
    await user.clear(name);
    await user.click(name);
    await user.paste("n".repeat(65));
    await user.click(row(0).getByLabelText(t("insights.publicPage.publicNote")));
    await user.paste("x".repeat(281));
    await user.click(saveButton());

    expect(await screen.findByText(t("validation.textLong", { max: 64 }))).toBeInTheDocument();
    expect(screen.getByText(t("validation.textLong", { max: 280 }))).toBeInTheDocument();
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
  });

  it("saves a page that is off with an empty host, and sends indexing off explicitly", async () => {
    const { panel, user } = await open();

    await user.type(field("insights.publicPage.pageTitle"), "Soon");
    await user.click(saveButton());

    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    // The whole page, every field: nothing is left for the panel to read as a default.
    expect(sentPage(panel)).toEqual(
      create(PublicPageSchema, {
        enabled: false,
        host: "",
        title: "Soon",
        bodyMd: "",
        unavailable: "mark",
        defaultLocale: "ru",
        items: [],
        allowIndexing: false,
      }),
    );
    expect(await screen.findByText(t("insights.publicPage.saved"))).toBeInTheDocument();
  });
});

describe("PublicPageForm: items", () => {
  it("adds a proxy with its name as the public name, and a proxy without a name with its domain", async () => {
    const { panel, user } = await open();

    await addProxy(user, /Alpha/);
    await addProxy(user, /gamma\.example\.com/);

    expect(publicNames()).toEqual(["Alpha", "gamma.example.com"]);

    await user.click(saveButton());
    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    expect(sentPage(panel)?.items).toEqual([
      expect.objectContaining({ proxyId: "proxy-a", publicName: "Alpha", publicNote: "" }),
      expect.objectContaining({ proxyId: "proxy-c", publicName: "gamma.example.com", publicNote: "" }),
    ]);
  });

  it("offers only the proxies that are not on the page yet", async () => {
    const { user } = await open({ publicPage: { items: [{ proxyId: "proxy-a", publicName: "Alpha", publicNote: "" }] } });

    await user.click(field("insights.publicPage.addProxy"));
    const options = await screen.findAllByRole("option");
    expect(options.map((option) => option.textContent)).toEqual([expect.stringContaining("Beta"), expect.stringContaining("gamma")]);
  });

  it("reorders with the move buttons and sends the new order", async () => {
    const { panel, user } = await open({
      publicPage: {
        items: [
          { proxyId: "proxy-a", publicName: "Alpha", publicNote: "" },
          { proxyId: "proxy-b", publicName: "Beta", publicNote: "" },
          { proxyId: "proxy-c", publicName: "Gamma", publicNote: "" },
        ],
      },
    });

    // The first cannot go up, the last cannot go down.
    expect(screen.getByRole("button", { name: t("insights.publicPage.moveUp", { name: "Alpha" }) })).toBeDisabled();
    expect(screen.getByRole("button", { name: t("insights.publicPage.moveDown", { name: "Gamma" }) })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: t("insights.publicPage.moveDown", { name: "Alpha" }) }));
    await user.click(screen.getByRole("button", { name: t("insights.publicPage.moveUp", { name: "Gamma" }) }));

    expect(publicNames()).toEqual(["Beta", "Gamma", "Alpha"]);

    await user.click(saveButton());
    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    expect(sentPage(panel)?.items.map((item) => item.proxyId)).toEqual(["proxy-b", "proxy-c", "proxy-a"]);
  });

  it("removes an item, and offers its proxy again", async () => {
    const { panel, user } = await open({
      publicPage: {
        items: [
          { proxyId: "proxy-a", publicName: "Alpha", publicNote: "" },
          { proxyId: "proxy-b", publicName: "Beta", publicNote: "" },
        ],
      },
    });

    await user.click(screen.getByRole("button", { name: t("insights.publicPage.remove", { name: "Alpha" }) }));
    expect(itemRows()).toHaveLength(1);

    await user.click(field("insights.publicPage.addProxy"));
    expect(await screen.findByRole("option", { name: /Alpha/ })).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await user.click(saveButton());
    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    expect(sentPage(panel)?.items.map((item) => item.proxyId)).toEqual(["proxy-b"]);
  });
});

describe("PublicPageForm: serving the page", () => {
  it("asks before the page goes public, and sends nothing when the question is closed", async () => {
    const { panel, user } = await open({
      publicPage: { host: "proxies.example.test", items: [{ proxyId: "proxy-a", publicName: "Alpha", publicNote: "" }] },
    });

    await user.click(toggle("insights.publicPage.enabled"));
    await user.click(saveButton());

    const dialog = await screen.findByRole("dialog", { name: t("insights.publicPage.confirm.title") });
    expect(within(dialog).getByText(/proxies\.example\.test/)).toBeInTheDocument();
    // One proxy, in the singular.
    expect(within(dialog).getByText(/the links of 1 proxy to anyone/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
    expect(toggle("insights.publicPage.enabled")).toBeChecked();
  });

  it("sends the page, enabled, once the question is confirmed, with every switch explicit", async () => {
    const { panel, user } = await open({ publicPage: { host: "proxies.example.test" } });

    await user.click(toggle("insights.publicPage.enabled"));
    await user.click(toggle("insights.publicPage.allowIndexing"));
    await user.click(saveButton());

    const dialog = await screen.findByRole("dialog", { name: t("insights.publicPage.confirm.title") });
    await user.click(within(dialog).getByRole("button", { name: t("insights.publicPage.confirm.confirm") }));

    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    expect(sentPage(panel)).toMatchObject({ enabled: true, host: "proxies.example.test", allowIndexing: true });
    expect(await screen.findByRole("link", { name: t("insights.publicPage.openLink") })).toHaveAttribute(
      "href",
      "https://proxies.example.test/",
    );
  });

  it("asks nothing when the page is served already", async () => {
    const { panel, user } = await open({ publicPage: { enabled: true, host: "proxies.example.test" } });

    await user.type(field("insights.publicPage.pageTitle"), "Still here");
    await user.click(saveButton());

    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(sentPage(panel)).toMatchObject({ enabled: true, title: "Still here" });
  });

  it("shows the refusal of an admin host in place, and keeps what was typed", async () => {
    const { panel, user } = await open({ adminHosts: ["panel.example.test"] });

    await user.type(field("insights.publicPage.host"), "panel.example.test");
    await user.type(field("insights.publicPage.pageTitle"), "Ours");
    await user.click(saveButton());

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(ADMIN_HOST_REFUSED);
    expect(field("insights.publicPage.host")).toHaveValue("panel.example.test");
    expect(field("insights.publicPage.pageTitle")).toHaveValue("Ours");
    expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(saveButton()).toBeEnabled();
    });

    // The refusal goes once the host is changed.
    await user.type(field("insights.publicPage.host"), "x");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("PublicPageForm: failures", () => {
  it("shows a failure that is not a refusal as such, and keeps it when the host changes", async () => {
    const { panel, user } = await open();
    panel.rpc.updatePublicPage.mockImplementation(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });

    await user.type(field("insights.publicPage.host"), "proxies.example.test");
    await user.click(saveButton());

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(t("insights.publicPage.saveFailed"));
    expect(alert).not.toHaveTextContent(t("insights.publicPage.refused"));
    expect(alert).toHaveTextContent("the database is locked");

    await user.type(field("insights.publicPage.host"), "x");
    expect(screen.getByRole("alert")).toHaveTextContent("the database is locked");
  });

  it("says that the proxies could not be loaded, instead of that there are none", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [LISTENER], proxies: PROXIES });
    panel.rpc.listProxies.mockImplementation(() => {
      throw new ConnectError("the proxies are not available", Code.Internal);
    });
    renderWithProviders(<PublicPageForm />, { transport: panel.transport });

    expect(
      await screen.findByText(t("insights.publicPage.proxiesFailed", { reason: "the proxies are not available" })),
    ).toBeInTheDocument();
    expect(screen.queryByText(t("insights.publicPage.noProxies"))).not.toBeInTheDocument();
  });

  it("says that the proxies are loading, instead of that there are none", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [LISTENER], proxies: PROXIES });
    panel.rpc.listProxies.mockImplementation(() => new Promise(() => undefined));
    renderWithProviders(<PublicPageForm />, { transport: panel.transport });

    expect(await screen.findByText(t("insights.publicPage.proxiesLoading"))).toBeInTheDocument();
    expect(screen.queryByText(t("insights.publicPage.noProxies"))).not.toBeInTheDocument();
  });
});

describe("PublicPageForm: the check of the host", () => {
  const HOST = "proxies.example.test";
  const dnsLine = (text: string) => `${t("insights.publicPage.check.dns")}: ${text}`;
  const httpsLine = (text: string) => `${t("insights.publicPage.check.https")}: ${text}`;
  const checkButton = () => screen.queryByRole("button", { name: t("insights.publicPage.check.button") });

  it("runs by itself when the page is on and shows where the name points and until when the certificate holds", async () => {
    const { panel } = await open({ publicPage: { host: HOST, enabled: true } });

    expect(await screen.findByText(dnsLine(t("insights.publicPage.check.dnsFound", { addresses: "203.0.113.10" })))).toBeInTheDocument();
    expect(screen.getByText(httpsLine(t("insights.publicPage.check.httpsOk", { date: "15.03" })))).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: t("insights.publicPage.check.hintLink") })).not.toBeInTheDocument();
    expect(screen.queryByText(t("insights.publicPage.check.notPanel"))).not.toBeInTheDocument();
    expect(panel.rpc.checkPublicPage).toHaveBeenCalledTimes(1);
  });

  it("waits for the button while the page is off", async () => {
    const { panel, user } = await open({ publicPage: { host: HOST } });
    const button = screen.getByRole("button", { name: t("insights.publicPage.check.button") });
    expect(panel.rpc.checkPublicPage).not.toHaveBeenCalled();

    await user.click(button);
    expect(await screen.findByText(dnsLine(t("insights.publicPage.check.dnsFound", { addresses: "203.0.113.10" })))).toBeInTheDocument();
    expect(panel.rpc.checkPublicPage).toHaveBeenCalledTimes(1);
  });

  it("shows the error of HTTPS and points to the guide of the reverse proxy", async () => {
    await open({
      publicPage: { host: HOST, enabled: true },
      publicPageCheck: { addresses: [], dnsError: "not found", httpsError: "remote error: tls: internal error" },
    });

    expect(await screen.findByText(dnsLine(t("insights.publicPage.check.dnsNotFound")))).toBeInTheDocument();
    expect(screen.getByText(httpsLine("remote error: tls: internal error"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("insights.publicPage.check.hintLink") })).toHaveAttribute(
      "href",
      "https://github.com/urbnywrt/postern/blob/main/deploy/panel/README.md#behind-a-reverse-proxy",
    );
  });

  it("says when something other than the panel answers", async () => {
    await open({
      publicPage: { host: HOST, enabled: true },
      publicPageCheck: { addresses: ["192.0.2.1"], httpsOk: true, certNotAfterUnix: 1_805_112_000n, servedByPanel: false },
    });
    expect(await screen.findByText(t("insights.publicPage.check.notPanel"))).toBeInTheDocument();
  });

  it("says that it checks the saved host while another one is typed", async () => {
    const { user } = await open({ publicPage: { host: HOST } });
    const unsaved = t("insights.publicPage.check.unsaved", { host: HOST });
    expect(screen.queryByText(unsaved)).toBeNull();

    await user.clear(field("insights.publicPage.host"));
    await user.type(field("insights.publicPage.host"), "other.example.test");
    expect(await screen.findByText(unsaved)).toBeInTheDocument();
  });

  it("has no check without a stored host", async () => {
    await open();
    expect(checkButton()).toBeNull();
  });
});

describe("PublicPageForm: the board", () => {
  it("starts from the stored two-line title, footer and codes, with the country as the placeholder", async () => {
    await open({
      publicPage: {
        title: "Pick\nа direction",
        footer: "Try the next one",
        items: [
          { proxyId: "proxy-a", publicName: "Alpha", publicNote: "", code: "RU", country: "NL" },
          { proxyId: "proxy-b", publicName: "Beta", publicNote: "", code: "", country: "DE" },
          { proxyId: "proxy-c", publicName: "Gamma", publicNote: "", code: "", country: "" },
        ],
      },
    });

    expect(field("insights.publicPage.pageTitle")).toHaveValue("Pick\nа direction");
    expect(field("insights.publicPage.pageTitle").tagName).toBe("TEXTAREA");
    expect(field("insights.publicPage.footer")).toHaveValue("Try the next one");
    expect(screen.getByText(t("insights.publicPage.footerHint"))).toBeInTheDocument();
    const code = (index: number) => row(index).getByLabelText(t("insights.publicPage.code"));
    expect(code(0)).toHaveValue("RU");
    expect(code(1)).toHaveValue("");
    expect(code(1)).toHaveAttribute("placeholder", "DE");
    expect(code(2)).toHaveAttribute("placeholder", t("insights.publicPage.codeAuto"));
    expect(row(0).getByText(t("insights.publicPage.codeHint"))).toBeInTheDocument();
  });

  it("refuses a title of three lines, a footer of more than 300 bytes and a code that is not up to 4 letters and digits", async () => {
    const { panel, user } = await open({
      publicPage: {
        items: [
          { proxyId: "proxy-a", publicName: "Alpha", publicNote: "" },
          { proxyId: "proxy-b", publicName: "Beta", publicNote: "" },
        ],
      },
    });

    await user.click(field("insights.publicPage.pageTitle"));
    await user.paste("one\ntwo\nthree");
    await user.click(field("insights.publicPage.footer"));
    await user.paste("ж".repeat(151)); // 302 bytes in UTF-8
    await user.type(row(0).getByLabelText(t("insights.publicPage.code")), "ABCDE");
    await user.type(row(1).getByLabelText(t("insights.publicPage.code")), "R-U");
    await user.click(saveButton());

    expect(await screen.findByText(t("insights.publicPage.validation.titleLines"))).toBeInTheDocument();
    expect(screen.getByText(t("insights.publicPage.validation.bytesLong", { max: 300 }))).toBeInTheDocument();
    expect(screen.getAllByText(t("insights.publicPage.validation.code", { max: 4 }))).toHaveLength(2);
    expect(panel.rpc.updatePublicPage).not.toHaveBeenCalled();
  });

  it("sends the two lines of the title, the footer and the codes in upper case", async () => {
    const { panel, user } = await open({
      publicPage: { items: [{ proxyId: "proxy-a", publicName: "Alpha", publicNote: "", country: "NL" }] },
    });

    await user.click(field("insights.publicPage.pageTitle"));
    await user.paste("  Pick \n a direction ");
    await user.click(field("insights.publicPage.footer"));
    await user.paste(" line one\nline two ");
    await user.type(row(0).getByLabelText(t("insights.publicPage.code")), " r2d ");
    await addProxy(user, /Beta/);
    await user.click(saveButton());

    await waitFor(() => {
      expect(panel.rpc.updatePublicPage).toHaveBeenCalledTimes(1);
    });
    const sent = sentPage(panel);
    expect(sent?.title).toBe("Pick\na direction");
    expect(sent?.footer).toBe("line one\nline two");
    expect(sent?.items.map((item) => [item.proxyId, item.code])).toEqual([
      ["proxy-a", "R2D"],
      ["proxy-b", ""],
    ]);
  });
});
