import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { ProxyForm } from "./ProxyForm";

const NODE = { id: "node-a", name: "Frankfurt", linkHost: "203.0.113.7" };
const TLS = { id: "listener-tls", nodeId: "node-a", kind: "tls", bindIp: "0.0.0.0", port: 443 };
const UPSTREAM = { id: "listener-up", nodeId: "node-a", kind: "http-upstream", bindIp: "127.0.0.1", port: 8089, trustedCidrs: ["127.0.0.1/32"] };

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const createButton = () => screen.getByRole("button", { name: t("proxy.form.create") });

type User = ReturnType<typeof userEvent.setup>;

function openCreateForm(options: Parameters<typeof createFakePanel>[0] = {}) {
  const onDone = vi.fn<(proxy: Proxy) => void>();
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], listeners: [TLS, UPSTREAM], dnsCredentials: [{ id: "dns-main", name: "Main zone" }], ...options });
  renderWithProviders(<ProxyForm nodeId={NODE.id} onDone={onDone} onCancel={vi.fn()} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup() };
}

async function choose(user: User, key: TKey, option: string) {
  await user.click(field(key));
  await user.click(await screen.findByRole("option", { name: option }));
}

// Each test drives a long form through many clicks: under the load of the whole suite
// that takes longer than the default 5 s, so the file has a longer timeout.
describe("ProxyForm: a WEB proxy", { timeout: 20_000 }, () => {
  it("on a tls listener: asks for the domain, the credential of the certificate, and sends the type and the WEB settings", async () => {
    const { panel, user, onDone } = openCreateForm();
    await screen.findByLabelText(t("proxy.form.listener"), FIELD);
    await user.click(screen.getByRole("radio", { name: t("proxy.type.web") }));
    await choose(user, "proxy.form.listener", "0.0.0.0:443");

    // A WEB proxy needs its domain: nothing is picked from the pool.
    await user.click(createButton());
    expect((await screen.findAllByText(t("validation.required"))).length).toBeGreaterThan(0);
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();

    await user.type(field("proxy.form.domain"), "proxy.example.com");
    await user.type(field("proxy.form.basePath"), "tg");
    await choose(user, "proxy.form.secretMode", t("proxy.secretMode.dd"));
    await choose(user, "proxy.form.dnsCredential", "Main zone");
    await user.type(field("proxy.form.acmeEmail"), "admin@example.com");
    await user.click(createButton());

    await waitFor(() => {
      expect(panel.rpc.createProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({
      nodeId: NODE.id,
      listenerId: TLS.id,
      type: "web",
      domain: "proxy.example.com",
      web: { basePath: "tg", secretMode: "dd", carrier: "https", certMode: "acme-dns01", dnsCredentialId: "dns-main", acmeEmail: "admin@example.com" },
    });
    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(onDone.mock.calls[0]?.[0]).toMatchObject({ type: "web", web: { basePath: "tg", certMode: "acme-dns01" } });
  });

  it("behind a web server (http-upstream): requires a base path and asks for no certificate", async () => {
    const { panel, user } = openCreateForm();
    await screen.findByLabelText(t("proxy.form.listener"), FIELD);
    await user.click(screen.getByRole("radio", { name: t("proxy.type.web") }));
    await choose(user, "proxy.form.listener", `127.0.0.1:8089 (${t("listener.kind.http-upstream")})`);
    await user.type(field("proxy.form.domain"), "site.example.com");
    expect(screen.queryByLabelText(t("proxy.form.certMode"), FIELD)).not.toBeInTheDocument();

    await user.click(createButton());
    expect(await screen.findByText(t("validation.basePathRequired"))).toBeInTheDocument();
    expect(panel.rpc.createProxy).not.toHaveBeenCalled();

    await user.type(field("proxy.form.basePath"), "tg/web");
    await user.click(createButton());
    await waitFor(() => {
      expect(panel.rpc.createProxy).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createProxy.mock.calls[0]?.[0]).toMatchObject({
      listenerId: UPSTREAM.id,
      type: "web",
      web: { basePath: "tg/web", certMode: "", dnsCredentialId: "" },
    });
  });

  it("with an imported certificate: sends the chain and the key as bytes", async () => {
    const { panel, user } = openCreateForm();
    await screen.findByLabelText(t("proxy.form.listener"), FIELD);
    await user.click(screen.getByRole("radio", { name: t("proxy.type.web") }));
    await choose(user, "proxy.form.listener", "0.0.0.0:443");
    await user.type(field("proxy.form.domain"), "proxy.example.com");
    await choose(user, "proxy.form.certMode", t("proxy.certMode.imported"));

    await user.click(createButton());
    expect(await screen.findByText(t("validation.certificate"))).toBeInTheDocument();

    // Pasted, as PEM is: typing it key by key is slow.
    await user.click(field("proxy.form.certChain"));
    await user.paste("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----");
    await user.click(field("proxy.form.certKey"));
    await user.paste("-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----");
    await user.click(createButton());
    await waitFor(() => {
      expect(panel.rpc.createProxy).toHaveBeenCalledTimes(1);
    });
    const sent = panel.rpc.createProxy.mock.calls[0]?.[0];
    expect(sent?.web?.certMode).toBe("imported");
    expect(new TextDecoder().decode(sent?.web?.certFullchainPem)).toContain("BEGIN CERTIFICATE");
    expect(new TextDecoder().decode(sent?.web?.certKeyPem)).toContain("PRIVATE KEY");
  });

  it("shows what the panel warned of, and is done: the proxy was taken", async () => {
    const { panel, user, onDone } = openCreateForm();
    const warning = "node Frankfurt has not reported its public IP addresses yet";
    const create = panel.rpc.createProxy.getMockImplementation();
    if (create === undefined) throw new Error("no createProxy");
    panel.rpc.createProxy.mockImplementationOnce(async (req) => ({ ...(await create(req)), warnings: [warning] }));
    await screen.findByLabelText(t("proxy.form.listener"), FIELD);
    await user.click(screen.getByRole("radio", { name: t("proxy.type.web") }));
    await choose(user, "proxy.form.listener", "0.0.0.0:443");
    await user.type(field("proxy.form.domain"), "proxy.example.com");
    await choose(user, "proxy.form.dnsCredential", "Main zone");
    await user.click(createButton());
    expect(await screen.findByText(warning)).toBeInTheDocument();
    expect(screen.getByText(t("proxy.form.warning"))).toBeInTheDocument();
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("hides the http-upstream listener from a fake-TLS proxy", async () => {
    const { user } = openCreateForm();
    await user.click(await screen.findByLabelText(t("proxy.form.listener"), FIELD));
    expect(await screen.findByRole("option", { name: "0.0.0.0:443" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: new RegExp("127.0.0.1:8089") })).not.toBeInTheDocument();
  });
});
