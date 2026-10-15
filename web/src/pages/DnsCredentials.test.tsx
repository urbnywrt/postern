import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

// A made-up token, by repetition: it cannot be taken for a real one.
const TOKEN = "tok".repeat(8);
const FIELD = { selector: "input, textarea" };

function openPage(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, ...options });
  const view = renderApp({ route: "/dns", transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

describe("DnsCredentials", () => {
  it("lists the credentials with how many proxies use them, and never a token", async () => {
    openPage({
      nodes: [{ id: "node-a", name: "Frankfurt" }],
      listeners: [{ id: "listener-a", nodeId: "node-a" }],
      proxies: [{ id: "p1", nodeId: "node-a", listenerId: "listener-a", type: "web", web: { dnsCredentialId: "dns-main" } }],
      dnsCredentials: [{ id: "dns-main", name: "Main zone" }],
    });
    expect(await screen.findByText("Main zone")).toBeInTheDocument();
    expect(screen.getByText(t("dns.usedBy", { count: 1 }))).toBeInTheDocument();
    expect(screen.getByText(t("dns.provider.cloudflare"))).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it("adds a credential: the token goes to the panel once and is not shown afterwards", async () => {
    const { panel, user, container } = openPage();
    expect(await screen.findByText(t("dns.empty"))).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("dns.add") }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText(t("dns.form.name"), FIELD), "Main zone");
    await user.type(dialog.getByLabelText(t("dns.form.token"), FIELD), TOKEN);
    await user.click(dialog.getByRole("button", { name: t("dns.form.create") }));

    await waitFor(() => {
      expect(panel.rpc.createDnsCredential).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createDnsCredential.mock.calls[0]?.[0]).toMatchObject({ name: "Main zone", provider: "cloudflare", token: TOKEN });
    expect(await screen.findByText("Main zone")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(container.innerHTML).not.toContain(TOKEN);
  });

  it("refuses an empty token before it calls the panel", async () => {
    const { panel, user } = openPage();
    await user.click(await screen.findByRole("button", { name: t("dns.add") }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText(t("dns.form.name"), FIELD), "Main zone");
    await user.click(dialog.getByRole("button", { name: t("dns.form.create") }));
    expect(await dialog.findByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.createDnsCredential).not.toHaveBeenCalled();
  });

  it("replaces the token of a credential without asking for the old one, and keeps the name", async () => {
    const { panel, user } = openPage({ dnsCredentials: [{ id: "dns-main", name: "Main zone" }] });
    await user.click(await screen.findByRole("button", { name: t("dns.edit", { name: "Main zone" }) }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText(t("dns.form.token"), FIELD)).toHaveValue("");
    await user.type(dialog.getByLabelText(t("dns.form.token"), FIELD), TOKEN);
    await user.click(dialog.getByRole("button", { name: t("dns.form.save") }));

    await waitFor(() => {
      expect(panel.rpc.updateDnsCredential).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateDnsCredential.mock.calls[0]?.[0]).toMatchObject({ id: "dns-main", token: TOKEN });
    expect(panel.rpc.updateDnsCredential.mock.calls[0]?.[0]).not.toHaveProperty("name");
  });

  it("says why a credential that proxies use cannot be deleted", async () => {
    const { user } = openPage({
      nodes: [{ id: "node-a", name: "Frankfurt" }],
      listeners: [{ id: "listener-a", nodeId: "node-a" }],
      proxies: [{ id: "p1", nodeId: "node-a", listenerId: "listener-a", type: "web", web: { dnsCredentialId: "dns-main" } }],
      dnsCredentials: [{ id: "dns-main", name: "Main zone" }],
    });
    await user.click(await screen.findByRole("button", { name: t("dns.delete.action", { name: "Main zone" }) }));
    await user.click(await screen.findByRole("button", { name: t("dns.delete.confirm") }));
    expect(await screen.findByText("proxies still use the dns credential: give them another one first")).toBeInTheDocument();
    expect(screen.getByText("Main zone")).toBeInTheDocument();
  });
});
