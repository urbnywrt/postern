import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { formatDateTime } from "../app/format";
import { PANEL_URL_KEY } from "../app/panelUrl";
import { composeFor, dockerCommandFor, NODE_IMAGE } from "../test/fakeInventory";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { NodeDockerInstall } from "./NodeDockerInstall";

const FIELD = { selector: "input" };
const urlField = () => screen.findByLabelText(t("nodes.docker.panelUrl"), FIELD);
/** The block of code that holds exactly `text`, line breaks and all. */
const codeBlock = (text: string) =>
  screen.findByText((_content, element) => element?.tagName === "PRE" && element.textContent === text);
const getButton =() => screen.findByRole("button", { name: t("nodes.docker.get") });

function open(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [{ id: "node-a", mgmtPort: 61234 }], ...options });
  const node = panel.inventory.nodes[0];
  if (node === undefined) {
    throw new Error("no node");
  }
  renderWithProviders(<NodeDockerInstall node={node} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

afterEach(() => {
  window.localStorage.clear();
});

describe("NodeDockerInstall", () => {
  it("starts from the address of the page, and asks for no command by itself", async () => {
    const { panel } = open();

    await getButton();
    expect(await urlField()).toHaveValue(window.location.origin);
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("starts from the address last used in this browser", async () => {
    window.localStorage.setItem(PANEL_URL_KEY, "https://panel.example.com");
    open();

    await getButton();
    expect(await urlField()).toHaveValue("https://panel.example.com");
  });

  it("gets the command on the button and shows both forms of it, as the panel wrote them", async () => {
    const { panel, user } = open();

    await user.clear(await urlField());
    await user.type(await urlField(), "HTTPS://Panel.Example.com/");
    await user.click(await getButton());

    const run = await screen.findByRole("tab", { name: "docker run" });
    expect(run).toHaveAttribute("aria-selected", "true");
    expect(panel.rpc.createJoinToken).toHaveBeenCalledTimes(1);
    expect(panel.rpc.createJoinToken.mock.calls[0]?.[0]).toMatchObject({
      nodeId: "node-a",
      panelUrl: "https://panel.example.com",
    });
    const token = panel.inventory.joinTokens.get("node-a") ?? "?";
    expect(await codeBlock(dockerCommandFor(NODE_IMAGE, "https://panel.example.com", token))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("nodes.docker.copyRun") })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "compose.yaml" }));
    expect(await codeBlock(composeFor(NODE_IMAGE, "https://panel.example.com", token))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("nodes.docker.copyCompose") })).toBeInTheDocument();

    // When it runs out, that it works once, that a new one cancels it, and the firewall.
    const expires = (panel.rpc.createJoinToken.mock.results[0]?.value as { expiresUnix: bigint }).expiresUnix;
    expect(
      screen.getByText(`${t("nodes.docker.expires", { at: formatDateTime(expires) })} ${t("nodes.docker.replaces")}`),
    ).toBeInTheDocument();
    expect(screen.getByText(t("nodes.docker.firewall", { port: 61234 }))).toBeInTheDocument();
    // The browser keeps the address, in its normal form.
    expect(window.localStorage.getItem(PANEL_URL_KEY)).toBe("https://panel.example.com");
  });

  it("refuses an address that a node cannot use, before it asks the panel", async () => {
    const { panel, user } = open();

    await user.clear(await urlField());
    await user.type(await urlField(), "http://panel.example.com");
    await user.click(await getButton());

    expect(await screen.findByText(t("validation.panelUrlHttp"))).toBeInTheDocument();
    await user.clear(await urlField());
    await user.type(await urlField(), "https://panel.example.com/admin");
    expect(await screen.findByText(t("validation.panelUrlPath"))).toBeInTheDocument();
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
    expect(window.localStorage.getItem(PANEL_URL_KEY)).toBeNull();
  });

  it("says how the panel reaches a node in hidden management", async () => {
    const { user } = open({ nodes: [{ id: "node-a", mgmtMode: "hidden", mgmtSni: "m.example.com", mgmtPublicPort: 443 }] });

    await user.clear(await urlField());
    await user.type(await urlField(), "https://panel.example.com");
    await user.click(await getButton());

    expect(await screen.findByText(t("nodes.docker.firewallHidden"))).toBeInTheDocument();
  });

  it("shows why the panel refused", async () => {
    const { panel, user } = open();
    panel.rpc.createJoinToken.mockImplementation(() => {
      throw new ConnectError("no node image: set POSTERN_NODE_IMAGE", Code.FailedPrecondition);
    });

    await user.click(await getButton());

    expect(await screen.findByText("no node image: set POSTERN_NODE_IMAGE")).toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it.each([
    ["an address it refuses", new ConnectError("panel_url: it must be https://host[:port]", Code.InvalidArgument)],
    ["no answer", new ConnectError("the panel did not answer", Code.Unavailable)],
  ])("shows %s", async (_what, error) => {
    const { panel, user } = open();
    panel.rpc.createJoinToken.mockImplementation(() => {
      throw error;
    });

    await user.click(await getButton());

    expect(await screen.findByText(error.rawMessage)).toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("takes the command off the screen when the address changes", async () => {
    const { user } = open();

    await user.clear(await urlField());
    await user.type(await urlField(), "https://panel.example.com");
    await user.click(await getButton());
    expect(await screen.findByRole("tab", { name: "docker run" })).toBeInTheDocument();

    await user.type(await urlField(), ":8443");

    expect(screen.queryByRole("tab", { name: "docker run" })).not.toBeInTheDocument();
    expect(screen.queryByText(t("nodes.docker.firewall", { port: 61234 }))).not.toBeInTheDocument();
  });

  it("has no command when the panel has no node image, and says the other ways still work", async () => {
    const { panel } = open({ nodeImage: "" });

    expect(await screen.findByText(t("nodes.docker.noImage"))).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("nodes.docker.get") })).not.toBeInTheDocument();
    await waitFor(() => {
      expect(panel.rpc.getNodeInstall).toHaveBeenCalled();
    });
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
  });
});
