import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { INSTALL_COMMAND } from "../test/fakeInventory";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { NodeCreateDialog } from "./NodeCreateDialog";

// A Select or a Modal can repeat a label, so a field is asked for by its input.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const createButton = () => screen.getByRole("button", { name: t("nodes.form.create") });

function openDialog(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, ...options });
  const onClose = vi.fn<() => void>();
  renderWithProviders(<NodeCreateDialog opened onClose={onClose} />, { transport: panel.transport });
  return { panel, onClose, user: userEvent.setup() };
}

async function fillAndCreate(user: ReturnType<typeof userEvent.setup>) {
  await user.type(field("nodes.form.name"), "Frankfurt");
  await user.type(field("nodes.form.mgmtHost"), "203.0.113.7");
  await user.click(createButton());
}

describe("NodeCreateDialog", () => {
  it("shows the install steps of the new node once it is created", async () => {
    const { panel, user } = openDialog();

    await fillAndCreate(user);

    // The bundle is a download from the panel, with the path that the panel gave.
    const created = panel.inventory.nodes[0];
    expect(created?.name).toBe("Frankfurt");
    const dialog = await screen.findByRole("dialog", { name: t("nodes.created.title") });
    await user.click(within(dialog).getByRole("button", { name: t("nodes.install.manualBlock") }));
    const download = await within(dialog).findByRole("link", { name: t("nodes.install.downloadBundle") });
    expect(download).toHaveAttribute("href", `/api/nodes/${created?.id ?? "?"}/bundle.tar`);
    expect(download).toHaveAttribute("download", "postern-node-bundle.tar");
    expect(panel.rpc.getNodeInstall.mock.calls[0]?.[0]).toMatchObject({ nodeId: created?.id });
    // The node kit of amd64, unless the admin picks another.
    expect(within(dialog).getByRole("link", { name: t("nodes.install.downloadKit", { arch: "amd64" }) })).toHaveAttribute(
      "href",
      "/api/node-kit/amd64",
    );
    // The command as the panel worded it, for amd64, and a way to copy it.
    expect(within(dialog).getByText(INSTALL_COMMAND.replace("<ARCH>", "amd64"))).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: t("nodes.install.copyCommand") })).toBeInTheDocument();
    // The bundle holds the private key of the node, and the dialog says so.
    expect(within(dialog).getByText(t("nodes.install.secret"))).toBeInTheDocument();
    // The form is gone.
    expect(screen.queryByLabelText(t("nodes.form.name"), FIELD)).not.toBeInTheDocument();
  });

  it("copies the install command", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const { user } = openDialog();

    await fillAndCreate(user);
    await user.click(await screen.findByRole("button", { name: t("nodes.install.manualBlock") }));
    await user.click(await screen.findByRole("button", { name: t("nodes.install.copyCommand") }));

    expect(await navigator.clipboard.readText()).toBe(INSTALL_COMMAND.replace("<ARCH>", "amd64"));
    Reflect.deleteProperty(window, "isSecureContext");
  });

  it("offers the one Docker command first, then SSH, then the kit and the bundle folded away", async () => {
    const { panel, user, onClose } = openDialog();

    await fillAndCreate(user);

    const dialog = await screen.findByRole("dialog", { name: t("nodes.created.title") });
    const get = await within(dialog).findByRole("button", { name: t("nodes.docker.get") });
    const ssh = within(dialog).getByRole("link", { name: t("deploy.open") });
    const folded = within(dialog).getByRole("button", { name: t("nodes.install.manualBlock") });
    expect(within(dialog).getByRole("heading", { name: t("nodes.docker.title") })).toBeInTheDocument();
    expect(get.compareDocumentPosition(ssh) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(ssh.compareDocumentPosition(folded) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(ssh).toHaveAttribute("href", `/nodes/${panel.inventory.nodes[0]?.id ?? "?"}/install`);
    expect(folded).toHaveAttribute("aria-expanded", "false");
    // A command is a join token: none is made until the admin asks.
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();

    // The SSH install is a page of its own: the dialog closes on the way.
    await user.click(ssh);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("says that the panel has no node image, and keeps the other ways", async () => {
    const { panel, user } = openDialog({ nodeImage: "" });

    await fillAndCreate(user);

    const dialog = await screen.findByRole("dialog", { name: t("nodes.created.title") });
    expect(await within(dialog).findByText(t("nodes.docker.noImage"))).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: t("nodes.docker.get") })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: t("deploy.open") })).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: t("nodes.install.manualBlock") })).toBeInTheDocument();
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
  });

  it("creates a node without a management host, which the join fills in", async () => {
    const { panel, user } = openDialog();

    expect(field("nodes.form.mgmtHost")).toHaveAccessibleDescription(
      `${t("nodes.form.mgmtHostHint")} ${t("nodes.form.mgmtHostHintCreate")}`,
    );
    await user.type(field("nodes.form.name"), "Frankfurt");
    await user.click(createButton());

    await screen.findByRole("dialog", { name: t("nodes.created.title") });
    expect(panel.rpc.createNode.mock.calls[0]?.[0]).toMatchObject({ name: "Frankfurt", mgmtHost: "", linkHost: "" });
  });

  it("sends what was typed, trimmed, with port 0 and no link host when those are left empty", async () => {
    const { panel, user } = openDialog();

    await user.type(field("nodes.form.name"), "  Frankfurt  ");
    await user.type(field("nodes.form.mgmtHost"), " 203.0.113.7 ");
    await user.click(createButton());

    await screen.findByRole("dialog", { name: t("nodes.created.title") });
    expect(panel.rpc.createNode).toHaveBeenCalledTimes(1);
    expect(panel.rpc.createNode.mock.calls[0]?.[0]).toMatchObject({
      name: "Frankfurt",
      mgmtHost: "203.0.113.7",
      mgmtPort: 0,
      linkHost: "",
    });
  });

  it("sends the port and the link host when they are given", async () => {
    const { panel, user } = openDialog();

    await user.type(field("nodes.form.name"), "Frankfurt");
    await user.type(field("nodes.form.mgmtHost"), "node.example.com");
    await user.type(field("nodes.form.mgmtPort"), "8443");
    await user.type(field("nodes.form.linkHost"), "links.example.com");
    await user.click(createButton());

    await screen.findByRole("dialog", { name: t("nodes.created.title") });
    expect(panel.rpc.createNode.mock.calls[0]?.[0]).toMatchObject({
      mgmtHost: "node.example.com",
      mgmtPort: 8443,
      linkHost: "links.example.com",
    });
  });

  it("points out what is wrong before it calls the panel", async () => {
    const { panel, user } = openDialog();

    await user.type(field("nodes.form.mgmtHost"), "http://node.example.com");
    await user.type(field("nodes.form.mgmtPort"), "70000");
    await user.type(field("nodes.form.linkHost"), "bad host");
    await user.click(createButton());

    expect(await screen.findByText(t("validation.required"))).toBeInTheDocument(); // the name
    expect(screen.getAllByText(t("validation.host"))).toHaveLength(2); // the two hosts
    expect(screen.getByText(t("validation.port"))).toBeInTheDocument();
    expect(panel.rpc.createNode).not.toHaveBeenCalled();
  });

  it("refuses a name that is too long", async () => {
    const { panel, user } = openDialog();

    await user.type(field("nodes.form.name"), "n".repeat(65));
    await user.type(field("nodes.form.mgmtHost"), "203.0.113.7");
    await user.click(createButton());

    expect(await screen.findByText(t("validation.textLong", { max: 64 }))).toBeInTheDocument();
    expect(panel.rpc.createNode).not.toHaveBeenCalled();
  });

  it("shows the message of the panel when it refuses, and keeps the form", async () => {
    const { panel, user, onClose } = openDialog();
    panel.rpc.createNode.mockImplementation(() => {
      throw new ConnectError("mgmt_host must be an IP address or a host name", Code.InvalidArgument);
    });

    await fillAndCreate(user);

    expect(await screen.findByText("mgmt_host must be an IP address or a host name")).toBeInTheDocument();
    expect(field("nodes.form.name")).toHaveValue("Frankfurt");
    expect(onClose).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(createButton()).toBeEnabled();
    });
  });

  it("closes from the cancel button", async () => {
    const first = openDialog();
    await first.user.click(screen.getByRole("button", { name: t("common.cancel") }));
    expect(first.onClose).toHaveBeenCalledTimes(1);
  });

  it("closes from the done button once the node is created", async () => {
    const { user, onClose } = openDialog();

    await fillAndCreate(user);
    await user.click(await screen.findByRole("button", { name: t("common.done") }));

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("asks nothing of the panel while it is closed", () => {
    const panel = createFakePanel({ signedIn: true });
    renderWithProviders(<NodeCreateDialog opened={false} onClose={vi.fn()} />, { transport: panel.transport });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(panel.rpc.createNode).not.toHaveBeenCalled();
  });
});
