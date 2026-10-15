import { getDefaultNormalizer, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { INSTALL_COMMAND, PANEL_VERSION } from "../test/fakeInventory";
import { createFakePanel, type FakePanelOptions } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { NodeInstallSteps } from "./NodeInstallSteps";

/** The install command of the fake panel with the architecture filled in. */
const commandFor = (arch: string) => INSTALL_COMMAND.replace("<ARCH>", arch);
/** The same without the kit: nothing to unpack. */
const commandWithoutKit = "sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node";
/** The command line that copies the files to the server: the directory first, then the files. */
const mkdir = "ssh root@<SERVER> mkdir -p /root/postern && ";
const scpFor = (arch: string) =>
  `${mkdir}scp postern-node-kit-linux-${arch}.tar postern-node-bundle.tar root@<SERVER>:/root/postern/`;
const scpWithoutKit = `${mkdir}scp postern-node-bundle.tar root@<SERVER>:/root/postern/`;
/** Finds a command as it is shown, line breaks and all. */
const command = (text: string) =>
  screen.queryByText(text, { normalizer: getDefaultNormalizer({ collapseWhitespace: false }) });
const kitLink = (arch: string) => screen.queryByRole("link", { name: t("nodes.install.downloadKit", { arch }) });

function panelWith(options: FakePanelOptions = {}) {
  return createFakePanel({ signedIn: true, nodes: [{ id: "node-a", name: "Frankfurt" }], ...options });
}

function renderSteps(panel = panelWith()) {
  renderWithProviders(<NodeInstallSteps nodeId="node-a" />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

describe("NodeInstallSteps", () => {
  it("offers the bundle, the kit of amd64, and the commands for amd64", async () => {
    const { panel } = renderSteps();

    const bundle = await screen.findByRole("link", { name: t("nodes.install.downloadBundle") });
    expect(bundle).toHaveAttribute("href", "/api/nodes/node-a/bundle.tar");
    expect(bundle).toHaveAttribute("download", "postern-node-bundle.tar");
    // The bundle holds the private key of the node, and the steps say so.
    expect(screen.getByText(t("nodes.install.secret"))).toBeInTheDocument();

    expect(screen.getByRole("radio", { name: "amd64" })).toBeChecked();
    expect(kitLink("amd64")).toHaveAttribute("href", "/api/node-kit/amd64");
    expect(kitLink("amd64")).toHaveAttribute("download", "postern-node-kit-linux-amd64.tar");
    // A fresh server has no /root/postern: the copy makes it first.
    expect(screen.getByText(t("nodes.install.copyStep"))).toBeInTheDocument();
    expect(command(scpFor("amd64"))).toBeInTheDocument();
    expect(command(commandFor("amd64"))).toBeInTheDocument();

    expect(panel.rpc.getNodeInstall).toHaveBeenCalledTimes(1);
    expect(panel.rpc.getNodeInstall.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a" });
  });

  it("changes the kit and the commands to the architecture that is picked", async () => {
    const { user } = renderSteps();

    await user.click(await screen.findByRole("radio", { name: "arm64" }));

    expect(screen.getByRole("radio", { name: "arm64" })).toBeChecked();
    expect(kitLink("amd64")).not.toBeInTheDocument();
    expect(kitLink("arm64")).toHaveAttribute("href", "/api/node-kit/arm64");
    expect(kitLink("arm64")).toHaveAttribute("download", "postern-node-kit-linux-arm64.tar");
    expect(command(scpFor("arm64"))).toBeInTheDocument();
    expect(command(commandFor("arm64"))).toBeInTheDocument();
    expect(command(commandFor("amd64"))).not.toBeInTheDocument();

    // And back.
    await user.click(screen.getByRole("radio", { name: "amd64" }));
    expect(kitLink("amd64")).toHaveAttribute("href", "/api/node-kit/amd64");
    expect(command(commandFor("amd64"))).toBeInTheDocument();
  });

  it("copies the commands with the architecture filled in", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const { user } = renderSteps();

    await user.click(await screen.findByRole("radio", { name: "arm64" }));
    await user.click(screen.getByRole("button", { name: t("nodes.install.copyCommand") }));
    expect(await navigator.clipboard.readText()).toBe(commandFor("arm64"));
    await user.click(screen.getByRole("button", { name: t("nodes.install.copyScp") }));
    expect(await navigator.clipboard.readText()).toBe(scpFor("arm64"));
    Reflect.deleteProperty(window, "isSecureContext");
  });

  it("without the kit of the architecture: copies the bundle alone and unpacks no kit, and says where the files come from", async () => {
    const { user } = renderSteps(panelWith({ kits: ["amd64"] }));
    expect(await screen.findByRole("link", { name: t("nodes.install.downloadKit", { arch: "amd64" }) })).toBeInTheDocument();
    expect(screen.queryByText(t("nodes.install.noKit", { arch: "amd64", version: PANEL_VERSION }))).not.toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: "arm64" }));

    const note = screen.getByText(t("nodes.install.noKit", { arch: "arm64", version: PANEL_VERSION }));
    // The note names the files to put next to the binary, and where they come from.
    for (const part of ["install.sh", "launcher.sh", "compose.yaml", "deploy/node/", PANEL_VERSION]) {
      expect(note).toHaveTextContent(part);
    }
    expect(kitLink("arm64")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("nodes.install.downloadBundle") })).toBeInTheDocument();
    expect(screen.getByText(t("nodes.install.copyStepNoKit"))).toBeInTheDocument();
    expect(command(scpWithoutKit)).toBeInTheDocument();
    expect(command(commandWithoutKit)).toBeInTheDocument();
    expect(command(scpFor("arm64"))).not.toBeInTheDocument();
    expect(command(commandFor("arm64"))).not.toBeInTheDocument();

    // The kit of amd64 is there: its commands are back.
    await user.click(screen.getByRole("radio", { name: "amd64" }));
    expect(command(scpFor("amd64"))).toBeInTheDocument();
    expect(command(commandFor("amd64"))).toBeInTheDocument();
  });

  it("copies the commands without the kit as they are shown", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const { user } = renderSteps(panelWith({ kits: [] }));

    await user.click(await screen.findByRole("button", { name: t("nodes.install.copyCommand") }));
    expect(await navigator.clipboard.readText()).toBe(commandWithoutKit);
    await user.click(screen.getByRole("button", { name: t("nodes.install.copyScp") }));
    expect(await navigator.clipboard.readText()).toBe(scpWithoutKit);
    Reflect.deleteProperty(window, "isSecureContext");
  });

  it("says so for amd64 at once when the panel has no kit at all", async () => {
    renderSteps(panelWith({ kits: [] }));

    expect(await screen.findByText(t("nodes.install.noKit", { arch: "amd64", version: PANEL_VERSION }))).toBeInTheDocument();
    expect(kitLink("amd64")).not.toBeInTheDocument();
    expect(command(scpWithoutKit)).toBeInTheDocument();
    expect(command(commandWithoutKit)).toBeInTheDocument();
  });

  it("shows the command as the panel words it, and links to paths of the API only", async () => {
    const panel = panelWith();
    panel.rpc.getNodeInstall.mockImplementation(() => ({
      bundleUrl: "https://elsewhere.example.com/bundle.tar",
      kits: [
        { arch: "amd64", url: "//elsewhere.example.com/kit.tar", available: true, version: "9.9.9" },
        { arch: "arm64", url: "/api/node-kit/arm64", available: true, version: "9.9.9" },
      ],
      installCommand: "sudo install-from-the-panel <ARCH> --again <ARCH>",
    }));
    renderSteps(panel);

    expect(await screen.findByText("sudo install-from-the-panel amd64 --again amd64")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("nodes.install.downloadBundle") })).toHaveAttribute(
      "href",
      "/api/nodes/node-a/bundle.tar",
    );
    expect(kitLink("amd64")).toHaveAttribute("href", "/api/node-kit/amd64");
  });

  it("shows the error of the panel, with a way to try again", async () => {
    const panel = panelWith({ nodes: [] });
    renderSteps(panel);

    expect(await screen.findByText("no such node")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("common.retry") })).toBeInTheDocument();
  });
});
