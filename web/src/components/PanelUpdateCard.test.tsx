import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { type UploadBundle, type UploadResult, usePanelVersion } from "../api/hooks/versions";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { PanelDetails, PanelUpdateAction } from "./PanelUpdateCard";

const REFUSED: UploadResult = {
  version: "v0.6.0",
  accepted: false,
  assets: [
    { name: "postern-node-linux-amd64", ok: true, sha256: "b".repeat(64) },
    { name: "postern-panel-linux-amd64", ok: false, reason: "release: the signature does not verify" },
  ],
  ignored: ["README.md"],
};

function show(options: Parameters<typeof createFakePanel>[0] = {}, upload: UploadBundle = vi.fn()) {
  const panel = createFakePanel({ signedIn: true, ...options });
  renderWithProviders(<PanelCard upload={upload} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

/** The details, and the update as the top of the page of versions shows it. */
function PanelCard({ upload }: { upload: UploadBundle }) {
  const panel = usePanelVersion();
  return (
    <>
      <PanelDetails upload={upload} />
      {panel.data !== undefined ? <PanelUpdateAction info={panel.data} /> : null}
    </>
  );
}

describe("PanelDetails and PanelUpdateAction", () => {
  it("updates the panel after a confirmation that names the version", async () => {
    const { panel, user } = show({
      panelVersion: { version: "v0.5.0", canUpdate: true, cannotUpdateReason: "", releases: [{ component: "postern", version: "v0.6.0" }], lastUpdate: "v0.5.0 did not start and was rolled back to v0.4.2" },
    });
    expect(await screen.findByText("v0.5.0 did not start and was rolled back to v0.4.2")).toBeInTheDocument();
    expect(screen.getByText(t("versions.panel.kitSigned"))).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: t("versions.updates.updatePanel") }));
    const dialog = await screen.findByRole("dialog", { name: t("versions.panel.confirmTitle", { version: "v0.6.0" }) });
    expect(panel.rpc.updatePanel).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("versions.panel.update", { version: "v0.6.0" }) }));
    await waitFor(() => {
      expect(panel.rpc.updatePanel).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updatePanel.mock.calls[0]?.[0]).toMatchObject({ version: "v0.6.0" });
    expect(await screen.findByText(t("versions.panel.restarting", { version: "v0.6.0" }))).toBeInTheDocument();
  });

  it("says why it cannot update in place of the button, and warns when test keys are trusted", async () => {
    show({
      panelVersion: { canUpdate: false, cannotUpdateReason: "these nodes run an agent older than v0.5.0: Helsinki; update them first", trustsTestKeys: true, releases: [{ component: "postern", version: "v0.6.0" }] },
    });
    // In the details, and in place of the button.
    expect(await screen.findAllByText("these nodes run an agent older than v0.5.0: Helsinki; update them first")).toHaveLength(2);
    expect(screen.getByText(t("versions.panel.testKeysTitle"))).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("versions.updates.updatePanel") })).not.toBeInTheDocument();
  });

  it("uploads a bundle with progress and shows each asset's result", async () => {
    let finish: (result: UploadResult) => void = () => undefined;
    const upload = vi.fn<UploadBundle>((_file, onProgress) => {
      onProgress(0.4);
      return new Promise((resolve) => {
        finish = resolve;
      });
    });
    const { user } = show({}, upload);
    const file = new File(["tar"], "postern-v0.6.0-bundle.tar", { type: "application/x-tar" });
    // Mantine's FileInput is a button with a hidden file input beside it.
    const input = document.querySelector<HTMLInputElement>("input[type=file]");
    if (input === null) throw new Error("no file input");
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: t("versions.upload.send") }));
    expect(await screen.findByRole("progressbar", { name: t("versions.upload.progress") })).toHaveAttribute("aria-valuenow", "40");
    finish(REFUSED);

    const table = await screen.findByRole("table", { name: t("versions.upload.assets") });
    expect(within(table).getByText("postern-node-linux-amd64")).toBeInTheDocument();
    expect(within(table).getByText("b".repeat(64))).toBeInTheDocument();
    expect(within(table).getByText("release: the signature does not verify")).toBeInTheDocument();
    expect(screen.getByText(t("versions.upload.refused"))).toBeInTheDocument();
    expect(screen.getByText(t("versions.upload.ignored", { names: "README.md" }))).toBeInTheDocument();
    expect(upload.mock.calls[0]?.[0].name).toBe("postern-v0.6.0-bundle.tar");
  });
});
