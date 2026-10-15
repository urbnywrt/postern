import { create } from "@bufbuild/protobuf";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { ReleaseSchema } from "../gen/postern/panel/v1/versions_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { ReleaseList } from "./ReleaseList";

const EVIL = "Fixes:\n<img src=x onerror=alert(1)>\n<script>alert(2)</script>";
const RELEASE = {
  component: "telemt",
  version: "3.5.14",
  prerelease: true,
  notes: EVIL,
  url: "javascript:alert(3)",
  assets: [
    { arch: "amd64", file: "telemt-x86_64-linux-musl.tar.gz", state: "ready", shaSource: "sums", sha256: "a".repeat(64) },
    { arch: "arm64", file: "telemt-aarch64-linux-musl.tar.gz", state: "unusable", reason: "the trial run exited 139" },
  ],
};

function show() {
  const panel = createFakePanel({ signedIn: true, releases: [RELEASE] });
  const view = renderWithProviders(<ReleaseList component="telemt" releases={[create(ReleaseSchema, RELEASE)]} />, { transport: panel.transport });
  return { panel, view, user: userEvent.setup() };
}

describe("ReleaseList", () => {
  it("renders release notes as text, never as markup", () => {
    const { view } = show();
    const notes = screen.getByTestId("release-notes");
    expect(notes.textContent).toBe(EVIL);
    expect(notes).toHaveStyle({ whiteSpace: "pre-wrap" });
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("script")).toBeNull();
    // A link that is not of the web is not made a link.
    expect(screen.queryByRole("link", { name: "3.5.14" })).not.toBeInTheDocument();
  });

  it("shows the prerelease badge, each arch's state with its reason, and the checksum source", () => {
    show();
    expect(screen.getByText(t("versions.releases.prerelease"))).toBeInTheDocument();
    expect(screen.getByText(t("versions.assetState.unusable"))).toBeInTheDocument();
    expect(screen.getByText("the trial run exited 139")).toBeInTheDocument();
    expect(screen.getByText(t("versions.shaSource.sums"))).toBeInTheDocument();
  });

  it("rechecks an unusable asset", async () => {
    const { panel, user } = show();
    await user.click(screen.getByRole("button", { name: t("versions.releases.recheckOf", { version: "3.5.14", arch: "arm64" }) }));
    await waitFor(() => {
      expect(panel.rpc.recheckRelease).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.recheckRelease.mock.calls[0]?.[0]).toMatchObject({ component: "telemt", version: "3.5.14", arch: "arm64" });
  });
});
