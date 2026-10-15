import { create } from "@bufbuild/protobuf";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { UploadGeoIP } from "../api/hooks/geoip";
import { GeoIPStatusSchema } from "../gen/postern/panel/v1/geoip_pb";
import { ATTRIBUTION, ATTRIBUTION_URL, LICENCE } from "../test/fakeInsights";
import { createFakePanel, type FakePanelOptions } from "../test/fakePanel";
import { renderApp, renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { GeoIPSettings } from "./GeoIPSettings";
import { StorageInfo } from "./StorageInfo";

function show(options: Omit<FakePanelOptions, "signedIn"> = {}, upload: UploadGeoIP = vi.fn<UploadGeoIP>()) {
  const panel = createFakePanel({ signedIn: true, ...options });
  renderWithProviders(<GeoIPSettings upload={upload} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const fileInput = () => {
  // Mantine's FileInput is a button with a hidden file input beside it.
  const input = document.querySelector<HTMLInputElement>("input[type=file]");
  if (input === null) throw new Error("no file input");
  return input;
};

describe("GeoIPSettings", () => {
  it("shows the database the panel has, with the attribution and the licence of DB-IP", async () => {
    show();

    expect(await screen.findByText("2026-10")).toBeInTheDocument();
    expect(screen.getByText("8 MB")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: ATTRIBUTION })).toHaveAttribute("href", ATTRIBUTION_URL);
    expect(screen.getByText(t("insights.settings.geoip.licence", { licence: LICENCE }))).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: (name) => name.startsWith(t("insights.settings.geoip.enabled")) })).toBeChecked();
  });

  it("says why the last look failed, and that there is no database", async () => {
    show({ geoip: { present: false, month: "", error: "download.db-ip.com did not answer" } });

    expect(await screen.findByText(t("insights.settings.geoip.none"))).toBeInTheDocument();
    expect(
      screen.getByText(t("insights.settings.geoip.error", { error: "download.db-ip.com did not answer" })),
    ).toBeInTheDocument();
  });

  it("looks for a newer database, and turns lookups off", async () => {
    const { panel, user } = show();
    await screen.findByText("2026-10");

    await user.click(screen.getByRole("button", { name: t("insights.settings.geoip.refresh") }));
    await waitFor(() => {
      expect(panel.rpc.refreshGeoIP).toHaveBeenCalledTimes(1);
    });

    await user.click(screen.getByRole("switch", { name: (name) => name.startsWith(t("insights.settings.geoip.enabled")) }));
    await waitFor(() => {
      expect(panel.rpc.setGeoIPEnabled.mock.calls[0]?.[0]).toMatchObject({ enabled: false });
    });
    expect(screen.getByRole("button", { name: t("insights.settings.geoip.refresh") })).toBeDisabled();
  });

  it("uploads a file and shows the database that the panel then has", async () => {
    const upload = vi.fn<UploadGeoIP>(() =>
      Promise.resolve(
        create(GeoIPStatusSchema, {
          enabled: true,
          present: true,
          month: "2026-09",
          size: 7_900_000n,
          sha256: "cd".repeat(32),
          attribution: ATTRIBUTION,
          attributionUrl: ATTRIBUTION_URL,
          licence: LICENCE,
        }),
      ),
    );
    const { user } = show({}, upload);
    await screen.findByText("2026-10");
    const send = screen.getByRole("button", { name: t("insights.settings.geoip.uploadButton") });
    expect(send).toBeDisabled();

    const file = new File(["mmdb"], "dbip-country-lite-2026-09.mmdb.gz", { type: "application/gzip" });
    await user.upload(fileInput(), file);
    await user.click(send);

    expect(await screen.findByText(t("insights.settings.geoip.uploaded"))).toBeInTheDocument();
    expect(upload).toHaveBeenCalledWith(file);
    expect(await screen.findByText("2026-09")).toBeInTheDocument();
  });

  it("says why an upload failed, and keeps the database that the panel had", async () => {
    const upload = vi.fn<UploadGeoIP>(() => Promise.reject(new Error("the file is not a country database")));
    const { user } = show({}, upload);
    await screen.findByText("2026-10");

    await user.upload(fileInput(), new File(["junk"], "junk.mmdb", { type: "application/octet-stream" }));
    await user.click(screen.getByRole("button", { name: t("insights.settings.geoip.uploadButton") }));

    expect(
      await screen.findByText(t("insights.settings.geoip.uploadFailed", { reason: "the file is not a country database" })),
    ).toBeInTheDocument();
    expect(screen.getByText("2026-10")).toBeInTheDocument();
  });
});

describe("StorageInfo", () => {
  it("shows the size of the database and the rows of each table", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderWithProviders(<StorageInfo />, { transport: panel.transport });

    expect(await screen.findByText("30 MB")).toBeInTheDocument();
    expect(screen.getByText("1 MB")).toBeInTheDocument();
    const row = screen.getByRole("row", { name: /stats_proxy_1m/ });
    expect(within(row).getByText("2,880")).toBeInTheDocument();
  });
});

describe("AboutDialog", () => {
  it("opens from the shell with the version, AGPL-3.0, and the DB-IP attribution and licence", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/", transport: panel.transport });
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: t("insights.about.open") }));

    const dialog = within(await screen.findByRole("dialog", { name: t("insights.about.title") }));
    expect(await dialog.findByText("v0.5.0")).toBeInTheDocument();
    expect(dialog.getByRole("link", { name: "AGPL-3.0" })).toHaveAttribute(
      "href",
      "https://www.gnu.org/licenses/agpl-3.0.html",
    );
    expect(await dialog.findByRole("link", { name: ATTRIBUTION })).toHaveAttribute("href", ATTRIBUTION_URL);
    expect(dialog.getByText(t("insights.about.geoipText", { licence: LICENCE }))).toBeInTheDocument();
  });
});
