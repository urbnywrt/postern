import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel, type FakePanelOptions } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { StatsSettingsForm } from "./StatsSettingsForm";

const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const save = () => screen.getByRole("button", { name: t("insights.settings.stats.save") });
const policy = (name: "full" | "countries" | "off") =>
  screen.getByRole("radio", { name: t(`insights.settings.stats.policy.${name}`) });

async function open(options: Omit<FakePanelOptions, "signedIn"> = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [{ id: "node-a", name: "Frankfurt" }], ...options });
  renderWithProviders(<StatsSettingsForm />, { transport: panel.transport });
  await screen.findByLabelText(t("insights.settings.stats.minutesHours"), FIELD);
  return { panel, user: userEvent.setup() };
}

function sent(panel: Awaited<ReturnType<typeof open>>["panel"]) {
  return panel.rpc.updateStatsSettings.mock.calls[0]?.[0].settings;
}

describe("StatsSettingsForm: the values", () => {
  it("starts from what is stored, with the privacy text of the IP policy", async () => {
    await open();

    expect(field("insights.settings.stats.minutesHours")).toHaveValue("48");
    expect(field("insights.settings.stats.hoursDays")).toHaveValue("90");
    expect(field("insights.settings.stats.ipDays")).toHaveValue("7");
    expect(field("insights.settings.stats.probeInterval")).toHaveValue("5");
    expect(policy("countries")).toBeChecked();
    expect(screen.getByText(t("insights.settings.stats.privacy"))).toBeInTheDocument();
    expect(screen.getByText(t("insights.settings.stats.probeIntervalHint"))).toBeInTheDocument();
  });

  it("saves every setting, the extra probe sources one per line", async () => {
    const { panel, user } = await open();

    await user.clear(field("insights.settings.stats.minutesHours"));
    await user.type(field("insights.settings.stats.minutesHours"), "72");
    await user.type(field("insights.settings.stats.extraSources"), "192.0.2.10\n2001:db8::7");
    await user.click(save());

    expect(await screen.findByText(t("insights.settings.stats.saved"))).toBeInTheDocument();
    expect(sent(panel)).toMatchObject({
      minutesHours: 72,
      hoursDays: 90,
      ipDays: 7,
      probeIntervalMinutes: 5,
      ipPolicy: "countries",
      extraProbeSources: ["192.0.2.10", "2001:db8::7"],
    });
  });

  it("refuses a value out of its range and a prefix as a source, before it calls the panel", async () => {
    const { panel, user } = await open();

    await user.clear(field("insights.settings.stats.ipDays"));
    await user.type(field("insights.settings.stats.ipDays"), "31");
    await user.clear(field("insights.settings.stats.probeInterval"));
    await user.type(field("insights.settings.stats.probeInterval"), "61");
    await user.type(field("insights.settings.stats.extraSources"), "192.0.2.0/24");
    await user.click(save());

    expect(await screen.findByText(t("insights.settings.stats.range", { min: 1, max: 30 }))).toBeInTheDocument();
    expect(screen.getByText(t("insights.settings.stats.range", { min: 0, max: 60 }))).toBeInTheDocument();
    expect(screen.getByText(t("insights.settings.stats.extraSourceInvalid", { value: "192.0.2.0/24" }))).toBeInTheDocument();
    expect(panel.rpc.updateStatsSettings).not.toHaveBeenCalled();
  });

  it("shows the refusal of the panel as a refusal, and another failure as such", async () => {
    const { panel, user } = await open();
    panel.rpc.updateStatsSettings.mockImplementationOnce(() => {
      throw new ConnectError("hours_days is out of range", Code.InvalidArgument);
    });
    await user.click(save());
    const refused = await screen.findByRole("alert");
    expect(refused).toHaveTextContent(t("insights.settings.stats.refused"));
    expect(refused).toHaveTextContent("hours_days is out of range");

    panel.rpc.updateStatsSettings.mockImplementationOnce(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });
    await user.click(save());
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(t("insights.settings.stats.saveFailed"));
    });
  });
});

describe("StatsSettingsForm: the IP policy", () => {
  it("asks before leaving full, because the IP history is deleted, and saves nothing when cancelled", async () => {
    const { panel, user } = await open({ ipPolicy: "full" });

    await user.click(policy("countries"));
    await user.click(save());

    const dialog = await screen.findByRole("dialog", { name: t("insights.settings.stats.confirm.title") });
    expect(within(dialog).getByText(t("insights.settings.stats.confirm.ipHistory"))).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(panel.rpc.updateStatsSettings).not.toHaveBeenCalled();

    await user.click(save());
    const again = await screen.findByRole("dialog", { name: t("insights.settings.stats.confirm.title") });
    await user.click(within(again).getByRole("button", { name: t("insights.settings.stats.confirm.confirm") }));
    await waitFor(() => {
      expect(panel.rpc.updateStatsSettings).toHaveBeenCalledTimes(1);
    });
    expect(sent(panel)?.ipPolicy).toBe("countries");
  });

  it("asks before choosing off, because the country history is deleted", async () => {
    const { user } = await open({ ipPolicy: "countries" });

    await user.click(policy("off"));
    await user.click(save());

    const dialog = await screen.findByRole("dialog", { name: t("insights.settings.stats.confirm.title") });
    expect(
      within(dialog).getByText(t("insights.settings.stats.confirm.countryHistory")),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(t("insights.settings.stats.confirm.ipHistory"))).not.toBeInTheDocument();
  });

  it("names both deletions when full becomes off", async () => {
    const { user } = await open({ ipPolicy: "full" });

    await user.click(policy("off"));
    await user.click(save());

    const dialog = await screen.findByRole("dialog", { name: t("insights.settings.stats.confirm.title") });
    expect(
      within(dialog).getByText(
        `${t("insights.settings.stats.confirm.ipHistory")} ${t("insights.settings.stats.confirm.countryHistory")}`,
      ),
    ).toBeInTheDocument();
  });

  it("asks nothing when the policy keeps more than before", async () => {
    const { panel, user } = await open({ ipPolicy: "countries" });

    await user.click(policy("full"));
    await user.click(save());

    await waitFor(() => {
      expect(panel.rpc.updateStatsSettings).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("StatsSettingsForm: the panel's addresses", () => {
  it("lists them by node, and warns on each shared one", async () => {
    await open({
      panelAddresses: [
        { nodeId: "node-a", addr: "198.51.100.4", shared: false },
        { nodeId: "node-a", addr: "100.64.0.9", shared: true },
      ],
    });

    const rowWith = (text: string) => {
      const found = screen.getAllByRole("row").find((row) => within(row).queryByText(text) !== null);
      if (found === undefined) throw new Error(`no row with ${text}`);
      return within(found);
    };
    expect(rowWith("100.64.0.9").getByText(t("insights.settings.stats.shared"))).toBeInTheDocument();
    expect(await rowWith("100.64.0.9").findByText("Frankfurt")).toBeInTheDocument();
    expect(rowWith("198.51.100.4").queryByText(t("insights.settings.stats.shared"))).not.toBeInTheDocument();
  });

  it("says when no node has seen the panel yet", async () => {
    await open();
    expect(screen.getByText(t("insights.settings.stats.noPanelAddresses"))).toBeInTheDocument();
  });
});
