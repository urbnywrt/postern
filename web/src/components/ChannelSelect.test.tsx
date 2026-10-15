import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { ChannelSelect, type ChannelAnswer } from "./ChannelSelect";

const OPTIONS = [
  { value: "stable", label: "Stable" },
  { value: "latest", label: "Latest" },
];

describe("ChannelSelect", () => {
  it("does not ask again when the first answer says the change was applied", async () => {
    const ask = vi.fn<(channel: string, confirm: boolean) => Promise<ChannelAnswer>>(() => Promise.resolve({ affectedProxies: [], applied: true }));
    renderWithProviders(<ChannelSelect label="Channel" value="stable" options={OPTIONS} ask={ask} />);
    const user = userEvent.setup();
    await user.click(screen.getByLabelText("Channel", { selector: "input" }));
    await user.click(await screen.findByRole("option", { name: "Latest" }));
    expect(await screen.findByText(t("versions.channel.changed"))).toBeInTheDocument();
    await waitFor(() => {
      expect(ask).toHaveBeenCalledTimes(1);
    });
    expect(ask).toHaveBeenCalledWith("latest", false);
  });
});
