import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { authKeys } from "../api/hooks/auth";
import { ADMIN, createFakePanel, NEW_PASSWORD, PASSWORD } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const heading = (name: string) => screen.findByRole("heading", { name });

describe("the route guard", () => {
  it("sends a visitor to the login page", async () => {
    const panel = createFakePanel();
    const { router } = renderApp({ route: "/", transport: panel.transport });

    expect(await heading(t("login.title"))).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("shows a signed-in admin the page inside the app shell", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/", transport: panel.transport });

    expect(await heading(t("overview.title"))).toBeInTheDocument();
    const navigation = within(screen.getByRole("navigation", { name: t("nav.main") }));
    for (const entry of ["nav.overview", "nav.nodes", "nav.proxies", "nav.settings"] as const) {
      expect(navigation.getByRole("link", { name: t(entry) })).toBeInTheDocument();
    }
    expect(screen.getByText(ADMIN)).toBeInTheDocument();
  });

  it("marks the page that is open in the navigation, and moves between pages", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/", transport: panel.transport });

    await heading(t("overview.title"));
    expect(screen.getByRole("link", { name: t("nav.overview") })).toHaveAttribute("data-active", "true");
    expect(screen.getByRole("link", { name: t("nav.nodes") })).not.toHaveAttribute("data-active");

    await user.click(screen.getByRole("link", { name: t("nav.nodes") }));
    expect(await heading(t("nodes.title"))).toBeInTheDocument();
    expect(await screen.findByText(t("nodes.empty"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: t("nav.nodes") })).toHaveAttribute("data-active", "true");

    await user.click(screen.getByRole("link", { name: t("nav.proxies") }));
    expect(await heading(t("proxies.title"))).toBeInTheDocument();
    expect(await screen.findByText(t("proxies.noNodes"))).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: t("nav.settings") }));
    expect(await heading(t("settings.title"))).toBeInTheDocument();
  });

  it("sends an unknown address to the overview", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { router } = renderApp({ route: "/no/such/page", transport: panel.transport });

    expect(await heading(t("overview.title"))).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/");
  });

  it("signs the admin out: the session ends, what was loaded is dropped, and the login page opens", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel({ signedIn: true });
    const { router, queryClient } = renderApp({ route: "/", transport: panel.transport });

    await heading(t("overview.title"));
    await user.click(screen.getByRole("button", { name: t("nav.signOut") }));

    expect(await heading(t("login.title"))).toBeInTheDocument();
    expect(panel.rpc.logout).toHaveBeenCalledTimes(1);
    expect(panel.state.signedIn).toBe(false);
    expect(router.state.location.pathname).toBe("/login");
    expect(queryClient.getQueryData(authKeys.me)).toBeUndefined();
  });

  it("keeps the admin on the page when the sign-out fails for another reason, and says why", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel({ signedIn: true });
    panel.rpc.logout.mockImplementation(() => {
      throw new ConnectError("the database is locked", Code.Internal);
    });
    renderApp({ route: "/", transport: panel.transport });

    await heading(t("overview.title"));
    await user.click(screen.getByRole("button", { name: t("nav.signOut") }));

    expect(await screen.findByText("the database is locked")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: t("overview.title") })).toBeInTheDocument();
  });

  it("sends the admin to the login page when the session ends while a page is open", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/settings", transport: panel.transport });

    const section = within(await screen.findByRole("region", { name: t("settings.password.title") }));
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);

    // The session expires (or ends elsewhere); the next call is refused with a 401.
    panel.state.signedIn = false;
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await heading(t("login.title"))).toBeInTheDocument();
  });

  it("shows why a page could not be loaded, and loads it again on request", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel({ signedIn: true });
    panel.rpc.me.mockImplementationOnce(() => {
      throw new ConnectError("the panel is starting", Code.Unavailable);
    });
    renderApp({ route: "/", transport: panel.transport });

    expect(await heading(t("errors.loadTitle"))).toBeInTheDocument();
    expect(screen.getByText("the panel is starting")).toBeInTheDocument();
    // This is not shown as a notification as well: the page says it.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("common.retry") }));
    expect(await heading(t("overview.title"))).toBeInTheDocument();
  });

  it("keeps a page that is open when a later refresh fails for another reason than a 401", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { queryClient } = renderApp({ route: "/", transport: panel.transport });
    await heading(t("overview.title"));

    panel.rpc.me.mockImplementationOnce(() => {
      throw new ConnectError("the panel is restarting", Code.Unavailable);
    });
    await queryClient.invalidateQueries({ queryKey: authKeys.me });

    await waitFor(() => {
      expect(queryClient.getQueryState(authKeys.me)?.status).toBe("error");
    });
    expect(screen.getByRole("heading", { name: t("overview.title") })).toBeInTheDocument();
  });
});
