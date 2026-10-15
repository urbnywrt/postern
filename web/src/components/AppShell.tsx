import { ActionIcon, AppShell as Shell, Burger, Group, NavLink, Text, Tooltip } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link, Outlet, useLocation, useNavigate } from "react-router";

import { isUnauthenticated } from "../api/errors";
import { useLogout, useMe } from "../api/hooks/auth";
import { notifyError } from "../app/notify";
import { AboutDialog } from "./AboutDialog";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { ThemeToggle } from "./ThemeToggle";
import {
  ArrowUpIcon,
  EgressIcon,
  InfoIcon,
  JournalIcon,
  KeyIcon,
  LogoutIcon,
  NodesIcon,
  OverviewIcon,
  ProxiesIcon,
  SettingsIcon,
} from "./icons";

const navigation = [
  { to: "/", label: "nav.overview", icon: <OverviewIcon /> },
  { to: "/nodes", label: "nav.nodes", icon: <NodesIcon /> },
  { to: "/proxies", label: "nav.proxies", icon: <ProxiesIcon /> },
  { to: "/egress", label: "nav.egress", icon: <EgressIcon /> },
  { to: "/dns", label: "nav.dns", icon: <KeyIcon /> },
  { to: "/versions", label: "nav.versions", icon: <ArrowUpIcon /> },
  { to: "/journal", label: "insights.nav.journal", icon: <JournalIcon /> },
  { to: "/settings", label: "nav.settings", icon: <SettingsIcon /> },
] as const;

/** The frame of every signed-in page: header, navigation, and the page itself. */
export function AppShell() {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: me } = useMe();
  const logout = useLogout();
  const [menuOpened, { toggle: toggleMenu, close: closeMenu }] = useDisclosure(false);
  const [aboutOpened, { open: openAbout, close: closeAbout }] = useDisclosure(false);

  async function signOut() {
    try {
      await logout.mutateAsync();
    } catch (error) {
      // No session is what a sign-out is for; any other failure the admin has to know.
      if (!isUnauthenticated(error)) {
        notifyError(error);
        return;
      }
    }
    void navigate("/login", { replace: true });
    // What was loaded belongs to the session that has ended.
    queryClient.clear();
  }

  return (
    <Shell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !menuOpened } }}
      padding="md"
    >
      <Shell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger
              size="sm"
              hiddenFrom="sm"
              opened={menuOpened}
              onClick={toggleMenu}
              aria-label={t("nav.menu")}
            />
            <Text fw={700} size="lg">
              {t("app.name")}
            </Text>
          </Group>
          <Group gap="xs" wrap="nowrap">
            {me ? (
              <Text size="sm" c="dimmed" visibleFrom="sm">
                {me.username}
              </Text>
            ) : null}
            <Tooltip label={t("insights.about.open")}>
              <ActionIcon variant="default" size="lg" aria-label={t("insights.about.open")} onClick={openAbout}>
                <InfoIcon />
              </ActionIcon>
            </Tooltip>
            <LanguageSwitcher />
            <ThemeToggle />
            <Tooltip label={t("nav.signOut")}>
              <ActionIcon
                variant="default"
                size="lg"
                aria-label={t("nav.signOut")}
                loading={logout.isPending}
                onClick={() => {
                  void signOut();
                }}
              >
                <LogoutIcon />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>
      </Shell.Header>

      <Shell.Navbar p="xs" aria-label={t("nav.main")}>
        {navigation.map((item) => (
          <NavLink
            key={item.to}
            component={Link}
            to={item.to}
            label={t(item.label)}
            leftSection={item.icon}
            active={item.to === "/" ? pathname === "/" : pathname.startsWith(item.to)}
            onClick={closeMenu}
          />
        ))}
      </Shell.Navbar>

      <Shell.Main>
        <Outlet />
      </Shell.Main>
      <AboutDialog opened={aboutOpened} onClose={closeAbout} />
    </Shell>
  );
}
