import { createBrowserRouter, Navigate, type RouteObject } from "react-router";

import { RequireAuth } from "../components/RequireAuth";
import { RouteError } from "../components/RouteError";
import { DnsCredentials } from "../pages/DnsCredentials";
import { Egress } from "../pages/Egress";
import { Login } from "../pages/Login";
import { NodeDetail } from "../pages/NodeDetail";
import type { NodeTabHandle } from "../pages/node/nodeTabs";
import { NodeDiagnosticsTab, NodeEgressTab, NodeOverviewTab, NodeProxiesTab, NodeSettingsTab, NodeTabNotFound } from "../pages/node/tabs";
import { NodeInstall } from "../pages/NodeInstall";
import { Nodes } from "../pages/Nodes";
import { Overview } from "../pages/Overview";
import { Proxies } from "../pages/Proxies";
import { ProxyDetailRoute } from "../pages/ProxyDetailRoute";
import { Settings } from "../pages/Settings";
import { Setup } from "../pages/Setup";
import type { VersionsTabHandle } from "../pages/versions/versionsTabs";

const versionsTabs = () => import("../pages/versions/tabs");

/**
 * Setup and Login are open to a visitor. Everything else sits behind
 * RequireAuth, which shows the app shell around the page. The page of a proxy is
 * loaded on demand (see ProxyDetailRoute).
 */
export const routes: RouteObject[] = [
  { path: "/setup", Component: Setup, ErrorBoundary: RouteError },
  { path: "/login", Component: Login, ErrorBoundary: RouteError },
  {
    Component: RequireAuth,
    ErrorBoundary: RouteError,
    children: [
      { index: true, Component: Overview },
      { path: "nodes", Component: Nodes },
      // The page of a node is in tabs, one route each: the address is the tab.
      {
        path: "nodes/:nodeId",
        Component: NodeDetail,
        children: [
          { index: true, Component: NodeOverviewTab, handle: { nodeTab: "overview" } satisfies NodeTabHandle },
          { path: "proxies", Component: NodeProxiesTab, handle: { nodeTab: "proxies" } satisfies NodeTabHandle },
          { path: "egress", Component: NodeEgressTab, handle: { nodeTab: "egress" } satisfies NodeTabHandle },
          { path: "diagnostics", Component: NodeDiagnosticsTab, handle: { nodeTab: "diagnostics" } satisfies NodeTabHandle },
          { path: "settings", Component: NodeSettingsTab, handle: { nodeTab: "settings" } satisfies NodeTabHandle },
          // A tab that does not exist is the overview of the node.
          { path: "*", Component: NodeTabNotFound },
        ],
      },
      { path: "nodes/:nodeId/install", Component: NodeInstall },
      { path: "proxies", Component: Proxies },
      { path: "proxies/:proxyId", Component: ProxyDetailRoute },
      { path: "egress", Component: Egress },
      { path: "dns", Component: DnsCredentials },
      // The page of versions is loaded when it is first opened, as that of a proxy is.
      // It is in tabs, one route each: the address is the tab.
      {
        path: "versions",
        lazy: async () => ({ Component: (await import("../pages/Versions")).Versions }),
        children: [
          { index: true, lazy: async () => ({ Component: (await versionsTabs()).VersionsEnginesTab }), handle: { versionsTab: "engines" } satisfies VersionsTabHandle },
          { path: "nodes", lazy: async () => ({ Component: (await versionsTabs()).VersionsNodesTab }), handle: { versionsTab: "nodes" } satisfies VersionsTabHandle },
          { path: "history", lazy: async () => ({ Component: (await versionsTabs()).VersionsHistoryTab }), handle: { versionsTab: "history" } satisfies VersionsTabHandle },
          { path: "settings", lazy: async () => ({ Component: (await versionsTabs()).VersionsSettingsTab }), handle: { versionsTab: "settings" } satisfies VersionsTabHandle },
          // A tab that does not exist is the first one.
          { path: "*", lazy: async () => ({ Component: (await versionsTabs()).VersionsTabNotFound }) },
        ],
      },
      // The journal is loaded when it is first opened.
      { path: "journal", lazy: async () => ({ Component: (await import("../pages/Journal")).Journal }) },
      { path: "settings", Component: Settings },
    ],
  },
  { path: "*", element: <Navigate to="/" replace /> },
];

export function createAppRouter() {
  return createBrowserRouter(routes);
}
