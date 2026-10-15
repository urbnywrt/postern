/** The tabs of the page of versions, in order; each is a route under /versions (the engines are its index). */
export const VERSIONS_TABS = ["engines", "nodes", "history", "settings"] as const;
export type VersionsTab = (typeof VERSIONS_TABS)[number];

/** The route handle by which a tab is known (see the router). */
export interface VersionsTabHandle {
  versionsTab: VersionsTab;
}

/** The address of a tab of the page of versions. */
export const versionsTabPath = (tab: VersionsTab) => (tab === "engines" ? "/versions" : `/versions/${tab}`);
