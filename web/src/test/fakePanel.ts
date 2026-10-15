import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { vi } from "vitest";

import {
  AuthService,
  type ChangePasswordRequest,
  type ConfirmTotpRequest,
  type DisableTotpRequest,
  type LoginRequest,
  type SetupRequest,
} from "../gen/postern/panel/v1/auth_pb";
import { DeployService } from "../gen/postern/panel/v1/deploy_pb";
import { DiagnosticsService } from "../gen/postern/panel/v1/diagnostics_pb";
import { DnsCredentialService } from "../gen/postern/panel/v1/dns_pb";
import { ChainService, EgressService } from "../gen/postern/panel/v1/egress_pb";
import { GeoIPService } from "../gen/postern/panel/v1/geoip_pb";
import { MetricsService } from "../gen/postern/panel/v1/metrics_pb";
import { NodeService } from "../gen/postern/panel/v1/nodes_pb";
import { ProbeService } from "../gen/postern/panel/v1/probes_pb";
import { ListenerService, ProxyService, StatsService } from "../gen/postern/panel/v1/proxies_pb";
import {
  CheckPublicPageResponseSchema,
  type PublicPage,
  PublicPageSchema,
  PublicPageService,
  type UpdatePublicPageRequest,
} from "../gen/postern/panel/v1/publicpage_pb";
import { SettingsService } from "../gen/postern/panel/v1/settings_pb";
import { VersionService } from "../gen/postern/panel/v1/versions_pb";
import { createFakeDeploy } from "./fakeDeploy";
import { createFakeDiagnostics } from "./fakeDiagnostics";
import { createFakeDns, type DnsOptions } from "./fakeDns";
import { createFakeEgress, type EgressOptions } from "./fakeEgress";
import { createFakeInsights, type InsightsOptions } from "./fakeInsights";
import { createFakeInventory, type InventoryOptions } from "./fakeInventory";
import { createFakeVersions, type VersionsOptions } from "./fakeVersions";

// Test values. The passwords are made by repetition so that they cannot be taken
// for real credentials.
export const ADMIN = "admin";
export const PASSWORD = "p".repeat(16);
export const NEW_PASSWORD = "n".repeat(16);
export const TOTP_CODE = "123456";
export const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
export const OTPAUTH_URI = `otpauth://totp/Postern:${ADMIN}?secret=${TOTP_SECRET}&issuer=Postern`;
export const SETUP_TOKEN = "t".repeat(24);

export interface FakePanelOptions extends InventoryOptions, EgressOptions, DnsOptions, VersionsOptions, InsightsOptions {
  /** A session cookie is there from the start. */
  signedIn?: boolean;
  totpEnabled?: boolean;
  needsSetup?: boolean;
  /** The public page as stored; off, empty and "mark"/"ru" unless this says otherwise. */
  publicPage?: MessageInitShape<typeof PublicPageSchema>;
  /** The names the admin pages have been served on: a public host equal to one is refused. */
  adminHosts?: string[];
  /** What CheckPublicPage finds, besides the host; HTTPS works with the panel's page by default. */
  publicPageCheck?: MessageInitShape<typeof CheckPublicPageResponseSchema>;
}

/** The message of the panel when the public host is one the admin pages are served on. */
export const ADMIN_HOST_REFUSED = "the admin pages are served on this name";

/**
 * An in-memory panel that behaves like the real one: AuthService with one admin
 * and one session flag, the services of nodes, listeners, proxies and stats
 * (see fakeInventory), and DeployService (see fakeDeploy). It answers with the same Connect codes and messages, and is
 * served through a router transport, so a test exercises the real client code.
 * `rpc` has every handler as a mock, `state` the account, `inventory` the nodes,
 * listeners and proxies, `deploy` the SSH targets and the jobs.
 */
export function createFakePanel(options: FakePanelOptions = {}) {
  const state = {
    signedIn: options.signedIn ?? false,
    totpEnabled: options.totpEnabled ?? false,
    needsSetup: options.needsSetup ?? false,
    password: PASSWORD,
    secretPending: false,
  };

  const requireSession = () => {
    if (!state.signedIn) {
      throw new ConnectError("authentication required", Code.Unauthenticated);
    }
  };
  const wrongPassword = () => new ConnectError("the password is wrong", Code.PermissionDenied);
  const wrongCode = () => new ConnectError("the verification code is wrong", Code.PermissionDenied);

  const authRpc = {
    getSetupStatus: vi.fn(() => ({ needsSetup: state.needsSetup })),

    setup: vi.fn((req: SetupRequest) => {
      if (!state.needsSetup) {
        throw new ConnectError("the panel is already set up", Code.FailedPrecondition);
      }
      if (req.setupToken !== SETUP_TOKEN) {
        throw new ConnectError(
          "the setup token is wrong or has expired; restart the panel to get a new one",
          Code.PermissionDenied,
        );
      }
      state.needsSetup = false;
      state.password = req.password;
      return {};
    }),

    login: vi.fn((req: LoginRequest) => {
      if (req.username !== ADMIN || req.password !== state.password) {
        throw new ConnectError("invalid user name or password", Code.Unauthenticated);
      }
      if (state.totpEnabled) {
        if (req.totpCode === "") {
          return { totpRequired: true };
        }
        if (req.totpCode !== TOTP_CODE) {
          throw new ConnectError("invalid verification code", Code.Unauthenticated);
        }
      }
      state.signedIn = true;
      return { totpRequired: false };
    }),

    logout: vi.fn(() => {
      state.signedIn = false;
      return {};
    }),

    me: vi.fn(() => {
      requireSession();
      return { username: ADMIN, totpEnabled: state.totpEnabled };
    }),

    changePassword: vi.fn((req: ChangePasswordRequest) => {
      requireSession();
      if (req.currentPassword !== state.password) throw wrongPassword();
      if (state.totpEnabled && req.totpCode !== TOTP_CODE) throw wrongCode();
      state.password = req.newPassword;
      return {};
    }),

    beginTotp: vi.fn(() => {
      requireSession();
      if (state.totpEnabled) {
        throw new ConnectError("TOTP is on already; turn it off first", Code.FailedPrecondition);
      }
      state.secretPending = true;
      return { secret: TOTP_SECRET, otpauthUri: OTPAUTH_URI };
    }),

    confirmTotp: vi.fn((req: ConfirmTotpRequest) => {
      requireSession();
      if (!state.secretPending) {
        throw new ConnectError("no TOTP set-up is in progress; start again", Code.FailedPrecondition);
      }
      if (req.password !== state.password) throw wrongPassword();
      if (req.code !== TOTP_CODE) {
        throw new ConnectError("the verification code is wrong", Code.InvalidArgument);
      }
      state.totpEnabled = true;
      state.secretPending = false;
      return {};
    }),

    disableTotp: vi.fn((req: DisableTotpRequest) => {
      requireSession();
      if (!state.totpEnabled) {
        throw new ConnectError("TOTP is not on", Code.FailedPrecondition);
      }
      if (req.password !== state.password) throw wrongPassword();
      if (req.code !== TOTP_CODE) throw wrongCode();
      state.totpEnabled = false;
      return {};
    }),
  };

  const inventory = createFakeInventory(requireSession, options);
  const deploy = createFakeDeploy(requireSession, () => inventory.state.nodeImage);
  const egress = createFakeEgress(requireSession, inventory.state, options);
  const dns = createFakeDns(requireSession, inventory.state, options);
  const versions = createFakeVersions(requireSession, inventory.state, options);
  const insights = createFakeInsights(requireSession, inventory.state, options);
  const diagnostics = createFakeDiagnostics(requireSession, inventory.state);

  // ---- PublicPageService ----
  const page = {
    current: create(PublicPageSchema, {
      enabled: false,
      host: "",
      title: "",
      bodyMd: "",
      unavailable: "mark",
      defaultLocale: "ru",
      items: [],
      allowIndexing: false,
      ...options.publicPage,
    }),
    adminHosts: (options.adminHosts ?? ["panel.example.com"]).map((host) => host.toLowerCase()),
    check: options.publicPageCheck ?? {
      addresses: ["203.0.113.10"],
      httpsOk: true,
      certIssuer: "E5",
      certNotAfterUnix: 1_805_112_000n, // 2027-03-15 12:00 UTC: 15.03 in every time zone but the far ones
      servedByPanel: true,
    },
  };
  const invalid = (message: string) => new ConnectError(message, Code.InvalidArgument);
  const publicPageRpc = {
    getPublicPage: vi.fn(() => {
      requireSession();
      return { page: page.current };
    }),

    updatePublicPage: vi.fn((req: UpdatePublicPageRequest) => {
      requireSession();
      const next: PublicPage = create(PublicPageSchema, req.page ?? {});
      if (next.host !== "" && page.adminHosts.includes(next.host.toLowerCase())) {
        throw invalid(ADMIN_HOST_REFUSED);
      }
      if (next.enabled && next.host === "") {
        throw invalid("the page cannot be enabled without a host");
      }
      const seen = new Set<string>();
      for (const item of next.items) {
        if (!inventory.state.proxies.some((proxy) => proxy.id === item.proxyId)) {
          throw new ConnectError("no such proxy", Code.NotFound);
        }
        if (seen.has(item.proxyId)) {
          throw invalid("a proxy is listed twice");
        }
        seen.add(item.proxyId);
      }
      page.current = next;
      return { page: page.current };
    }),

    checkPublicPage: vi.fn(() => {
      requireSession();
      if (page.current.host === "") {
        throw new ConnectError("the public page has no host", Code.FailedPrecondition);
      }
      return create(CheckPublicPageResponseSchema, { ...page.check, host: page.current.host });
    }),
  };

  const rpc = { ...authRpc, ...inventory.rpc, ...deploy.rpc, ...egress.rpc, ...dns.rpc, ...publicPageRpc, ...versions.rpc, ...insights.rpc, ...diagnostics.rpc };

  const transport = createRouterTransport(({ service }) => {
    service(AuthService, authRpc);
    service(NodeService, {
      listNodes: rpc.listNodes,
      getNode: rpc.getNode,
      createNode: rpc.createNode,
      updateNode: rpc.updateNode,
      deleteNode: rpc.deleteNode,
      getNodeInstall: rpc.getNodeInstall,
      createJoinToken: rpc.createJoinToken,
      setNodeMgmtMode: rpc.setNodeMgmtMode,
    });
    service(ListenerService, {
      listListeners: rpc.listListeners,
      createListener: rpc.createListener,
      updateListener: rpc.updateListener,
      deleteListener: rpc.deleteListener,
    });
    service(ProxyService, {
      listProxies: rpc.listProxies,
      getProxy: rpc.getProxy,
      createProxy: rpc.createProxy,
      updateProxy: rpc.updateProxy,
      deleteProxy: rpc.deleteProxy,
      setProxyEnabled: rpc.setProxyEnabled,
      getProxyLinks: rpc.getProxyLinks,
      getWebSnippets: rpc.getWebSnippets,
    });
    service(DnsCredentialService, {
      listDnsCredentials: rpc.listDnsCredentials,
      createDnsCredential: rpc.createDnsCredential,
      updateDnsCredential: rpc.updateDnsCredential,
      deleteDnsCredential: rpc.deleteDnsCredential,
    });
    service(StatsService, { proxyLive: rpc.proxyLive, proxySeries: rpc.proxySeries });
    service(DeployService, deploy.rpc);
    service(EgressService, {
      listEgresses: rpc.listEgresses,
      getEgress: rpc.getEgress,
      createEgress: rpc.createEgress,
      updateEgress: rpc.updateEgress,
      deleteEgress: rpc.deleteEgress,
      validateEgress: rpc.validateEgress,
      refreshSubscription: rpc.refreshSubscription,
      getNodeEgressHealth: rpc.getNodeEgressHealth,
      setNodeDnsMode: rpc.setNodeDnsMode,
    });
    service(ChainService, {
      listChains: rpc.listChains,
      getChain: rpc.getChain,
      createChain: rpc.createChain,
      updateChain: rpc.updateChain,
      deleteChain: rpc.deleteChain,
      setNodeDefaultChain: rpc.setNodeDefaultChain,
    });
    service(PublicPageService, publicPageRpc);
    service(VersionService, versions.rpc);
    service(MetricsService, {
      overview: rpc.overview,
      nodeSeries: rpc.nodeSeries,
      topProxies: rpc.topProxies,
      countries: rpc.countries,
      listIpSightings: rpc.listIpSightings,
      egressHistory: rpc.egressHistory,
    });
    service(ProbeService, { probeNow: rpc.probeNow, probeHistory: rpc.probeHistory });
    service(SettingsService, {
      getStatsSettings: rpc.getStatsSettings,
      updateStatsSettings: rpc.updateStatsSettings,
      getStorage: rpc.getStorage,
    });
    service(DiagnosticsService, diagnostics.rpc);
    service(GeoIPService, { getGeoIP: rpc.getGeoIP, refreshGeoIP: rpc.refreshGeoIP, setGeoIPEnabled: rpc.setGeoIPEnabled });
  });

  return { transport, rpc, state, inventory: inventory.state, deploy: deploy.state, egress: egress.state, dns: dns.state, publicPage: page, versions: versions.state, insights: insights.state, diagnostics: diagnostics.state };
}

export type FakePanel = ReturnType<typeof createFakePanel>;
