import { Anchor, Button, Group, Paper, Stack, Switch, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";

import { errorMessage } from "../api/errors";
import { useChains } from "../api/hooks/egress";
import { useListeners } from "../api/hooks/listeners";
import { useNode } from "../api/hooks/nodes";
import { useDeleteProxy, useProxy, useSetProxyEnabled } from "../api/hooks/proxies";
import { useProxyLive } from "../api/hooks/stats";
import { PROXY_SCOPES, type ProxyScope } from "../app/egress";
import { formatDateTime } from "../app/format";
import { listenerLabel } from "../app/listener";
import { notifySuccess } from "../app/notify";
import { proxyTitle } from "../app/proxy";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { AvailabilitySection } from "../components/AvailabilitySection";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DefinitionList } from "../components/DefinitionList";
import { BackIcon, TrashIcon } from "../components/icons";
import { LiveStats } from "../components/LiveStats";
import { NotFoundNotice } from "../components/NotFoundNotice";
import { ProxyForm } from "../components/ProxyForm";
import { ProxyLinks } from "../components/ProxyLinks";
import { ProxyVersions } from "../components/ProxyVersions";
import { QueryView } from "../components/QueryView";
import { StatsSection } from "../components/StatsSection";
import { StatusBadge } from "../components/StatusBadge";
import { WebSnippets } from "../components/WebSnippets";

/**
 * One proxy: its links and QR code, live numbers, its statistics over a range and
 * its settings. The router loads this page on demand: it draws charts, and the
 * chart library is the biggest part of the app.
 */
export function ProxyDetail() {
  const { t } = useTranslation();
  const { proxyId = "" } = useParams();
  const proxy = useProxy(proxyId);

  return (
    <QueryView query={proxy} notFound={<NotFoundNotice backTo="/proxies" backLabel={t("proxies.title")} />}>
      {(data) => <ProxyPage proxy={data} />}
    </QueryView>
  );
}

function ProxyPage({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const remove = useDeleteProxy();
  const setEnabled = useSetProxyEnabled();
  const live = useProxyLive(proxy.id);
  const [deleting, setDeleting] = useState(false);
  const title = proxyTitle(proxy);
  // What the node reported last, which is newer than what the proxy was listed with.
  const status = live.data?.status ?? proxy.status;

  async function confirmDelete() {
    try {
      await remove.mutateAsync(proxy.id);
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("proxy.delete.done"));
    void navigate("/proxies");
  }

  return (
    <Stack gap="lg">
      <Anchor component={Link} to="/proxies" size="sm" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <BackIcon />
        {t("proxies.title")}
      </Anchor>

      <Group justify="space-between" align="center" wrap="wrap">
        <Group gap="sm" align="center">
          <Title order={1}>{title}</Title>
          <StatusBadge kind="proxy" value={status?.phase ?? "unknown"} reason={status?.reason} />
        </Group>
        <Group gap="md">
          <Switch
            label={t("proxy.detail.enabled")}
            checked={proxy.enabled}
            disabled={setEnabled.isPending}
            onChange={(event) => {
              setEnabled.mutate({ id: proxy.id, enabled: event.currentTarget.checked });
            }}
          />
          <Button
            variant="light"
            color="red"
            leftSection={<TrashIcon />}
            onClick={() => {
              setDeleting(true);
            }}
          >
            {t("proxy.delete.action")}
          </Button>
        </Group>
      </Group>

      <ProxyDetails proxy={proxy} />
      <ProxyVersions proxy={proxy} />
      <ProxyLinks proxyId={proxy.id} />
      {proxy.type === "web" ? <WebSnippetsIfUpstream proxy={proxy} /> : null}
      <LiveStats proxyId={proxy.id} />
      <StatsSection proxyId={proxy.id} />
      <AvailabilitySection proxy={proxy} />
      <ProxySettings proxy={proxy} />

      <ConfirmDialog
        opened={deleting}
        title={t("proxy.delete.title")}
        message={t("proxy.delete.message", { name: title })}
        confirmLabel={t("proxy.delete.confirm")}
        loading={remove.isPending}
        onConfirm={() => {
          void confirmDelete();
        }}
        onClose={() => {
          setDeleting(false);
        }}
      />
    </Stack>
  );
}

/** The snippets of a WEB proxy behind a web server of the node (an http-upstream listener); nothing for the others. */
function WebSnippetsIfUpstream({ proxy }: { proxy: Proxy }) {
  const listeners = useListeners(proxy.nodeId);
  const listener = listeners.data?.find((entry) => entry.id === proxy.listenerId);
  return listener?.kind === "http-upstream" ? <WebSnippets proxyId={proxy.id} /> : null;
}

/** The label of the chain of each scope. */
const SCOPE_LABEL = { me: "proxy.detail.scopeMe", fetch: "proxy.detail.scopeFetch" } as const satisfies Record<ProxyScope, string>;

/** Where the proxy is, what runs it, and the chains that it goes out through. */
function ProxyDetails({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const titleId = useId();
  const node = useNode(proxy.nodeId);
  const listeners = useListeners(proxy.nodeId);
  const listener = listeners.data?.find((entry) => entry.id === proxy.listenerId);
  const chains = useChains(proxy.nodeId);
  /** A chain by its name, or its id while the chains cannot be had (and then why). */
  const chainName = (id: string) => {
    const name = chains.data?.find((entry) => entry.id === id)?.name;
    if (name !== undefined || !chains.isError) {
      return name ?? id;
    }
    return (
      <Stack gap={0} component="span">
        <span>{id}</span>
        <Text component="span" size="xs" c="red">
          {errorMessage(chains.error)}
        </Text>
      </Stack>
    );
  };
  const chain = proxy.egressChainId === "" ? t("proxy.form.chainDefault") : chainName(proxy.egressChainId);
  // The chains of its own that the proxy has for a scope; a scope without one takes the chain of the proxy.
  const scopeChains = PROXY_SCOPES.flatMap((scope) => {
    const id = proxy.egressScopeChains[scope] ?? "";
    return id === "" ? [] : [{ label: t(SCOPE_LABEL[scope]), value: chainName(id) }];
  });

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="md">
        {t("proxy.detail.info")}
      </Title>
      <DefinitionList
        items={[
          {
            label: t("proxy.detail.node"),
            value: node.data ? (
              <Anchor component={Link} to={`/nodes/${node.data.id}`} size="sm">
                {node.data.name}
              </Anchor>
            ) : (
              "—"
            ),
          },
          { label: t("proxy.detail.listener"), value: listener ? listenerLabel(listener, t) : "—" },
          { label: t("proxy.detail.type"), value: proxy.type === "web" ? t("proxy.type.web") : t("proxy.type.faketls") },
          { label: t("proxy.detail.domain"), value: proxy.domain },
          ...webItems(proxy, listener?.kind === "http-upstream", t),
          { label: t("proxy.detail.engine"), value: `${proxy.engine} ${proxy.engineVersion}`.trim() },
          { label: t("proxy.detail.chain"), value: chain },
          ...scopeChains,
          ...(proxy.note === ""
            ? []
            : [{ label: t("proxy.detail.note"), value: <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{proxy.note}</Text> }]),
        ]}
      />
    </Paper>
  );
}

/** What is shown of the WEB settings: the address under the domain, how the secret is written, and the certificate. */
function webItems(proxy: Proxy, upstream: boolean, t: TFunction) {
  const web = proxy.web;
  if (proxy.type !== "web" || web === undefined) {
    return [];
  }
  const items = [
    { label: t("proxy.detail.address"), value: `https://${proxy.domain}${web.basePath === "" ? "" : `/${web.basePath}`}` },
    { label: t("proxy.detail.secretMode"), value: web.secretMode === "dd" ? t("proxy.secretMode.dd") : t("proxy.secretMode.plain") },
  ];
  if (upstream) {
    items.push({ label: t("proxy.detail.certificate"), value: t("proxy.detail.certificateUpstream") });
  } else if (web.certMode === "imported") {
    items.push({
      label: t("proxy.detail.certificate"),
      value:
        web.certNotAfterUnix === 0n
          ? t("proxy.certMode.imported")
          : t("proxy.detail.certificateImported", { until: formatDateTime(web.certNotAfterUnix) }),
    });
  } else {
    items.push({ label: t("proxy.detail.certificate"), value: t("proxy.certMode.acme-dns01") });
  }
  return items;
}

function ProxySettings({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="md">
        {t("proxy.detail.settings")}
      </Title>
      <ProxyForm proxy={proxy} onDone={() => undefined} />
    </Paper>
  );
}
