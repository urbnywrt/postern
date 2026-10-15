import { Alert, Anchor, Button, Group, SegmentedControl, Select, SimpleGrid, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { errorMessage } from "../api/errors";
import { useDnsCredentials } from "../api/hooks/dns";
import { useChains } from "../api/hooks/egress";
import { useListeners } from "../api/hooks/listeners";
import { useNode, useNodes } from "../api/hooks/nodes";
import { type UpdateProxyVars, useCreateProxy, useUpdateProxy, type WebSettingsVars } from "../api/hooks/proxies";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { PROXY_SCOPES, type ProxyScope } from "../app/egress";
import { listenerLabel } from "../app/listener";
import { notifySuccess } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import {
  parseLimit,
  validateAcmeEmail,
  validateAdTag,
  validateBasePath,
  validateCertificatePair,
  validateDomain,
  validateLimit,
  validateNote,
  validateProxyName,
  validateSecret,
  validateWebDomain,
} from "../app/validators";
import { type ChangeCheck, ChangeCheckNotice } from "./ChangeCheckNotice";

/** The middle-proxy settings of a proxy, as the panel names them, with the text that tells them apart. */
const MIDDLE_PROXY_MODES = [
  { value: "auto", label: "proxy.form.middleProxyAuto" },
  { value: "on", label: "proxy.form.middleProxyOn" },
  { value: "off", label: "proxy.form.middleProxyOff" },
] as const;

/** The setting of a proxy; a proxy that says none (an older panel) is on auto. */
const middleProxyOf = (proxy: Proxy | undefined) => (proxy === undefined || proxy.useMiddleProxy === "" ? "auto" : proxy.useMiddleProxy);

interface Values {
  nodeId: string;
  listenerId: string;
  type: string;
  name: string;
  note: string;
  domain: string;
  secret: string;
  devices: string;
  connsTotal: string;
  connsPerIp: string;
  adTag: string;
  /** The egress chain, NO_CHAIN for the default of the node. */
  chain: string;
  /** The chains for the scopes me and fetch, NO_CHAIN for the chain of the proxy. */
  scopeMe: string;
  scopeFetch: string;
  useMiddleProxy: string;
  // WEB proxies.
  basePath: string;
  secretMode: string;
  carrier: string;
  certMode: string;
  dnsCredentialId: string;
  acmeEmail: string;
  certChain: string;
  certKey: string;
}

/** The value of a chain field for no chain of its own: a Select has no empty value. */
const NO_CHAIN = "-";

const chainValue = (id: string | undefined) => (id === undefined || id === "" ? NO_CHAIN : id);
const chainId = (value: string) => (value === NO_CHAIN ? "" : value);

/** The field of the chain of each scope. */
const SCOPE_FIELD = { me: "scopeMe", fetch: "scopeFetch" } as const satisfies Record<ProxyScope, keyof Values>;
const SCOPE_FIELDS = PROXY_SCOPES.map((scope) => SCOPE_FIELD[scope]);

/** The scope chains that the values give, without the scopes that take the chain of the proxy. */
function scopeChainsOf(v: Values): Record<string, string> {
  const out: Record<string, string> = {};
  for (const scope of PROXY_SCOPES) {
    const id = chainId(v[SCOPE_FIELD[scope]]);
    if (id !== "") out[scope] = id;
  }
  return out;
}

const sameScopes = (a: Record<string, string>, b: Record<string, string>) =>
  Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([scope, id]) => b[scope] === id);

/** The WEB settings that the values give, without the certificate. */
function webSettingsOf(v: Values, upstream: boolean): WebSettingsVars {
  return {
    basePath: v.basePath.trim(),
    secretMode: v.secretMode,
    carrier: v.carrier,
    certMode: upstream ? "" : v.certMode,
    dnsCredentialId: upstream || v.certMode !== "acme-dns01" ? "" : v.dnsCredentialId,
    acmeEmail: upstream ? "" : v.acmeEmail.trim(),
  };
}

const sameWeb = (a: WebSettingsVars, b: WebSettingsVars) =>
  a.basePath === b.basePath &&
  a.secretMode === b.secretMode &&
  a.carrier === b.carrier &&
  a.certMode === b.certMode &&
  a.dnsCredentialId === b.dnsCredentialId &&
  a.acmeEmail === b.acmeEmail;

const encoder = new TextEncoder();

interface ProxyFormProps {
  /**
   * A new proxy on this node. Left out, the form asks which node (unless it is
   * the form of an existing proxy, which is told by `proxy`).
   */
  nodeId?: string;
  /** The proxy whose settings are edited: name, note, domain, limits, ad tag, middle-proxy setting and WEB settings. */
  proxy?: Proxy;
  onDone: (proxy: Proxy) => void;
  onCancel?: () => void;
}

const limitsOf = (proxy: Proxy) => ({
  devices: proxy.limits?.devices ?? 0,
  connsTotal: proxy.limits?.connsTotal ?? 0,
  connsPerIp: proxy.limits?.connsPerIp ?? 0,
});

/**
 * The form of a proxy: a new one on a listener of a node, or the settings of an
 * existing one. The secret is asked for only when the proxy is made: it is shown
 * only inside its links afterwards, and rotating it is not a setting. A WEB
 * proxy has its settings too: where it lives under its domain, how the secret is
 * written in the link, and where its certificate comes from.
 */
export function ProxyForm({ nodeId: fixedNodeId, proxy, onDone, onCancel }: ProxyFormProps) {
  const { t } = useTranslation();
  const editing = proxy !== undefined;
  const create = useCreateProxy();
  const update = useUpdateProxy();
  const pending = create.isPending || update.isPending;
  // What the form started from, and then what it last saved. Only what differs from it
  // goes to the panel: a field that was not touched must not undo a change that somebody
  // else made in the meantime.
  const [baseline, setBaseline] = useState(proxy);
  // A change of the chains makes the panel check the proxy before it saves (up to 90 s).
  const [check, setCheck] = useState<ChangeCheck>(null);

  const form = useFormState<Values>({
    nodeId: "",
    listenerId: "",
    type: proxy?.type ?? "faketls",
    name: proxy?.name ?? "",
    note: proxy?.note ?? "",
    domain: proxy?.domain ?? "",
    secret: "",
    devices: String(proxy?.limits?.devices ?? 0),
    connsTotal: String(proxy?.limits?.connsTotal ?? 0),
    connsPerIp: String(proxy?.limits?.connsPerIp ?? 0),
    adTag: proxy?.adTag ?? "",
    chain: chainValue(proxy?.egressChainId),
    scopeMe: chainValue(proxy?.egressScopeChains.me),
    scopeFetch: chainValue(proxy?.egressScopeChains.fetch),
    basePath: proxy?.web?.basePath ?? "",
    secretMode: proxy?.web?.secretMode ?? "plain",
    carrier: proxy?.web?.carrier ?? "https",
    certMode: proxy?.web?.certMode === "imported" ? "imported" : "acme-dns01",
    dnsCredentialId: proxy?.web?.dnsCredentialId ?? "",
    acmeEmail: proxy?.web?.acmeEmail ?? "",
    certChain: "",
    certKey: "",
    useMiddleProxy: middleProxyOf(proxy),
  });
  const { values } = form;
  const web = values.type === "web";

  // The node and the listener a new proxy goes on: the one that was chosen, or the
  // only one there is. Nothing is guessed when there are several.
  const askNode = !editing && fixedNodeId === undefined;
  const nodes = useNodes({ enabled: askNode });
  const nodeList = askNode ? (nodes.data ?? []) : [];
  const nodeId =
    fixedNodeId ??
    proxy?.nodeId ??
    (nodeList.some((node) => node.id === values.nodeId) ? values.nodeId : nodeList.length === 1 ? (nodeList[0]?.id ?? "") : "");
  const listeners = useListeners(nodeId, { enabled: nodeId !== "" });
  // A node with no address yet (it has not joined, or joined from an address that is not
  // public) gives links without a host: the form says so before the proxy is made.
  const fixedNode = useNode(fixedNodeId ?? "", { enabled: !editing && fixedNodeId !== undefined });
  const chosenNode = askNode ? nodeList.find((node) => node.id === nodeId) : fixedNode.data;
  const nodeHasNoHost = !editing && chosenNode?.mgmtHost === "" && chosenNode.linkHost === "";
  // A fake-TLS proxy goes on a tls listener; a WEB one on either kind.
  const listenerList = editing ? [] : (listeners.data ?? []).filter((listener) => web || listener.kind === "tls");
  const listenerId = editing
    ? proxy.listenerId
    : listenerList.some((listener) => listener.id === values.listenerId)
      ? values.listenerId
      : listenerList.length === 1
        ? (listenerList[0]?.id ?? "")
        : "";
  const noListeners = !editing && listeners.isSuccess && listenerList.length === 0;
  const listener = (listeners.data ?? []).find((entry) => entry.id === listenerId);
  // Behind a web server of the node the certificate is that server's.
  const upstream = listener?.kind === "http-upstream";
  const imported = web && !upstream && values.certMode === "imported";
  const acme = web && !upstream && values.certMode === "acme-dns01";
  const credentials = useDnsCredentials({ enabled: acme });
  // The chains that the node of the proxy can use: those of every node, and its own.
  const chainNode = proxy?.nodeId ?? nodeId;
  const chains = useChains(chainNode, { enabled: chainNode !== "" });
  const chainData = (none: string) => [
    { value: NO_CHAIN, label: none },
    ...(chains.data ?? []).map((chain) => ({ value: chain.id, label: chain.name })),
  ];

  const fields = form.check(validate(values));

  function validate(v: Values): FieldErrors<Values> {
    return {
      nodeId: askNode && nodeId === "" ? "required" : null,
      listenerId: editing || listenerId !== "" ? null : "required",
      name: validateProxyName(v.name),
      note: validateNote(v.note),
      domain: web ? validateWebDomain(v.domain) : validateDomain(v.domain),
      secret: editing ? null : validateSecret(v.secret),
      devices: validateLimit(v.devices),
      connsTotal: validateLimit(v.connsTotal),
      connsPerIp: validateLimit(v.connsPerIp),
      adTag: validateAdTag(v.adTag),
      basePath: web ? validateBasePath(v.basePath, upstream) : null,
      dnsCredentialId: acme && v.dnsCredentialId === "" ? "required" : null,
      acmeEmail: acme ? validateAcmeEmail(v.acmeEmail) : null,
      // A stored certificate stays when none is given.
      certChain: imported ? validateCertificatePair(v.certChain, v.certKey, baseline?.web?.certSha256 === undefined || baseline.web.certSha256 === "") : null,
    };
  }

  async function submit() {
    if (pending) {
      return; // a second Enter must not send the same try again
    }
    form.setSubmitted(true);
    if (!fields.valid) {
      return;
    }
    const limits = {
      devices: parseLimit(values.devices),
      connsTotal: parseLimit(values.connsTotal),
      connsPerIp: parseLimit(values.connsPerIp),
    };
    const webSettings = (): WebSettingsVars => {
      const settings = webSettingsOf(values, upstream);
      if (imported && values.certChain.trim() !== "") {
        settings.certFullchainPem = encoder.encode(values.certChain.trim() + "\n");
        settings.certKeyPem = encoder.encode(values.certKey.trim() + "\n");
      }
      return settings;
    };
    try {
      if (baseline === undefined) {
        const created = await create.mutateAsync({
          nodeId,
          listenerId,
          type: values.type,
          name: values.name.trim(),
          note: values.note,
          domain: values.domain.trim(),
          secret: values.secret.trim(),
          limits,
          adTag: values.adTag.trim(),
          egressChainId: chainId(values.chain),
          egressScopeChains: scopeChainsOf(values),
          web: web ? webSettings() : undefined,
          useMiddleProxy: values.useMiddleProxy,
        });
        onDone(created);
        return;
      }
      const changes: UpdateProxyVars = { id: baseline.id };
      const before = limitsOf(baseline);
      if (values.name.trim() !== baseline.name) changes.name = values.name.trim();
      if (values.note !== baseline.note) changes.note = values.note;
      if (values.domain.trim() !== baseline.domain) changes.domain = values.domain.trim();
      if (values.adTag.trim() !== baseline.adTag) changes.adTag = values.adTag.trim();
      if (values.useMiddleProxy !== middleProxyOf(baseline)) changes.useMiddleProxy = values.useMiddleProxy;
      if (limits.devices !== before.devices || limits.connsTotal !== before.connsTotal || limits.connsPerIp !== before.connsPerIp) {
        changes.limits = limits;
      }
      if (chainId(values.chain) !== baseline.egressChainId) changes.egressChainId = chainId(values.chain);
      const scopes = scopeChainsOf(values);
      if (!sameScopes(scopes, baseline.egressScopeChains)) changes.egressScopeChains = { chains: scopes };
      if (web && baseline.web) {
        const next = webSettings();
        const stored: WebSettingsVars = {
          basePath: baseline.web.basePath,
          secretMode: baseline.web.secretMode,
          carrier: baseline.web.carrier,
          certMode: baseline.web.certMode,
          dnsCredentialId: baseline.web.dnsCredentialId,
          acmeEmail: baseline.web.acmeEmail,
        };
        if (!sameWeb(next, stored) || next.certFullchainPem !== undefined) changes.web = next;
      }
      if (Object.keys(changes).length === 1) {
        onDone(baseline);
        return;
      }
      const checked = changes.egressChainId !== undefined || changes.egressScopeChains !== undefined;
      const target = { nodeId: baseline.nodeId, proxyId: baseline.id };
      setCheck(checked ? target : null);
      const { proxy: updated, beforeRunId } = await update.mutateAsync(changes).catch((error: unknown) => {
        setCheck(null);
        throw error;
      });
      setCheck(checked ? { ...target, beforeRunId } : null);
      setBaseline(updated);
      // The certificate was sent; it is not kept in the form.
      form.set("certChain", "");
      form.set("certKey", "");
      notifySuccess(t("proxy.form.saved"));
      onDone(updated);
    } catch {
      // The query client has shown why, and the form keeps what was typed.
    }
  }

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Stack gap="sm">
        {editing ? null : (
          <Stack gap={4}>
            <Text size="sm" fw={500} component="label" htmlFor="proxy-type">
              {t("proxy.form.type")}
            </Text>
            <SegmentedControl
              id="proxy-type"
              data={[
                { value: "faketls", label: t("proxy.type.faketls") },
                { value: "web", label: t("proxy.type.web") },
              ]}
              value={values.type}
              onChange={(value) => {
                form.set("type", value);
              }}
            />
            <Text size="xs" c="dimmed">
              {web ? t("proxy.form.typeWebHint") : t("proxy.form.typeFakeTlsHint")}
            </Text>
          </Stack>
        )}

        {askNode ? (
          <Select
            label={t("proxy.form.node")}
            data={nodeList.map((node) => ({ value: node.id, label: node.name }))}
            {...fields.bindSelect("nodeId")}
            value={nodeId === "" ? null : nodeId}
            onChange={(value) => {
              if ((value ?? "") === nodeId) {
                return;
              }
              form.set("nodeId", value ?? "");
              // A chain of one node is not for another: back to those of the node.
              for (const chainField of ["chain", ...SCOPE_FIELDS] as const) {
                form.set(chainField, NO_CHAIN);
              }
            }}
            disabled={nodes.isPending}
            error={fields.errorOf("nodeId") ?? (nodes.isError ? errorMessage(nodes.error) : undefined)}
          />
        ) : null}

        {nodeHasNoHost ? <Alert color="yellow">{t("proxy.form.noHost")}</Alert> : null}

        {editing ? null : noListeners ? (
          <Alert color="yellow">{t("proxy.form.noListeners")}</Alert>
        ) : (
          <Select
            label={t("proxy.form.listener")}
            placeholder={t("proxy.form.listenerPlaceholder")}
            data={listenerList.map((entry) => ({ value: entry.id, label: listenerLabel(entry, t) }))}
            {...fields.bindSelect("listenerId")}
            value={listenerId === "" ? null : listenerId}
            disabled={nodeId === "" || listeners.isPending}
            error={fields.errorOf("listenerId") ?? (listeners.isError ? errorMessage(listeners.error) : undefined)}
            allowDeselect={false}
          />
        )}

        <TextInput label={t("proxy.form.name")} description={t("proxy.form.nameHint")} autoComplete="off" {...fields.bind("name")} />
        <Textarea label={t("proxy.form.note")} autosize minRows={2} maxRows={6} {...fields.bind("note")} />
        <TextInput
          label={t("proxy.form.domain")}
          description={web ? t("proxy.form.webDomainHint") : editing ? t("proxy.form.domainHintEdit") : t("proxy.form.domainHint")}
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("domain")}
        />
        {editing ? null : (
          <TextInput
            label={t("proxy.form.secret")}
            description={t("proxy.form.secretHint")}
            autoComplete="off"
            spellCheck={false}
            {...fields.bind("secret")}
          />
        )}

        {web ? (
          <Stack gap="sm">
            <Stack gap={4}>
              <Text size="sm" fw={500}>
                {t("proxy.form.web")}
              </Text>
              <Text size="xs" c="dimmed">
                {upstream ? t("proxy.form.webHintUpstream") : t("proxy.form.webHint")}
              </Text>
            </Stack>
            <TextInput
              label={t("proxy.form.basePath")}
              description={upstream ? t("proxy.form.basePathHintUpstream") : t("proxy.form.basePathHint")}
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("basePath")}
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <Select
                label={t("proxy.form.secretMode")}
                description={t("proxy.form.secretModeHint")}
                data={[
                  { value: "plain", label: t("proxy.secretMode.plain") },
                  { value: "dd", label: t("proxy.secretMode.dd") },
                ]}
                allowDeselect={false}
                {...fields.bindSelect("secretMode")}
              />
              <Select
                label={t("proxy.form.carrier")}
                description={t("proxy.form.carrierHint")}
                data={[
                  { value: "https", label: "https" },
                  { value: "https-lanes", label: "https-lanes" },
                ]}
                allowDeselect={false}
                {...fields.bindSelect("carrier")}
              />
            </SimpleGrid>
            {upstream ? null : (
              <>
                <Select
                  label={t("proxy.form.certMode")}
                  description={t("proxy.form.certModeHint")}
                  data={[
                    { value: "acme-dns01", label: t("proxy.certMode.acme-dns01") },
                    { value: "imported", label: t("proxy.certMode.imported") },
                  ]}
                  allowDeselect={false}
                  {...fields.bindSelect("certMode")}
                />
                {acme ? (
                  <>
                    <Select
                      label={t("proxy.form.dnsCredential")}
                      description={
                        <>
                          {t("proxy.form.dnsCredentialHint")}{" "}
                          <Anchor component={Link} to="/dns" size="xs">
                            {t("dns.title")}
                          </Anchor>
                        </>
                      }
                      placeholder={t("proxy.form.dnsCredentialPlaceholder")}
                      data={(credentials.data ?? []).map((credential) => ({ value: credential.id, label: credential.name }))}
                      {...fields.bindSelect("dnsCredentialId")}
                      disabled={credentials.isPending}
                      error={fields.errorOf("dnsCredentialId") ?? (credentials.isError ? errorMessage(credentials.error) : undefined)}
                      allowDeselect={false}
                    />
                    <TextInput
                      label={t("proxy.form.acmeEmail")}
                      description={t("proxy.form.acmeEmailHint")}
                      autoComplete="off"
                      spellCheck={false}
                      {...fields.bind("acmeEmail")}
                    />
                  </>
                ) : null}
                {imported ? (
                  <>
                    {baseline?.web?.certSha256 ? (
                      <Text size="xs" c="dimmed">
                        {t("proxy.form.certStored", { sha256: baseline.web.certSha256.slice(0, 16) })}
                      </Text>
                    ) : null}
                    <Textarea
                      label={t("proxy.form.certChain")}
                      description={t("proxy.form.certChainHint")}
                      autosize
                      minRows={3}
                      maxRows={8}
                      spellCheck={false}
                      {...fields.bind("certChain")}
                    />
                    <Textarea
                      label={t("proxy.form.certKey")}
                      description={t("proxy.form.certKeyHint")}
                      autosize
                      minRows={3}
                      maxRows={8}
                      spellCheck={false}
                      {...fields.bind("certKey")}
                      error={undefined}
                    />
                  </>
                ) : null}
              </>
            )}
          </Stack>
        ) : null}

        <Stack gap={4}>
          <Text size="sm" fw={500}>
            {t("proxy.form.limits")}
          </Text>
          <Text size="xs" c="dimmed">
            {t("proxy.form.limitsHint")}
          </Text>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
            <TextInput
              label={t("proxy.form.devices")}
              description={t("proxy.form.devicesHint")}
              inputMode="numeric"
              autoComplete="off"
              {...fields.bind("devices")}
            />
            <TextInput label={t("proxy.form.connsTotal")} inputMode="numeric" autoComplete="off" {...fields.bind("connsTotal")} />
            <TextInput label={t("proxy.form.connsPerIp")} inputMode="numeric" autoComplete="off" {...fields.bind("connsPerIp")} />
          </SimpleGrid>
        </Stack>

        <TextInput
          label={t("proxy.form.adTag")}
          description={t("proxy.form.adTagHint")}
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("adTag")}
        />

        <Stack gap={4}>
          <Text size="sm" fw={500}>
            {t("proxy.form.egress")}
          </Text>
          <Text size="xs" c="dimmed">
            {t("proxy.form.egressHint")}
          </Text>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
            <Select
              label={t("proxy.form.chain")}
              data={chainData(t("proxy.form.chainDefault"))}
              {...fields.bindSelect("chain")}
              disabled={chainNode === "" || chains.isPending}
              error={chains.isError ? errorMessage(chains.error) : undefined}
              allowDeselect={false}
            />
            <Select
              label={t("proxy.form.scopeMe")}
              description={t("proxy.form.scopeMeHint")}
              data={chainData(t("proxy.form.scopeSame"))}
              {...fields.bindSelect("scopeMe")}
              disabled={chainNode === "" || chains.isPending}
              allowDeselect={false}
            />
            <Select
              label={t("proxy.form.scopeFetch")}
              description={t("proxy.form.scopeFetchHint")}
              data={chainData(t("proxy.form.scopeSame"))}
              {...fields.bindSelect("scopeFetch")}
              disabled={chainNode === "" || chains.isPending}
              allowDeselect={false}
            />
          </SimpleGrid>
        </Stack>
        <Select
          label={t("proxy.form.useMiddleProxy")}
          description={t("proxy.form.useMiddleProxyHint")}
          data={MIDDLE_PROXY_MODES.map((mode) => ({ value: mode.value, label: t(mode.label) }))}
          allowDeselect={false}
          {...fields.bindSelect("useMiddleProxy")}
        />

        <ChangeCheckNotice saving={update.isPending} check={check} />
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending} disabled={noListeners}>
            {editing ? t("proxy.form.save") : t("proxy.form.create")}
          </Button>
          {onCancel ? (
            <Button variant="default" onClick={onCancel} disabled={pending}>
              {t("common.cancel")}
            </Button>
          ) : null}
        </Group>
      </Stack>
    </form>
  );
}
