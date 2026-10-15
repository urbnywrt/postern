import { Accordion, Alert, Badge, Button, Group, Select, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import {
  type EgressParamsVars,
  type UpdateEgressVars,
  useCreateEgress,
  useUpdateEgress,
  useValidateEgress,
} from "../api/hooks/egress";
import { useNodes } from "../api/hooks/nodes";
import {
  countryName,
  EGRESS_KINDS,
  isEgressKind,
  isExperimental,
  KIND_FIELDS,
  kindLabel,
  PSIPHON_COUNTRIES,
} from "../app/egress";
import { notifySuccess } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import {
  validateHostPort,
  validateInterface,
  validateNodeName,
  validatePartnerId,
  validateProxyPassword,
  validateProxyUsername,
  validateSelectName,
  validateSourceIp,
  validateStoredPassword,
  validateSubscriptionUrl,
} from "../app/validators";
import type { Egress, ValidateEgressResponse } from "../gen/postern/panel/v1/egress_pb";
import { ChangeCheckNotice } from "./ChangeCheckNotice";
import { PasswordField } from "./PasswordField";

interface Values {
  name: string;
  kind: string;
  /** Empty for an egress that every node can use. */
  nodeId: string;
  interface: string;
  bindIp: string;
  addr: string;
  username: string;
  password: string;
  uri: string;
  url: string;
  /** all, first or name; name takes selectText. */
  select: string;
  selectText: string;
  country: string;
  /** The Psiphon partner ids of a psiphon egress: both or neither. */
  propagationChannelId: string;
  sponsorId: string;
}

/** The value of the node field for "every node": a Select has no empty value. */
const EVERY_NODE = "*";

function initialOf(egress: Egress | undefined): Values {
  const p = egress?.params;
  const select = p?.select ?? "";
  const byName = select.startsWith("name:");
  return {
    name: egress?.name ?? "",
    kind: egress?.kind ?? "",
    nodeId: egress?.nodeId ?? "",
    interface: p?.interface ?? "",
    bindIp: p?.bindIp ?? "",
    addr: p?.addr ?? "",
    username: p?.username ?? "",
    // The secrets are never sent to the browser: they are typed anew, or kept.
    password: "",
    uri: "",
    url: "",
    select: byName ? "name" : select === "first" ? "first" : "all",
    selectText: byName ? select.slice("name:".length) : "",
    country: p?.country ?? "",
    propagationChannelId: p?.propagationChannelId ?? "",
    sponsorId: p?.sponsorId ?? "",
  };
}

/** Whether an egress of the kind of the values has a parameter. */
function has(values: Values, field: keyof EgressParamsVars): boolean {
  return isEgressKind(values.kind) && KIND_FIELDS[values.kind].includes(field);
}

/** The parameters that the values give: those of their kind, the others empty. */
function paramsOf(v: Values): EgressParamsVars {
  return {
    interface: has(v, "interface") ? v.interface.trim() : "",
    bindIp: has(v, "bindIp") ? v.bindIp.trim() : "",
    addr: has(v, "addr") ? v.addr.trim() : "",
    username: has(v, "username") ? v.username : "",
    password: has(v, "password") ? v.password : "",
    uri: has(v, "uri") ? v.uri.trim() : "",
    url: has(v, "url") ? v.url.trim() : "",
    select: has(v, "select") ? (v.select === "name" ? `name:${v.selectText.trim()}` : v.select) : "",
    country: has(v, "country") ? v.country : "",
    propagationChannelId: has(v, "propagationChannelId") ? v.propagationChannelId.trim().toUpperCase() : "",
    sponsorId: has(v, "sponsorId") ? v.sponsorId.trim().toUpperCase() : "",
  };
}

const sameParams = (a: EgressParamsVars, b: EgressParamsVars) =>
  (Object.keys(a) as (keyof EgressParamsVars)[]).every((key) => a[key] === b[key]);

/**
 * A 53-bit hash of a text (cyrb53). The form tells by it whether the verdict
 * of the panel is still about the parameters that it has, so that it does not
 * keep another copy of the secrets that were typed.
 */
function fingerprint(text: string): number {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ code, 2654435761);
    h2 = Math.imul(h2 ^ code, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

interface EgressFormProps {
  /** The egress whose name and parameters are edited; left out, the form makes a new one. */
  egress?: Egress;
  /** Called once saved, with the checks that the panel made before the change, by node (none for a new egress). */
  onDone: (egress: Egress, beforeRunIds?: Record<string, string>) => void;
  onCancel?: () => void;
}

/**
 * The form of an egress: its name, its kind and its node (fixed once it is
 * made), and the parameters of its kind. The secrets (a password, a share link,
 * the URL of a subscription) are never shown again once they are sent: the
 * form of an egress that exists says what is stored of them, and keeps it when
 * the field is left empty. "Check" asks the panel whether it takes the
 * parameters, without storing anything.
 */
export function EgressForm({ egress, onDone, onCancel }: EgressFormProps) {
  const { t, i18n } = useTranslation();
  const editing = egress !== undefined;
  const create = useCreateEgress();
  const update = useUpdateEgress();
  const check = useValidateEgress();
  const pending = create.isPending || update.isPending;
  // What the form started from, and then what it last saved: only what differs
  // from it goes to the panel.
  const [baseline, setBaseline] = useState(egress);
  const [checking, setChecking] = useState(false);
  const form = useFormState<Values>(initialOf(egress));
  const { values } = form;
  const nodes = useNodes();
  // The verdict of the panel, for the parameters that it was asked about (by
  // their hash): it is shown while the form still has them.
  const [verdict, setVerdict] = useState<{ asked: number; answer: ValidateEgressResponse }>();
  const asked = fingerprint(JSON.stringify({ kind: values.kind, params: paramsOf(values) }));

  const fields = form.check(validate(values));

  function validate(v: Values): FieldErrors<Values> {
    // What is stored of the password of a proxy, which an empty one keeps.
    const stored = baseline && { addr: baseline.params?.addr ?? "", username: baseline.params?.username ?? "", passwordSet: baseline.passwordSet };
    return {
      name: validateNodeName(v.name),
      kind: v.kind === "" ? "required" : null,
      interface: has(v, "interface") ? validateInterface(v.interface) : null,
      bindIp: has(v, "bindIp") ? validateSourceIp(v.bindIp) : null,
      addr: has(v, "addr") ? validateHostPort(v.addr) : null,
      username: has(v, "username") ? validateProxyUsername(v.kind, v.username) : null,
      password: has(v, "password")
        ? (validateProxyPassword(v.kind, v.username, v.password) ?? validateStoredPassword(stored, v.addr, v.username, v.password))
        : null,
      uri: has(v, "uri") && !editing && v.uri.trim() === "" ? "required" : null,
      url: has(v, "url") ? validateSubscriptionUrl(v.url, !editing) : null,
      selectText: has(v, "select") && v.select === "name" ? validateSelectName(v.selectText) : null,
      country: has(v, "country") && v.country === "" ? "required" : null,
      propagationChannelId: has(v, "propagationChannelId") ? validatePartnerId(v.propagationChannelId, v.sponsorId) : null,
      sponsorId: has(v, "sponsorId") ? validatePartnerId(v.sponsorId, v.propagationChannelId) : null,
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
    try {
      if (baseline === undefined) {
        const created = await create.mutateAsync({
          name: values.name.trim(),
          kind: values.kind,
          nodeId: values.nodeId,
          params: paramsOf(values),
        });
        // The form may stay on the screen, and the mutation would keep the secrets it was sent with.
        create.reset();
        onDone(created);
        return;
      }
      const changes: UpdateEgressVars = { id: baseline.id };
      if (values.name.trim() !== baseline.name) changes.name = values.name.trim();
      const params = paramsOf(values);
      if (!sameParams(params, paramsOf(initialOf(baseline)))) changes.params = params;
      if (Object.keys(changes).length === 1) {
        onDone(baseline);
        return;
      }
      // The panel checks every node that uses the egress before it saves the change.
      setChecking(changes.params !== undefined);
      const { egress: updated, beforeRunIds } = await update.mutateAsync(changes).finally(() => {
        setChecking(false);
      });
      update.reset();
      setBaseline(updated);
      for (const secret of ["password", "uri", "url"] as const) {
        form.set(secret, "");
      }
      notifySuccess(t("egress.form.saved"));
      onDone(updated, beforeRunIds);
    } catch {
      // The query client has shown why, and the form keeps what was typed.
    }
  }

  async function runCheck() {
    try {
      const answer = await check.mutateAsync({ kind: values.kind, params: paramsOf(values), id: baseline?.id ?? "" });
      setVerdict({ asked, answer });
    } catch {
      setVerdict(undefined); // the query client has shown why
    } finally {
      check.reset();
    }
  }

  const kindData = EGRESS_KINDS.map((kind) => ({ value: kind, label: kindLabel(t, kind) }));
  const nodeData = [
    { value: EVERY_NODE, label: t("egress.everyNode") },
    ...(nodes.data ?? []).map((node) => ({ value: node.id, label: node.name })),
  ];
  const countryData = PSIPHON_COUNTRIES.map((code) => ({ value: code, label: `${countryName(code, i18n.language)} (${code})` }));
  const shown = verdict?.asked === asked ? verdict.answer : undefined;

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Stack gap="sm">
        <TextInput label={t("egress.form.name")} autoComplete="off" {...fields.bind("name")} />
        <Select
          label={t("egress.form.kind")}
          data={kindData}
          {...fields.bindSelect("kind")}
          disabled={editing}
          allowDeselect={false}
        />
        <Select
          label={t("egress.form.node")}
          description={t("egress.form.nodeHint")}
          data={nodeData}
          value={values.nodeId === "" ? EVERY_NODE : values.nodeId}
          onChange={(value) => {
            form.set("nodeId", value === null || value === EVERY_NODE ? "" : value);
          }}
          disabled={editing}
          error={nodes.isError ? errorMessage(nodes.error) : undefined}
          allowDeselect={false}
        />

        {has(values, "interface") ? (
          <>
            <TextInput
              label={t("egress.form.interface")}
              description={t("egress.form.interfaceHint")}
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("interface")}
            />
            <TextInput
              label={t("egress.form.bindIp")}
              description={t("egress.form.bindIpHint")}
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("bindIp")}
            />
          </>
        ) : null}

        {has(values, "addr") ? (
          <>
            <TextInput
              label={t("egress.form.addr")}
              description={t("egress.form.addrHint")}
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("addr")}
            />
            <TextInput label={t("egress.form.username")} autoComplete="off" spellCheck={false} {...fields.bind("username")} />
            <PasswordField
              label={t("egress.form.password")}
              description={baseline?.passwordSet ? t("egress.form.passwordKept") : undefined}
              autoComplete="new-password"
              {...fields.bind("password")}
            />
          </>
        ) : null}

        {has(values, "uri") ? (
          <Textarea
            label={t("egress.form.uri")}
            description={
              baseline !== undefined && baseline.masked !== ""
                ? t("egress.form.uriKept", { masked: baseline.masked })
                : t("egress.form.uriHint")
            }
            autosize
            minRows={2}
            maxRows={6}
            autoComplete="off"
            spellCheck={false}
            {...fields.bind("uri")}
          />
        ) : null}

        {has(values, "url") ? (
          <>
            <TextInput
              label={t("egress.form.url")}
              description={
                baseline !== undefined && baseline.masked !== ""
                  ? t("egress.form.urlKept", { masked: baseline.masked })
                  : t("egress.form.urlHint")
              }
              autoComplete="off"
              spellCheck={false}
              {...fields.bind("url")}
            />
            <Select
              label={t("egress.form.select")}
              data={[
                { value: "all", label: t("egress.form.selectAll") },
                { value: "first", label: t("egress.form.selectFirst") },
                { value: "name", label: t("egress.form.selectName") },
              ]}
              {...fields.bindSelect("select")}
              allowDeselect={false}
            />
            {values.select === "name" ? (
              <TextInput label={t("egress.form.selectText")} autoComplete="off" {...fields.bind("selectText")} />
            ) : null}
          </>
        ) : null}

        {values.kind === "warp" ? (
          <Text size="sm" c="dimmed">
            {t("egress.form.warpHint")}
          </Text>
        ) : null}

        {has(values, "country") ? (
          <Select label={t("egress.form.country")} data={countryData} searchable {...fields.bindSelect("country")} />
        ) : null}

        {has(values, "propagationChannelId") ? (
          <Accordion variant="contained" defaultValue={values.propagationChannelId !== "" ? "partner" : null}>
            <Accordion.Item value="partner">
              <Accordion.Control>{t("egress.form.partner")}</Accordion.Control>
              <Accordion.Panel>
                <Stack gap="sm">
                  <Text size="sm" c="dimmed">
                    {t("egress.form.partnerHint")}
                  </Text>
                  <TextInput
                    label={t("egress.form.propagationChannelId")}
                    placeholder="FFFFFFFFFFFFFFFF"
                    autoComplete="off"
                    spellCheck={false}
                    {...fields.bind("propagationChannelId")}
                  />
                  <TextInput
                    label={t("egress.form.sponsorId")}
                    placeholder="FFFFFFFFFFFFFFFF"
                    autoComplete="off"
                    spellCheck={false}
                    {...fields.bind("sponsorId")}
                  />
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          </Accordion>
        ) : null}

        {isExperimental(values.kind) ? (
          <Alert color="yellow" title={<Badge color="yellow" variant="light">{t("egress.experimental")}</Badge>}>
            {t("egress.experimentalHint")}
          </Alert>
        ) : null}

        {shown === undefined ? null : shown.valid ? (
          <Alert color="teal" role="status">
            <Stack gap={4}>
              <Text size="sm">{t("egress.form.valid")}</Text>
              {shown.protocol !== "" ? (
                <Text size="sm">
                  {t("egress.form.validLink", {
                    protocol: shown.protocol,
                    security: shown.security,
                    network: shown.network,
                    masked: shown.masked,
                  })}
                </Text>
              ) : shown.masked !== "" ? (
                <Text size="sm">{shown.masked}</Text>
              ) : null}
              <Text size="xs" c="dimmed">
                {t("egress.form.liveHint")}
              </Text>
            </Stack>
          </Alert>
        ) : (
          <Alert color="red" role="status" title={t("egress.form.invalid")}>
            {shown.problem}
          </Alert>
        )}

        <ChangeCheckNotice saving={checking} check={checking ? { nodes: true } : null} />
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending}>
            {editing ? t("egress.form.save") : t("egress.form.create")}
          </Button>
          <Button
            variant="light"
            loading={check.isPending}
            disabled={values.kind === ""}
            onClick={() => {
              void runCheck();
            }}
          >
            {t("egress.form.check")}
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
