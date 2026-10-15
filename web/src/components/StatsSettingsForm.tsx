import { Code, ConnectError } from "@connectrpc/connect";
import { Alert, Badge, Button, Group, Paper, Radio, SimpleGrid, Stack, Table, Text, Textarea, TextInput, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useNodes } from "../api/hooks/nodes";
import { useStatsSettings, useUpdateStatsSettings } from "../api/hooks/settings";
import { notifySuccess } from "../app/notify";
import {
  deletionsFor,
  IP_POLICIES,
  isIpPolicy,
  parseStatsForm,
  type STATS_LIMITS,
  type StatsErrors,
  type StatsForm,
  type StatsSettingsValue,
} from "../app/statsSettings";
import type { GetStatsSettingsResponse, PanelAddress } from "../gen/postern/panel/v1/settings_pb";
import { ConfirmDialog } from "./ConfirmDialog";
import { QueryView } from "./QueryView";

/** Settings: how long the statistics are kept, the IP policy, and the probes of the panel. */
export function StatsSettingsForm() {
  const { t } = useTranslation();
  const titleId = useId();
  const settings = useStatsSettings();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("insights.settings.stats.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="sm">
        {t("insights.settings.stats.intro")}
      </Text>
      <QueryView query={settings}>{(data) => <Editor stored={data} />}</QueryView>
    </Paper>
  );
}

function formOf(stored: GetStatsSettingsResponse): StatsForm {
  const s = stored.settings;
  return {
    minutesHours: String(s?.minutesHours ?? 48),
    hoursDays: String(s?.hoursDays ?? 90),
    ipDays: String(s?.ipDays ?? 7),
    probeIntervalMinutes: String(s?.probeIntervalMinutes ?? 5),
    ipPolicy: isIpPolicy(s?.ipPolicy ?? "") ? (s?.ipPolicy as StatsForm["ipPolicy"]) : "countries",
    extraProbeSources: (s?.extraProbeSources ?? []).join("\n"),
  };
}

function Editor({ stored }: { stored: GetStatsSettingsResponse }) {
  const { t } = useTranslation();
  const update = useUpdateStatsSettings();
  const [form, setForm] = useState<StatsForm>(() => formOf(stored));
  const [submitted, setSubmitted] = useState(false);
  const [pending, setPending] = useState<StatsSettingsValue | null>(null);
  const [refusal, setRefusal] = useState<{ message: string; refused: boolean } | null>(null);
  const storedPolicy = stored.settings?.ipPolicy ?? "countries";

  const { settings, errors } = parseStatsForm(form);
  const shown = (field: keyof StatsErrors) => (submitted ? errors[field] : undefined);
  const rangeError = (field: keyof typeof STATS_LIMITS) => {
    const error = shown(field);
    return error !== undefined && "min" in error ? t("insights.settings.stats.range", error) : undefined;
  };
  const sourcesError = (() => {
    const error = shown("extraProbeSources");
    if (error === undefined || !("invalid" in error || "tooMany" in error)) return undefined;
    return "invalid" in error
      ? t("insights.settings.stats.extraSourceInvalid", { value: error.invalid })
      : t("insights.settings.stats.extraTooMany", { max: error.tooMany });
  })();
  const set = (field: keyof StatsForm) => (value: string) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const deletions = deletionsFor(storedPolicy, pending?.ipPolicy ?? storedPolicy);
  const confirmMessage = [
    deletions.ipHistory ? t("insights.settings.stats.confirm.ipHistory") : "",
    deletions.countryHistory ? t("insights.settings.stats.confirm.countryHistory") : "",
  ]
    .filter((line) => line !== "")
    .join(" ");

  function submit() {
    if (update.isPending) return;
    setSubmitted(true);
    if (settings === null) return;
    const next = deletionsFor(storedPolicy, settings.ipPolicy);
    if (next.ipHistory || next.countryHistory) {
      setPending(settings);
      return;
    }
    void send(settings);
  }

  async function send(value: StatsSettingsValue) {
    setPending(null);
    setRefusal(null);
    try {
      await update.mutateAsync(value);
      notifySuccess(t("insights.settings.stats.saved"));
    } catch (error) {
      // INVALID_ARGUMENT is a refusal of the values; anything else, a failure of the panel or the network.
      setRefusal({ message: errorMessage(error), refused: error instanceof ConnectError && error.code === Code.InvalidArgument });
    }
  }

  const numberField = (field: keyof typeof STATS_LIMITS, label: string, hint: string) => (
    <TextInput
      label={label}
      description={hint}
      inputMode="numeric"
      value={form[field]}
      onChange={(event) => {
        set(field)(event.currentTarget.value);
      }}
      error={rangeError(field)}
    />
  );

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <Stack gap="md">
        <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
          {numberField("minutesHours", t("insights.settings.stats.minutesHours"), t("insights.settings.stats.minutesHoursHint"))}
          {numberField("hoursDays", t("insights.settings.stats.hoursDays"), t("insights.settings.stats.hoursDaysHint"))}
          {numberField("ipDays", t("insights.settings.stats.ipDays"), t("insights.settings.stats.ipDaysHint"))}
        </SimpleGrid>
        <Radio.Group
          label={t("insights.settings.stats.ipPolicy")}
          description={t("insights.settings.stats.privacy")}
          value={form.ipPolicy}
          onChange={(value) => {
            if (isIpPolicy(value)) setForm((current) => ({ ...current, ipPolicy: value }));
          }}
        >
          <Stack gap="xs" mt="xs">
            {IP_POLICIES.map((policy) => (
              <Radio key={policy} value={policy} label={t(`insights.settings.stats.policy.${policy}`)} />
            ))}
          </Stack>
        </Radio.Group>
        {numberField(
          "probeIntervalMinutes",
          t("insights.settings.stats.probeInterval"),
          t("insights.settings.stats.probeIntervalHint"),
        )}
        <Textarea
          label={t("insights.settings.stats.extraSources")}
          description={t("insights.settings.stats.extraSourcesHint")}
          autosize
          minRows={2}
          value={form.extraProbeSources}
          onChange={(event) => {
            set("extraProbeSources")(event.currentTarget.value);
          }}
          error={sourcesError}
          styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
        />
        <PanelAddresses addresses={stored.panelAddresses} />
        {refusal !== null ? (
          <Alert
            color="red"
            role="alert"
            title={refusal.refused ? t("insights.settings.stats.refused") : t("insights.settings.stats.saveFailed")}
          >
            {refusal.message}
          </Alert>
        ) : null}
        <Group>
          <Button type="submit" loading={update.isPending}>
            {t("insights.settings.stats.save")}
          </Button>
        </Group>
      </Stack>
      <ConfirmDialog
        opened={pending !== null}
        title={t("insights.settings.stats.confirm.title")}
        message={confirmMessage}
        confirmLabel={t("insights.settings.stats.confirm.confirm")}
        loading={update.isPending}
        onConfirm={() => {
          if (pending !== null) void send(pending);
        }}
        onClose={() => {
          setPending(null);
        }}
      />
    </form>
  );
}

/**
 * The addresses that the nodes see the panel come from, which they exempt from the
 * limits of their proxies. A shared one (private, CGNAT) lets everyone behind it
 * through, and each says so.
 */
function PanelAddresses({ addresses }: { addresses: readonly PanelAddress[] }) {
  const { t } = useTranslation();
  const nodes = useNodes();
  const nodeName = (id: string) => nodes.data?.find((node) => node.id === id)?.name ?? id;
  return (
    <Stack gap="xs">
      <div>
        <Text size="sm" fw={500}>
          {t("insights.settings.stats.panelAddresses")}
        </Text>
        <Text size="xs" c="dimmed">
          {t("insights.settings.stats.panelAddressesHint")}
        </Text>
      </div>
      {addresses.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.settings.stats.noPanelAddresses")}
        </Text>
      ) : (
        <Table verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("insights.settings.stats.node")}</Table.Th>
              <Table.Th>{t("insights.settings.stats.address")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {addresses.map((address) => (
              <Table.Tr key={`${address.nodeId} ${address.addr}`}>
                <Table.Td>{nodeName(address.nodeId)}</Table.Td>
                <Table.Td>
                  <Stack gap={4}>
                    <Text size="sm" ff="monospace">
                      {address.addr}
                    </Text>
                    {address.shared ? (
                      <Badge color="orange" variant="light" style={{ textTransform: "none", whiteSpace: "normal", height: "auto" }}>
                        {t("insights.settings.stats.shared")}
                      </Badge>
                    ) : null}
                  </Stack>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Stack>
  );
}
