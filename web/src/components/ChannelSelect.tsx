import { Button, Group, List, Modal, Select, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { notifySuccess } from "../app/notify";
import type { AffectedProxy } from "../gen/postern/panel/v1/versions_pb";

/** What SetDefaultChannel and SetNodeChannel answer. */
export interface ChannelAnswer {
  affectedProxies: AffectedProxy[];
  applied: boolean;
}

interface ChannelSelectProps {
  label: string;
  value: string;
  /** The channels offered; "" is "the default of the panel" for a node. */
  options: { value: string; label: string }[];
  /** Calls the panel: without confirm it changes nothing and lists what would change (Ruling S5-11). */
  ask: (channel: string, confirm: boolean) => Promise<ChannelAnswer>;
  size?: "xs" | "sm";
}

/**
 * A select of the channel of the panel or of a node. A change is first asked
 * without confirm; when it alters the version of any proxy the dialog lists
 * them, and only its button makes the change (the same call, with confirm).
 * A change that alters no proxy is made at once.
 */
export function ChannelSelect({ label, value, options, ask, size = "sm" }: ChannelSelectProps) {
  const { t } = useTranslation();
  const [pending, setPending] = useState<{ channel: string; affected: AffectedProxy[] } | undefined>();
  const [busy, setBusy] = useState(false);

  async function apply(channel: string) {
    setBusy(true);
    try {
      const answer = await ask(channel, true);
      if (answer.applied) {
        notifySuccess(t("versions.channel.changed"));
        setPending(undefined);
      }
    } catch {
      // the query client has shown why
    } finally {
      setBusy(false);
    }
  }

  async function choose(channel: string) {
    if (channel === value) return;
    setBusy(true);
    let answer: ChannelAnswer;
    try {
      answer = await ask(channel, false);
    } catch {
      setBusy(false);
      return;
    }
    setBusy(false);
    if (answer.applied) {
      // The panel made the change already: nothing to confirm.
      notifySuccess(t("versions.channel.changed"));
      return;
    }
    if (answer.affectedProxies.length === 0) {
      await apply(channel);
      return;
    }
    setPending({ channel, affected: answer.affectedProxies });
  }

  const channelLabel = (channel: string) => options.find((o) => o.value === channel)?.label ?? channel;

  return (
    <>
      <Select
        label={label}
        size={size}
        data={options}
        value={value}
        allowDeselect={false}
        disabled={busy}
        onChange={(channel) => {
          if (channel !== null) void choose(channel);
        }}
        w={size === "xs" ? 150 : 220}
      />
      <Modal
        opened={pending !== undefined}
        onClose={() => {
          setPending(undefined);
        }}
        title={t("versions.channel.confirmTitle", { channel: channelLabel(pending?.channel ?? "") })}
        centered
        size="lg"
      >
        <Stack gap="md">
          <Text size="sm">{t("versions.channel.confirmIntro", { count: pending?.affected.length ?? 0 })}</Text>
          <List size="sm" spacing={4} aria-label={t("versions.channel.affected")}>
            {(pending?.affected ?? []).map((proxy) => (
              <List.Item key={proxy.proxyId}>
                {t("versions.channel.affectedProxy", { name: proxy.name || proxy.proxyId, from: proxy.fromVersion || "—", to: proxy.toVersion || "—" })}
              </List.Item>
            ))}
          </List>
          <Group justify="flex-end" gap="sm">
            <Button
              variant="default"
              disabled={busy}
              onClick={() => {
                setPending(undefined);
              }}
            >
              {t("common.cancel")}
            </Button>
            <Button
              loading={busy}
              onClick={() => {
                if (pending !== undefined) void apply(pending.channel);
              }}
            >
              {t("versions.channel.confirm")}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
