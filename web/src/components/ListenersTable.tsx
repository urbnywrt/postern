import { ActionIcon, Button, Group, Modal, Paper, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { useId, useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";

import { useDeleteListener, useListeners } from "../api/hooks/listeners";
import { notifySuccess } from "../app/notify";
import type { Listener } from "../gen/postern/panel/v1/proxies_pb";
import { ConfirmDialog } from "./ConfirmDialog";
import { EditIcon, PlusIcon, TrashIcon } from "./icons";
import { ListenerForm } from "./ListenerForm";
import { QueryView } from "./QueryView";

const address = (listener: Listener) => `${listener.bindIp}:${String(listener.port)}`;

/** The listeners of a node, with the dialogs that add, change and delete them. */
export function ListenersTable({ nodeId }: { nodeId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const listeners = useListeners(nodeId);
  const remove = useDeleteListener();
  // The dialog keeps the listener it was opened for while it closes, so that it does
  // not turn into the form of a new one for the length of its exit.
  const [form, setForm] = useState<{ opened: boolean; listener?: Listener }>({ opened: false });
  const [deleting, setDeleting] = useState<{ opened: boolean; listener?: Listener }>({ opened: false });

  async function confirmDelete() {
    if (deleting.listener === undefined) {
      return;
    }
    try {
      await remove.mutateAsync(deleting.listener.id);
    } catch {
      return; // the query client has shown why, for example that proxies still use it
    }
    notifySuccess(t("listeners.delete.done"));
    setDeleting((current) => ({ ...current, opened: false }));
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="md" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("listeners.title")}
        </Title>
        <Button
          size="xs"
          leftSection={<PlusIcon />}
          onClick={() => {
            setForm({ opened: true });
          }}
        >
          {t("listeners.add")}
        </Button>
      </Group>

      <QueryView query={listeners}>
        {(list) =>
          list.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("listeners.empty")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={640}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("listeners.columns.address")}</Table.Th>
                    <Table.Th>{t("listeners.columns.linkHost")}</Table.Th>
                    <Table.Th>{t("listeners.columns.strangers")}</Table.Th>
                    <Table.Th>{t("listeners.columns.nonTls")}</Table.Th>
                    <Table.Th>{t("listeners.columns.actions")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {list.map((listener) => (
                    <ListenerRow
                      key={listener.id}
                      listener={listener}
                      onEdit={() => {
                        setForm({ opened: true, listener });
                      }}
                      onDelete={() => {
                        setDeleting({ opened: true, listener });
                      }}
                    />
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </QueryView>

      <Modal
        opened={form.opened}
        onClose={() => {
          setForm((current) => ({ ...current, opened: false }));
        }}
        title={form.listener === undefined ? t("listeners.addTitle") : t("listeners.editTitle")}
        size="lg"
        centered
      >
        <ListenerForm
          nodeId={nodeId}
          listener={form.listener}
          onDone={() => {
            setForm((current) => ({ ...current, opened: false }));
          }}
          onCancel={() => {
            setForm((current) => ({ ...current, opened: false }));
          }}
        />
      </Modal>

      <ConfirmDialog
        opened={deleting.opened}
        title={t("listeners.delete.title")}
        message={t("listeners.delete.message", { address: deleting.listener ? address(deleting.listener) : "" })}
        confirmLabel={t("listeners.delete.confirm")}
        loading={remove.isPending}
        onConfirm={() => {
          void confirmDelete();
        }}
        onClose={() => {
          setDeleting((current) => ({ ...current, opened: false }));
        }}
      />
    </Paper>
  );
}

function ListenerRow({ listener, onEdit, onDelete }: { listener: Listener; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation();
  return (
    <Table.Tr>
      <Table.Td>
        <Stack gap={0}>
          <Text size="sm">{address(listener)}</Text>
          {listener.kind === "http-upstream" ? (
            <Text size="xs" c="dimmed">
              {t("listener.kind.http-upstream")}
            </Text>
          ) : null}
        </Stack>
      </Table.Td>
      <Table.Td>{listener.linkHostOverride === "" ? "—" : listener.linkHostOverride}</Table.Td>
      <Table.Td>
        <Stack gap={0}>
          <Text size="sm">{strangerLabel(listener.strangerAction, t)}</Text>
          {listener.strangerAction === "mask" && listener.maskTarget !== "" ? (
            <Text size="xs" c="dimmed">
              {listener.maskTarget}
            </Text>
          ) : null}
        </Stack>
      </Table.Td>
      <Table.Td>{nonTlsLabel(listener.nonTlsAction, t)}</Table.Td>
      <Table.Td>
        <Group gap={4} wrap="nowrap">
          <Tooltip label={t("listeners.edit", { address: address(listener) })}>
            <ActionIcon variant="subtle" color="gray" aria-label={t("listeners.edit", { address: address(listener) })} onClick={onEdit}>
              <EditIcon />
            </ActionIcon>
          </Tooltip>
          <Tooltip label={t("listeners.delete.action", { address: address(listener) })}>
            <ActionIcon
              variant="subtle"
              color="red"
              aria-label={t("listeners.delete.action", { address: address(listener) })}
              onClick={onDelete}
            >
              <TrashIcon />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Table.Td>
    </Table.Tr>
  );
}

type Translate = TFunction;

/** What a listener does with an unknown server name; a value of a newer panel is shown as it is. */
function strangerLabel(action: string, t: Translate): string {
  switch (action) {
    case "mask":
      return t("listeners.strangerShort.mask");
    case "reject":
      return t("listeners.strangerShort.reject");
    case "drop":
      return t("listeners.strangerShort.drop");
    default:
      return action;
  }
}

function nonTlsLabel(action: string, t: Translate): string {
  switch (action) {
    case "drop":
      return t("listeners.nonTlsShort.drop");
    case "http400":
      return t("listeners.nonTlsShort.http400");
    default:
      return action;
  }
}
