import { ActionIcon, Badge, Button, Group, Modal, Paper, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { type ReactNode, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useChains, useDeleteChain, useDeleteEgress, useEgresses, useRefreshSubscription } from "../api/hooks/egress";
import { useNodes } from "../api/hooks/nodes";
import { egressSummary, isExperimental, kindLabel } from "../app/egress";
import { notifySuccess } from "../app/notify";
import type { Chain, Egress as EgressRecord } from "../gen/postern/panel/v1/egress_pb";
import { ChainEditor } from "../components/ChainEditor";
import { type ChangeCheck, ChangeCheckNotice } from "../components/ChangeCheckNotice";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EgressForm } from "../components/EgressForm";
import { EditIcon, PlusIcon, RefreshIcon, TrashIcon } from "../components/icons";
import { QueryView } from "../components/QueryView";

/**
 * The egresses, the ways out to Telegram, and the chains that put them in the
 * order that the edge tries them, with the dialogs that add, change and delete
 * them. Which chain a node and a proxy use is set on their own pages.
 */
export function Egress() {
  const { t } = useTranslation();
  return (
    <Stack gap="lg">
      <Stack gap={4}>
        <Title order={1}>{t("egress.title")}</Title>
        <Text size="sm" c="dimmed" maw={760}>
          {t("egress.intro")}
        </Text>
      </Stack>
      <EgressesSection />
      <ChainsSection />
    </Stack>
  );
}

/** The name of the node of an egress or a chain, or "every node". */
function useNodeName() {
  const { t } = useTranslation();
  const nodes = useNodes();
  return (nodeId: string) =>
    nodeId === "" ? t("egress.everyNode") : (nodes.data?.find((node) => node.id === nodeId)?.name ?? nodeId);
}

function EgressesSection() {
  const { t } = useTranslation();
  const titleId = useId();
  const egresses = useEgresses();
  const chains = useChains();
  const nodeName = useNodeName();
  const remove = useDeleteEgress();
  const refresh = useRefreshSubscription();
  // The dialog keeps the egress it was opened for while it closes.
  const [form, setForm] = useState<{ opened: boolean; egress?: EgressRecord }>({ opened: false });
  const [deleting, setDeleting] = useState<{ opened: boolean; egress?: EgressRecord }>({ opened: false });
  // The checks that the panel made before the last saved change of an egress, linked here since the form closes.
  const [changeCheck, setChangeCheck] = useState<ChangeCheck>(null);
  const chainName = (id: string) => chains.data?.find((chain) => chain.id === id)?.name ?? id;

  async function confirmDelete() {
    if (deleting.egress === undefined) {
      return;
    }
    try {
      await remove.mutateAsync(deleting.egress.id);
    } catch {
      return; // the query client has shown why, for example that a chain has it
    }
    notifySuccess(t("egress.delete.done"));
    setDeleting((current) => ({ ...current, opened: false }));
  }

  async function fetchAgain(egress: EgressRecord) {
    try {
      const answer = await refresh.mutateAsync(egress.id);
      notifySuccess(answer.nodeIds.length > 0 ? t("egress.refreshed") : t("egress.refreshedNone"));
    } catch {
      // the query client has shown why
    }
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="md" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("egress.egresses")}
        </Title>
        <Button
          size="xs"
          leftSection={<PlusIcon />}
          onClick={() => {
            setForm({ opened: true });
          }}
        >
          {t("egress.add")}
        </Button>
      </Group>
      <ChangeCheckNotice saving={false} check={changeCheck} />
      <QueryView query={egresses}>
        {(list) =>
          list.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("egress.empty")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={760}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("egress.columns.name")}</Table.Th>
                    <Table.Th>{t("egress.columns.kind")}</Table.Th>
                    <Table.Th>{t("egress.columns.node")}</Table.Th>
                    <Table.Th>{t("egress.columns.details")}</Table.Th>
                    <Table.Th>{t("egress.columns.chains")}</Table.Th>
                    <Table.Th>{t("egress.columns.actions")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {list.map((egress) => (
                    <Table.Tr key={egress.id}>
                      <Table.Td>{egress.name}</Table.Td>
                      <Table.Td>
                        <Group gap="xs" wrap="nowrap">
                          <span>{kindLabel(t, egress.kind)}</span>
                          {isExperimental(egress.kind) ? (
                            <Tooltip label={t("egress.experimentalHint")} multiline maw={300} withArrow>
                              <Badge variant="light" color="yellow" size="sm" style={{ cursor: "help" }} tabIndex={0}>
                                {t("egress.experimental")}
                              </Badge>
                            </Tooltip>
                          ) : null}
                        </Group>
                      </Table.Td>
                      <Table.Td>{nodeName(egress.nodeId)}</Table.Td>
                      <Table.Td>
                        <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>
                          {egressSummary(t, egress) || "—"}
                        </Text>
                      </Table.Td>
                      <Table.Td>{egress.chainIds.length === 0 ? "—" : egress.chainIds.map(chainName).join(", ")}</Table.Td>
                      <Table.Td>
                        <Group gap={4} wrap="nowrap">
                          <RowAction
                            label={t("egress.edit", { name: egress.name })}
                            onClick={() => {
                              setForm({ opened: true, egress });
                            }}
                          >
                            <EditIcon />
                          </RowAction>
                          {egress.kind === "xray-subscription" ? (
                            <RowAction
                              label={t("egress.refresh", { name: egress.name })}
                              loading={refresh.isPending && refresh.variables === egress.id}
                              onClick={() => {
                                void fetchAgain(egress);
                              }}
                            >
                              <RefreshIcon />
                            </RowAction>
                          ) : null}
                          <RowAction
                            label={t("egress.delete.action", { name: egress.name })}
                            color="red"
                            onClick={() => {
                              setDeleting({ opened: true, egress });
                            }}
                          >
                            <TrashIcon />
                          </RowAction>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
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
        title={form.egress === undefined ? t("egress.addTitle") : t("egress.editTitle")}
        size="lg"
        centered
      >
        <EgressForm
          key={form.egress?.id ?? "new"}
          egress={form.egress}
          onDone={(_egress, beforeRunIds) => {
            setChangeCheck(beforeRunIds === undefined || Object.keys(beforeRunIds).length === 0 ? null : { nodes: true, beforeRuns: beforeRunIds });
            setForm((current) => ({ ...current, opened: false }));
          }}
          onCancel={() => {
            setForm((current) => ({ ...current, opened: false }));
          }}
        />
      </Modal>

      <ConfirmDialog
        opened={deleting.opened}
        title={t("egress.delete.title")}
        message={t("egress.delete.message", { name: deleting.egress?.name ?? "" })}
        confirmLabel={t("egress.delete.confirm")}
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

function ChainsSection() {
  const { t } = useTranslation();
  const titleId = useId();
  const chains = useChains();
  const egresses = useEgresses();
  const nodeName = useNodeName();
  const remove = useDeleteChain();
  const [form, setForm] = useState<{ opened: boolean; chain?: Chain }>({ opened: false });
  const [deleting, setDeleting] = useState<{ opened: boolean; chain?: Chain }>({ opened: false });
  /**
   * A member of a chain as the table names it: Psiphon is marked experimental
   * in words. An egress that is not in the list is gone only when the list is
   * there: while it cannot be had, the id stands in for the name.
   */
  const egressName = (id: string) => {
    const egress = egresses.data?.find((entry) => entry.id === id);
    if (egress === undefined) {
      return egresses.isSuccess ? t("chain.form.missing") : id;
    }
    return isExperimental(egress.kind) ? `${egress.name} (${t("egress.experimental")})` : egress.name;
  };

  async function confirmDelete() {
    if (deleting.chain === undefined) {
      return;
    }
    try {
      await remove.mutateAsync(deleting.chain.id);
    } catch {
      return; // the query client has shown why, for example that a node uses it
    }
    notifySuccess(t("chain.delete.done"));
    setDeleting((current) => ({ ...current, opened: false }));
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="md" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("chain.title")}
        </Title>
        <Button
          size="xs"
          leftSection={<PlusIcon />}
          onClick={() => {
            setForm({ opened: true });
          }}
        >
          {t("chain.add")}
        </Button>
      </Group>
      <QueryView query={chains}>
        {(list) =>
          list.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("chain.empty")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={680}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("chain.columns.name")}</Table.Th>
                    <Table.Th>{t("chain.columns.node")}</Table.Th>
                    <Table.Th>{t("chain.columns.members")}</Table.Th>
                    <Table.Th>{t("chain.columns.usedBy")}</Table.Th>
                    <Table.Th>{t("chain.columns.actions")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {list.map((chain) => (
                    <Table.Tr key={chain.id}>
                      <Table.Td>{chain.name}</Table.Td>
                      <Table.Td>{nodeName(chain.nodeId)}</Table.Td>
                      <Table.Td>{chain.memberIds.map(egressName).join(" → ")}</Table.Td>
                      <Table.Td>
                        {chain.defaultOf.length === 0 && chain.proxyIds.length === 0 ? (
                          <Text size="sm" c="dimmed">
                            {t("chain.unused")}
                          </Text>
                        ) : (
                          <Stack gap={0}>
                            {chain.defaultOf.length > 0 ? (
                              <Text size="sm">{t("chain.usedByNodes", { count: chain.defaultOf.length })}</Text>
                            ) : null}
                            {chain.proxyIds.length > 0 ? (
                              <Text size="sm">{t("chain.usedByProxies", { count: chain.proxyIds.length })}</Text>
                            ) : null}
                          </Stack>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} wrap="nowrap">
                          <RowAction
                            label={t("chain.edit", { name: chain.name })}
                            onClick={() => {
                              setForm({ opened: true, chain });
                            }}
                          >
                            <EditIcon />
                          </RowAction>
                          <RowAction
                            label={t("chain.delete.action", { name: chain.name })}
                            color="red"
                            onClick={() => {
                              setDeleting({ opened: true, chain });
                            }}
                          >
                            <TrashIcon />
                          </RowAction>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
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
        title={form.chain === undefined ? t("chain.addTitle") : t("chain.editTitle")}
        size="lg"
        centered
      >
        <ChainEditor
          key={form.chain?.id ?? "new"}
          chain={form.chain}
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
        title={t("chain.delete.title")}
        message={t("chain.delete.message", { name: deleting.chain?.name ?? "" })}
        confirmLabel={t("chain.delete.confirm")}
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

function RowAction({
  label,
  color = "gray",
  loading = false,
  onClick,
  children,
}: {
  label: string;
  color?: string;
  loading?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Tooltip label={label}>
      <ActionIcon variant="subtle" color={color} aria-label={label} loading={loading} onClick={onClick}>
        {children}
      </ActionIcon>
    </Tooltip>
  );
}
