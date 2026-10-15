import { ActionIcon, Button, Group, Modal, Paper, Stack, Table, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useCreateDnsCredential, useDeleteDnsCredential, useDnsCredentials, useUpdateDnsCredential } from "../api/hooks/dns";
import { formatDateTime } from "../app/format";
import { notifySuccess } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import { validateRequired } from "../app/validation";
import { validateProxyName } from "../app/validators";
import type { DnsCredential } from "../gen/postern/panel/v1/dns_pb";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EditIcon, PlusIcon, TrashIcon } from "../components/icons";
import { PasswordField } from "../components/PasswordField";
import { QueryView } from "../components/QueryView";

/**
 * The DNS credentials that the nodes issue the certificates of WEB proxies
 * with. A token is written here and never shown again: the panel keeps it
 * sealed and hands it to the nodes only.
 */
export function DnsCredentials() {
  const { t } = useTranslation();
  const titleId = useId();
  const credentials = useDnsCredentials();
  const remove = useDeleteDnsCredential();
  const [form, setForm] = useState<{ opened: boolean; credential?: DnsCredential }>({ opened: false });
  const [deleting, setDeleting] = useState<{ opened: boolean; credential?: DnsCredential }>({ opened: false });

  async function confirmDelete() {
    if (deleting.credential === undefined) {
      return;
    }
    try {
      await remove.mutateAsync(deleting.credential.id);
    } catch {
      return; // the query client has shown why, for example that proxies still use it
    }
    notifySuccess(t("dns.delete.done"));
    setDeleting((current) => ({ ...current, opened: false }));
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="center" wrap="wrap">
        <Title order={1} id={titleId}>
          {t("dns.title")}
        </Title>
        <Button
          leftSection={<PlusIcon />}
          onClick={() => {
            setForm({ opened: true });
          }}
        >
          {t("dns.add")}
        </Button>
      </Group>
      <Text size="sm" c="dimmed">
        {t("dns.intro")}
      </Text>

      <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
        <QueryView query={credentials}>
          {(list) =>
            list.length === 0 ? (
              <Text size="sm" c="dimmed">
                {t("dns.empty")}
              </Text>
            ) : (
              <Table.ScrollContainer minWidth={520}>
                <Table verticalSpacing="xs">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t("dns.columns.name")}</Table.Th>
                      <Table.Th>{t("dns.columns.provider")}</Table.Th>
                      <Table.Th>{t("dns.columns.usedBy")}</Table.Th>
                      <Table.Th>{t("dns.columns.updated")}</Table.Th>
                      <Table.Th>{t("dns.columns.actions")}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {list.map((credential) => (
                      <Table.Tr key={credential.id}>
                        <Table.Td>{credential.name}</Table.Td>
                        <Table.Td>{t(`dns.provider.${credential.provider === "cloudflare" ? "cloudflare" : "other"}`)}</Table.Td>
                        <Table.Td>{t("dns.usedBy", { count: credential.usedBy })}</Table.Td>
                        <Table.Td>{formatDateTime(credential.updatedUnix)}</Table.Td>
                        <Table.Td>
                          <Group gap="xs" wrap="nowrap">
                            <Tooltip label={t("dns.edit", { name: credential.name })}>
                              <ActionIcon
                                variant="subtle"
                                aria-label={t("dns.edit", { name: credential.name })}
                                onClick={() => {
                                  setForm({ opened: true, credential });
                                }}
                              >
                                <EditIcon />
                              </ActionIcon>
                            </Tooltip>
                            <Tooltip label={t("dns.delete.action", { name: credential.name })}>
                              <ActionIcon
                                variant="subtle"
                                color="red"
                                aria-label={t("dns.delete.action", { name: credential.name })}
                                onClick={() => {
                                  setDeleting({ opened: true, credential });
                                }}
                              >
                                <TrashIcon />
                              </ActionIcon>
                            </Tooltip>
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
      </Paper>

      <Modal
        opened={form.opened}
        onClose={() => {
          setForm((current) => ({ ...current, opened: false }));
        }}
        title={form.credential === undefined ? t("dns.addTitle") : t("dns.editTitle")}
        centered
      >
        <DnsCredentialForm
          credential={form.credential}
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
        title={t("dns.delete.title")}
        message={t("dns.delete.message", { name: deleting.credential?.name ?? "" })}
        confirmLabel={t("dns.delete.confirm")}
        loading={remove.isPending}
        onConfirm={() => {
          void confirmDelete();
        }}
        onClose={() => {
          setDeleting((current) => ({ ...current, opened: false }));
        }}
      />
    </Stack>
  );
}

interface Values {
  name: string;
  token: string;
}

/**
 * The form of a credential: a name and a token. The token is write-only: the
 * form of an existing credential starts with an empty token field, and sends a
 * token only when one is typed.
 */
export function DnsCredentialForm({
  credential,
  onDone,
  onCancel,
}: {
  credential?: DnsCredential;
  onDone: (credential: DnsCredential) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const editing = credential !== undefined;
  const create = useCreateDnsCredential();
  const update = useUpdateDnsCredential();
  const pending = create.isPending || update.isPending;
  const form = useFormState<Values>({ name: credential?.name ?? "", token: "" });
  const { values } = form;
  const fields = form.check({
    name: validateRequired(values.name) ?? validateProxyName(values.name),
    token: editing ? null : validateRequired(values.token),
  } satisfies FieldErrors<Values>);

  async function submit() {
    if (pending) {
      return;
    }
    form.setSubmitted(true);
    if (!fields.valid) {
      return;
    }
    const name = values.name.trim();
    const token = values.token.trim();
    try {
      if (credential === undefined) {
        const created = await create.mutateAsync({ name, provider: "cloudflare", token });
        notifySuccess(t("dns.form.saved"));
        onDone(created);
        return;
      }
      const changes: { id: string; name?: string; token?: string } = { id: credential.id };
      if (name !== credential.name) changes.name = name;
      if (token !== "") changes.token = token;
      if (Object.keys(changes).length === 1) {
        onDone(credential);
        return;
      }
      const updated = await update.mutateAsync(changes);
      form.set("token", ""); // it went to the panel; the form does not keep it
      notifySuccess(t("dns.form.saved"));
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
        <TextInput label={t("dns.form.name")} description={t("dns.form.nameHint")} autoComplete="off" data-autofocus {...fields.bind("name")} />
        <TextInput label={t("dns.form.provider")} value={t("dns.provider.cloudflare")} readOnly />
        <PasswordField
          label={t("dns.form.token")}
          description={editing ? t("dns.form.tokenHintEdit") : t("dns.form.tokenHint")}
          autoComplete="off"
          {...fields.bind("token")}
        />
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending}>
            {editing ? t("dns.form.save") : t("dns.form.create")}
          </Button>
          <Button variant="default" onClick={onCancel} disabled={pending}>
            {t("common.cancel")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
