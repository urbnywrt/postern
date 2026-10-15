import { Button, Group, Stack, Textarea, TextInput } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { type UpdateNodeVars, useCreateNode, useUpdateNode } from "../api/hooks/nodes";
import type { CreateNodeResponse, Node } from "../gen/postern/panel/v1/nodes_pb";
import { notifySuccess } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import {
  validateHost,
  validateNodeName,
  validateNote,
  validateOptionalHost,
  validateOptionalPort,
  validatePort,
} from "../app/validators";

interface Values {
  name: string;
  mgmtHost: string;
  mgmtPort: string;
  linkHost: string;
  note: string;
}

interface NodeFormProps {
  /** The node whose settings are edited. Left out, the form adds a new node. */
  node?: Node;
  /** A node was added: the answer has the download of its bundle. */
  onCreated?: (created: CreateNodeResponse) => void;
  onSaved?: (node: Node) => void;
  onCancel: () => void;
}

/** The form of a node: adding one, or changing its name, its addresses and its note. */
export function NodeForm({ node, onCreated, onSaved, onCancel }: NodeFormProps) {
  const { t } = useTranslation();
  const editing = node !== undefined;
  const create = useCreateNode();
  const update = useUpdateNode();
  const pending = create.isPending || update.isPending;
  // What the form started from, and then what it last saved. Only what differs from it is
  // sent, so a field that was not touched cannot undo a change that somebody else made.
  const [baseline, setBaseline] = useState(node);

  const form = useFormState<Values>({
    name: node?.name ?? "",
    mgmtHost: node?.mgmtHost ?? "",
    mgmtPort: node ? String(node.mgmtPort) : "",
    linkHost: node?.linkHost ?? "",
    note: node?.note ?? "",
  });
  const { values } = form;
  const errors: FieldErrors<Values> = {
    name: validateNodeName(values.name),
    // A new node may leave its address to the join: the panel takes the one that it connects from.
    mgmtHost: editing ? validateHost(values.mgmtHost) : validateOptionalHost(values.mgmtHost),
    // A new node may leave the port to the panel, which picks a random high one.
    mgmtPort: editing ? validatePort(values.mgmtPort) : validateOptionalPort(values.mgmtPort),
    linkHost: validateOptionalHost(values.linkHost),
    note: validateNote(values.note),
  };
  const fields = form.check(errors);

  async function submit() {
    if (pending) {
      return; // a second Enter must not send the same try again
    }
    form.setSubmitted(true);
    if (!fields.valid) {
      return;
    }
    const name = values.name.trim();
    const mgmtHost = values.mgmtHost.trim();
    const mgmtPort = values.mgmtPort.trim() === "" ? 0 : Number(values.mgmtPort.trim());
    const linkHost = values.linkHost.trim();
    try {
      if (baseline === undefined) {
        onCreated?.(await create.mutateAsync({ name, mgmtHost, mgmtPort, linkHost }));
        return;
      }
      const changes: UpdateNodeVars = { id: baseline.id };
      if (name !== baseline.name) changes.name = name;
      if (mgmtHost !== baseline.mgmtHost) changes.mgmtHost = mgmtHost;
      if (mgmtPort !== baseline.mgmtPort) changes.mgmtPort = mgmtPort;
      if (linkHost !== baseline.linkHost) changes.linkHost = linkHost;
      if (values.note !== baseline.note) changes.note = values.note;
      if (Object.keys(changes).length === 1) {
        onSaved?.(baseline);
        return;
      }
      const saved = await update.mutateAsync(changes);
      setBaseline(saved);
      notifySuccess(t("nodes.form.saved"));
      onSaved?.(saved);
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
        <TextInput label={t("nodes.form.name")} autoComplete="off" data-autofocus {...fields.bind("name")} />
        <TextInput
          label={t("nodes.form.mgmtHost")}
          description={
            editing ? t("nodes.form.mgmtHostHint") : `${t("nodes.form.mgmtHostHint")} ${t("nodes.form.mgmtHostHintCreate")}`
          }
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("mgmtHost")}
        />
        <TextInput
          label={t("nodes.form.mgmtPort")}
          description={editing ? t("nodes.form.mgmtPortHintEdit") : t("nodes.form.mgmtPortHintCreate")}
          inputMode="numeric"
          autoComplete="off"
          {...fields.bind("mgmtPort")}
        />
        <TextInput
          label={t("nodes.form.linkHost")}
          description={t("nodes.form.linkHostHint")}
          autoComplete="off"
          spellCheck={false}
          {...fields.bind("linkHost")}
        />
        {editing ? <Textarea label={t("nodes.form.note")} autosize minRows={2} maxRows={6} {...fields.bind("note")} /> : null}
        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending}>
            {editing ? t("nodes.form.save") : t("nodes.form.create")}
          </Button>
          <Button variant="default" onClick={onCancel} disabled={pending}>
            {t("common.cancel")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
