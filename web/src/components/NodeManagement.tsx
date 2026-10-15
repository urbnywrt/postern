import { Alert, Button, Group, Modal, Paper, Select, Stack, Text, TextInput, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useListeners } from "../api/hooks/listeners";
import { useSetNodeMgmtMode } from "../api/hooks/nodes";
import { orDash } from "../app/format";
import { notifySuccess } from "../app/notify";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { DefinitionList } from "./DefinitionList";

/** The mode as the page shows it: empty is the default, port. */
const modeOf = (node: Node) => (node.mgmtMode === "hidden" ? "hidden" : "port");

/**
 * How the panel reaches the agent of the node (spec §5.3): on a port of its
 * own, or hidden behind a public tls listener of the node by a management SNI,
 * with the port of its own closed. A switch is checked live by the panel and
 * leaves the mode as it was when the check fails.
 */
export function NodeManagement({ node }: { node: Node }) {
  const { t } = useTranslation();
  const titleId = useId();
  const [switching, setSwitching] = useState(false);
  const hidden = modeOf(node) === "hidden";
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="baseline" mb="xs" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("nodes.detail.management")}
        </Title>
        <Button
          size="xs"
          variant="default"
          onClick={() => {
            setSwitching(true);
          }}
        >
          {t("nodes.mgmt.switch")}
        </Button>
      </Group>
      <Text size="sm" c="dimmed" mb="md">
        {t("nodes.mgmt.intro")}
      </Text>
      <DefinitionList
        items={[
          { label: t("nodes.mgmt.mode"), value: hidden ? t("nodes.mgmt.modeHidden") : t("nodes.mgmt.modePort") },
          { label: t("nodes.mgmt.sni"), value: orDash(node.mgmtSni) },
          { label: t("nodes.mgmt.publicPort"), value: node.mgmtPublicPort === 0 ? orDash("") : String(node.mgmtPublicPort) },
        ]}
      />
      <Modal
        opened={switching}
        onClose={() => {
          setSwitching(false);
        }}
        title={t("nodes.mgmt.title")}
        centered
      >
        {switching && (
          <MgmtForm
            node={node}
            onDone={() => {
              setSwitching(false);
            }}
          />
        )}
      </Modal>
    </Paper>
  );
}

function MgmtForm({ node, onDone }: { node: Node; onDone: () => void }) {
  const { t } = useTranslation();
  const listeners = useListeners(node.id);
  const setMode = useSetNodeMgmtMode();
  const [mode, setModeValue] = useState(modeOf(node));
  const [sni, setSni] = useState(node.mgmtSni);
  const [port, setPort] = useState(node.mgmtPublicPort === 0 ? null : String(node.mgmtPublicPort));
  const [failure, setFailure] = useState("");
  const [missing, setMissing] = useState(false);

  // The public tls listeners of the node, one entry to a port.
  const ports = [
    ...new Set((listeners.data ?? []).filter((l) => l.kind === "" || l.kind === "tls").map((l) => l.port)),
  ].sort((a, b) => a - b);

  async function submit() {
    setFailure("");
    if (mode === "hidden" && (sni.trim() === "" || port === null)) {
      setMissing(true);
      return;
    }
    let answer;
    try {
      answer = await setMode.mutateAsync({
        nodeId: node.id,
        mode,
        mgmtSni: mode === "hidden" ? sni.trim() : "",
        publicPort: mode === "hidden" && port !== null ? Number(port) : 0,
      });
    } catch {
      return; // the query client has shown why
    }
    if (!answer.ok) {
      setFailure(answer.reason);
      return;
    }
    notifySuccess(t("nodes.mgmt.done"));
    onDone();
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
        <Select
          label={t("nodes.mgmt.mode")}
          data={[
            { value: "port", label: t("nodes.mgmt.modePort") },
            { value: "hidden", label: t("nodes.mgmt.modeHidden") },
          ]}
          value={mode}
          onChange={(value) => {
            setModeValue(value === "hidden" ? "hidden" : "port");
          }}
          allowDeselect={false}
        />
        {mode === "hidden" && (
          <>
            <TextInput
              label={t("nodes.mgmt.sni")}
              description={t("nodes.mgmt.sniHint")}
              value={sni}
              onChange={(event) => {
                setSni(event.currentTarget.value);
              }}
              error={missing && sni.trim() === "" ? t("nodes.mgmt.required") : undefined}
            />
            <Select
              label={t("nodes.mgmt.publicPort")}
              description={t("nodes.mgmt.publicPortHint")}
              data={ports.map((p) => String(p))}
              value={port}
              onChange={setPort}
              disabled={listeners.isPending}
              nothingFoundMessage={t("nodes.mgmt.noPorts")}
              error={
                listeners.isError
                  ? errorMessage(listeners.error)
                  : missing && port === null
                    ? t("nodes.mgmt.required")
                    : undefined
              }
            />
          </>
        )}
        <Text size="xs" c="dimmed">
          {t("nodes.mgmt.slow")}
        </Text>
        {failure !== "" && (
          <Alert color="red" title={t("nodes.mgmt.failed")}>
            {failure}
          </Alert>
        )}
        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={onDone} disabled={setMode.isPending}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" loading={setMode.isPending}>
            {t("nodes.mgmt.apply")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
