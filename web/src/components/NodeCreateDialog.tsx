import { Button, Divider, Group, Modal, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import type { CreateNodeResponse } from "../gen/postern/panel/v1/nodes_pb";
import { NodeDockerInstall } from "./NodeDockerInstall";
import { NodeForm } from "./NodeForm";
import { NodeManualInstall } from "./NodeInstallSteps";

interface NodeCreateDialogProps {
  opened: boolean;
  onClose: () => void;
}

/**
 * Adds a node. When the panel has made it, the dialog turns into the ways to install
 * it: one Docker command first, then the install over SSH, and, folded away, the
 * bundle and the node kit for a server without access to a registry.
 */
export function NodeCreateDialog({ opened, onClose }: NodeCreateDialogProps) {
  const { t } = useTranslation();
  const [created, setCreated] = useState<CreateNodeResponse | null>(null);

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      // The next time it opens, it is the form again.
      onExitTransitionEnd={() => {
        setCreated(null);
      }}
      title={created === null ? t("nodes.create.title") : t("nodes.created.title")}
      size="lg"
      centered
    >
      {created?.node === undefined ? (
        <NodeForm onCreated={setCreated} onCancel={onClose} />
      ) : (
        <Stack gap="md">
          <NodeDockerInstall node={created.node} />
          <Divider label={t("nodes.otherWays")} labelPosition="left" />
          <Group gap="md" align="center" wrap="wrap">
            <Button component={Link} to={`/nodes/${created.node.id}/install`} variant="default" onClick={onClose}>
              {t("deploy.open")}
            </Button>
            <Text size="sm" c="dimmed">
              {t("deploy.openHint")}
            </Text>
          </Group>
          <NodeManualInstall nodeId={created.node.id} />
          <Text size="sm" c="dimmed">
            {t("nodes.created.later")}
          </Text>
          <Group justify="flex-end">
            <Button onClick={onClose}>{t("common.done")}</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
