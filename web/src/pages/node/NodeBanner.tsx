import { Alert, Button, Group, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { usePanelVersion } from "../../api/hooks/versions";
import { isProvisioning, nodeBanner } from "../../app/node";
import type { RolloutTarget } from "../../app/versions";
import { RolloutDialog } from "../../components/RolloutDialog";
import type { Node } from "../../gen/postern/panel/v1/nodes_pb";

/**
 * The one action that matters on the page of a node, above its tabs (see nodeBanner): to
 * install it, to update its agent or roll its edge (the rollouts of its versions card), or
 * that it needs a new build. Nothing when none applies.
 */
export function NodeBanner({ node }: { node: Node }) {
  const { t } = useTranslation();
  const panel = usePanelVersion();
  const [dialog, setDialog] = useState<{ opened: boolean; target?: RolloutTarget }>({ opened: false });
  const banner = nodeBanner(node, panel.data?.version);
  if (banner === null) {
    return null;
  }

  let color = "yellow";
  let text: string;
  let action = null;
  switch (banner.kind) {
    case "provisioning":
      color = "blue";
      text = t("nodes.banner.provisioning");
      // Before the node connects, the install is the page itself, right below.
      action = isProvisioning(node) ? null : (
        <Button size="xs" component={Link} to={`/nodes/${node.id}/settings`}>
          {t("nodes.banner.install")}
        </Button>
      );
      break;
    case "agentUpdate":
      color = "blue";
      text = t("nodes.banner.agentUpdate", { agent: `v${banner.agent}`, panel: `v${banner.panel}` });
      action = (
        <Button
          size="xs"
          onClick={() => {
            setDialog({ opened: true, target: { kind: "node", nodeIds: [node.id], agent: true, edge: false } });
          }}
        >
          {t("nodes.banner.updateNode")}
        </Button>
      );
      break;
    case "edgeOutdated":
      color = "orange";
      text = t("nodes.banner.edgeOutdated");
      action = (
        <Button
          size="xs"
          onClick={() => {
            setDialog({ opened: true, target: { kind: "node", nodeIds: [node.id], agent: false, edge: true } });
          }}
        >
          {t("versions.node.rollEdge")}
        </Button>
      );
      break;
    case "needsInstall":
      text = t("versions.node.needsInstall");
      break;
  }

  return (
    <>
      <Alert color={color} variant="light" role="status" aria-label={t("nodes.banner.label")}>
        <Group justify="space-between" align="center" gap="sm" wrap="wrap">
          <Text size="sm" style={{ flex: "1 1 16rem", minWidth: 0, overflowWrap: "anywhere" }}>
            {text}
          </Text>
          {action}
        </Group>
      </Alert>
      <RolloutDialog
        opened={dialog.opened}
        target={dialog.target}
        onClose={() => {
          setDialog((current) => ({ ...current, opened: false }));
        }}
      />
    </>
  );
}
