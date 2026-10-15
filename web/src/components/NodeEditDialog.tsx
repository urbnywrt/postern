import { Modal } from "@mantine/core";
import { useTranslation } from "react-i18next";

import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { NodeForm } from "./NodeForm";

interface NodeEditDialogProps {
  node: Node;
  opened: boolean;
  onClose: () => void;
}

/** Changes the name, the addresses and the note of a node. */
export function NodeEditDialog({ node, opened, onClose }: NodeEditDialogProps) {
  const { t } = useTranslation();
  return (
    <Modal opened={opened} onClose={onClose} title={t("nodes.edit.title")} size="lg" centered>
      <NodeForm node={node} onSaved={onClose} onCancel={onClose} />
    </Modal>
  );
}
