import { Modal } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

import { ProxyForm } from "./ProxyForm";

interface ProxyCreateDialogProps {
  opened: boolean;
  onClose: () => void;
  /** The node of the new proxy, when it is known (the page of a node, or a filter). */
  nodeId?: string;
}

/** Adds a proxy, and takes the admin to its page, where the links are. */
export function ProxyCreateDialog({ opened, onClose, nodeId }: ProxyCreateDialogProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <Modal opened={opened} onClose={onClose} title={t("proxies.addTitle")} size="lg" centered>
      <ProxyForm
        nodeId={nodeId}
        onCancel={onClose}
        onDone={(proxy) => {
          onClose();
          void navigate(`/proxies/${proxy.id}`);
        }}
      />
    </Modal>
  );
}
