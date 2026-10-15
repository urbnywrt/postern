import { Button, Group, Modal, Stack, Text } from "@mantine/core";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

interface ConfirmDialogProps {
  opened: boolean;
  title: string;
  message: ReactNode;
  /** What the red button says: the act itself, "Delete the proxy". */
  confirmLabel: string;
  loading?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

/** Asks before something that cannot be undone. Nothing happens until the red button is pressed. */
export function ConfirmDialog({ opened, title, message, confirmLabel, loading = false, onConfirm, onClose }: ConfirmDialogProps) {
  const { t } = useTranslation();
  return (
    <Modal opened={opened} onClose={onClose} title={title} centered>
      <Stack gap="md">
        <Text size="sm">{message}</Text>
        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={onClose} disabled={loading}>
            {t("common.cancel")}
          </Button>
          <Button color="red" loading={loading} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
