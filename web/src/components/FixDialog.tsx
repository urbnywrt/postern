import { Alert, Anchor, Button, Group, Modal, Select, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { errorMessage } from "../api/errors";
import { useApplyFix } from "../api/hooks/diagnostics";
import { useChains } from "../api/hooks/egress";
import { FIX_AFTERWARDS, FIXES, fixName, fixRefusal, isFix, runLink } from "../app/diagnostics";

/** What a fix is offered for: a check of a target of a node, from a run or from the light checks. */
export interface FixOffer {
  nodeId: string;
  checkId: string;
  target: string;
  fix: string;
  /** The run that offered the fix; "" for the light checks and the problem feed. */
  offeredRunId: string;
}

interface FixDialogProps {
  offer: FixOffer | null;
  onClose: () => void;
}

/**
 * Asks before a fix and says what it changes. Nothing changes until the admin
 * confirms. The panel may refuse: a fix whose check no longer offers it is
 * stale (the admin runs the checks again), a fix that the node cannot take says
 * why, and one that this panel cannot apply yet (reissue_cert) says so.
 */
export function FixDialog({ offer, onClose }: FixDialogProps) {
  const { t } = useTranslation();
  return (
    <Modal opened={offer !== null} onClose={onClose} title={offer === null ? "" : t("insights.diagnostics.fix.title", { fix: fixName(t, offer.fix) })} centered>
      {offer === null ? null : <FixBody key={`${offer.nodeId} ${offer.checkId} ${offer.target} ${offer.fix} ${offer.offeredRunId}`} offer={offer} onClose={onClose} />}
    </Modal>
  );
}

function FixBody({ offer, onClose }: { offer: FixOffer; onClose: () => void }) {
  const { t } = useTranslation();
  const apply = useApplyFix();
  const needsChain = offer.fix === "change_egress";
  const chains = useChains(offer.nodeId, { enabled: needsChain });
  const [chainId, setChainId] = useState<string | null>(null);
  const fix = isFix(offer.fix) ? offer.fix : null;
  const refusal = apply.isError ? fixRefusal(apply.error) : null;
  const afterwards = fix === null ? undefined : FIX_AFTERWARDS[fix];

  if (apply.data !== undefined) {
    return (
      <Stack gap="md">
        <Alert color="teal" role="status">
          {t("insights.diagnostics.fix.applied", { generation: apply.data.generation.toString() })}
        </Alert>
        {apply.data.beforeRunId === "" ? null : (
          <Anchor component={Link} to={runLink(offer.nodeId, apply.data.beforeRunId)} size="sm" onClick={onClose}>
            {t("insights.diagnostics.fix.openBefore")}
          </Anchor>
        )}
        <Group justify="flex-end">
          <Button onClick={onClose}>{t("insights.diagnostics.close")}</Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Stack gap="md">
      {fix !== null ? (
        <Text size="sm">{t(FIXES[fix])}</Text>
      ) : (
        <Text size="sm">{t("insights.diagnostics.fix.unknown")}</Text>
      )}
      {afterwards === undefined ? null : <Text size="sm">{t(afterwards)}</Text>}
      <Text size="sm" c="dimmed">
        {t("insights.diagnostics.fix.afterRun")}
      </Text>
      {needsChain ? (
        <Select
          label={t("insights.diagnostics.fix.chain")}
          description={t("insights.diagnostics.fix.chainHint")}
          data={(chains.data ?? []).map((chain) => ({ value: chain.id, label: chain.name }))}
          value={chainId}
          onChange={setChainId}
          disabled={chains.isPending}
          error={chains.isError ? errorMessage(chains.error) : undefined}
          allowDeselect={false}
        />
      ) : null}
      {refusal === null ? null : <Refusal refusal={refusal} error={apply.error} />}
      <Group justify="flex-end" gap="sm">
        <Button variant="default" onClick={onClose} disabled={apply.isPending}>
          {t("common.cancel")}
        </Button>
        <Button
          color="red"
          loading={apply.isPending}
          disabled={fix === null || (needsChain && chainId === null) || refusal?.kind === "stale" || refusal?.kind === "unavailable"}
          onClick={() => {
            apply.mutate({ ...offer, chainId: chainId ?? "" });
          }}
        >
          {t("insights.diagnostics.fix.confirm")}
        </Button>
      </Group>
    </Stack>
  );
}

function Refusal({ refusal, error }: { refusal: ReturnType<typeof fixRefusal>; error: unknown }) {
  const { t } = useTranslation();
  switch (refusal.kind) {
    case "stale":
      return (
        <Alert color="orange" role="alert">
          <Stack gap={4}>
            <Text size="sm">{t("insights.diagnostics.fix.stale")}</Text>
            <Text size="xs" c="dimmed">
              {refusal.message}
            </Text>
          </Stack>
        </Alert>
      );
    case "unavailable":
      return (
        <Alert color="gray" role="alert">
          {t("insights.diagnostics.fix.unavailable", { reason: refusal.message })}
        </Alert>
      );
    case "refused":
      return (
        <Alert color="red" role="alert">
          {t("insights.diagnostics.fix.refused", { reason: refusal.message })}
        </Alert>
      );
    default:
      return (
        <Alert color="red" role="alert">
          {t("insights.diagnostics.fix.refused", { reason: errorMessage(error) })}
        </Alert>
      );
  }
}
