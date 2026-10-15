import { Anchor, Button, Group, Paper, Select, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { errorMessage } from "../api/errors";
import { useChains, useSetNodeDefaultChain, useSetNodeDnsMode } from "../api/hooks/egress";
import { notifySuccess } from "../app/notify";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { type ChangeCheck, ChangeCheckNotice } from "./ChangeCheckNotice";

/** The value of the chain field for "none": a Select has no empty value. */
const DIRECT = "-";

/** The DNS mode as the form shows it: the default of the node is doh. */
const dnsModeOf = (node: Node) => (node.dnsMode === "" ? "doh" : node.dnsMode);

/**
 * The egress settings of a node: the chain that it goes out through, which is
 * also that of its proxies that have none of their own, and how its containers
 * resolve names. A change that the node cannot take (an older node, a chain of
 * a kind that it does not run) is refused by the panel, which says why.
 */
export function NodeEgressSettings({
  node,
  check: givenCheck,
  onCheck,
}: {
  node: Node;
  /**
   * The check of the last save, kept by the page: the form is made anew when the
   * node changes, and what it saved must still be linked afterwards.
   */
  check?: ChangeCheck;
  onCheck?: (check: ChangeCheck) => void;
}) {
  const { t } = useTranslation();
  const titleId = useId();
  const chains = useChains(node.id);
  const setChain = useSetNodeDefaultChain();
  const setDns = useSetNodeDnsMode();
  const [chain, setChainValue] = useState(node.defaultChainId === "" ? DIRECT : node.defaultChainId);
  const [dns, setDnsValue] = useState(dnsModeOf(node));
  const pending = setChain.isPending || setDns.isPending;
  const [ownCheck, setOwnCheck] = useState<ChangeCheck>(null);
  const check = givenCheck === undefined ? ownCheck : givenCheck;
  const setCheck = onCheck ?? setOwnCheck;

  async function save() {
    const chainId = chain === DIRECT ? "" : chain;
    // Each change makes the panel check the node before it saves (up to 90 s).
    const changed = chainId !== node.defaultChainId || dns !== dnsModeOf(node);
    setCheck(changed ? { nodeId: node.id } : null);
    // Two changes make two before-runs; the after-run of the node is related to the first.
    let beforeRunId = "";
    try {
      if (chainId !== node.defaultChainId) {
        beforeRunId = (await setChain.mutateAsync({ nodeId: node.id, chainId })).beforeRunId;
      }
      if (dns !== dnsModeOf(node)) {
        const answer = await setDns.mutateAsync({ nodeId: node.id, dnsMode: dns });
        beforeRunId ||= answer.beforeRunId;
      }
    } catch {
      setCheck(null);
      return; // the query client has shown why
    }
    setCheck(changed ? { nodeId: node.id, beforeRunId } : null);
    notifySuccess(t("nodes.egress.saved"));
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="baseline" mb="xs" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("nodes.detail.egress")}
        </Title>
        <Anchor component={Link} to="/egress" size="sm">
          {t("nodes.egress.manage")}
        </Anchor>
      </Group>
      <Text size="sm" c="dimmed" mb="md">
        {t("nodes.egress.intro")}
      </Text>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Stack gap="sm">
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
            <Select
              label={t("nodes.egress.defaultChain")}
              description={t("nodes.egress.defaultChainHint")}
              data={[
                { value: DIRECT, label: t("nodes.egress.direct") },
                ...(chains.data ?? []).map((c) => ({ value: c.id, label: c.name })),
              ]}
              value={chain}
              onChange={(value) => {
                setChainValue(value ?? DIRECT);
              }}
              disabled={chains.isPending}
              error={chains.isError ? errorMessage(chains.error) : undefined}
              allowDeselect={false}
            />
            <Select
              label={t("nodes.egress.dnsMode")}
              description={t("nodes.egress.dnsModeHint")}
              data={[
                { value: "doh", label: t("nodes.egress.dnsDoh") },
                { value: "system", label: t("nodes.egress.dnsSystem") },
              ]}
              value={dns}
              onChange={(value) => {
                setDnsValue(value ?? "doh");
              }}
              allowDeselect={false}
            />
          </SimpleGrid>
          <ChangeCheckNotice saving={pending} check={check} />
          <Group>
            <Button type="submit" size="xs" loading={pending}>
              {t("nodes.egress.save")}
            </Button>
          </Group>
        </Stack>
      </form>
    </Paper>
  );
}
