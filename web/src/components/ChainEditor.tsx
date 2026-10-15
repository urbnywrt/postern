import { ActionIcon, Badge, Button, Group, Select, SimpleGrid, Stack, Text, TextInput, Tooltip } from "@mantine/core";
import { type ReactNode, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { type ChainCheckVars, type UpdateChainVars, useCreateChain, useEgresses, useUpdateChain } from "../api/hooks/egress";
import { useNodes } from "../api/hooks/nodes";
import { isExperimental, kindLabel } from "../app/egress";
import { notifySuccess } from "../app/notify";
import { type FieldErrors, useFormState } from "../app/useFormState";
import {
  parseCheckValue,
  validateCheckInterval,
  validateCheckThreshold,
  validateCheckTimeout,
  validateNodeName,
} from "../app/validators";
import type { Chain } from "../gen/postern/panel/v1/egress_pb";
import { ArrowDownIcon, ArrowUpIcon, CloseIcon } from "./icons";

interface Values {
  name: string;
  /** Empty for a chain that every node can use. */
  nodeId: string;
  interval: string;
  timeout: string;
  fail: string;
  recover: string;
}

/** The value of the node field for "every node": a Select has no empty value. */
const EVERY_NODE = "*";

const checkField = (n: number | undefined) => (n === undefined || n === 0 ? "0" : String(n));

function initialOf(chain: Chain | undefined): Values {
  return {
    name: chain?.name ?? "",
    nodeId: chain?.nodeId ?? "",
    interval: checkField(chain?.check?.intervalSeconds),
    timeout: checkField(chain?.check?.timeoutSeconds),
    fail: checkField(chain?.check?.failThreshold),
    recover: checkField(chain?.check?.recoverThreshold),
  };
}

/**
 * The check that the values give, with the datacenters of the chain kept as
 * they are: the editor has no field for them, and a new chain has none.
 */
function checkOf(v: Values, chain: Chain | undefined): ChainCheckVars {
  return {
    intervalSeconds: parseCheckValue(v.interval),
    timeoutSeconds: parseCheckValue(v.timeout),
    failThreshold: parseCheckValue(v.fail),
    recoverThreshold: parseCheckValue(v.recover),
    dcAddrs: [...(chain?.check?.dcAddrs ?? [])],
  };
}

const sameCheck = (a: ChainCheckVars, b: ChainCheckVars) =>
  a.intervalSeconds === b.intervalSeconds &&
  a.timeoutSeconds === b.timeoutSeconds &&
  a.failThreshold === b.failThreshold &&
  a.recoverThreshold === b.recoverThreshold &&
  a.dcAddrs.join("\n") === b.dcAddrs.join("\n");

const sameMembers = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((id, i) => id === b[i]);

interface ChainEditorProps {
  /** The chain that is edited; left out, the editor makes a new one. */
  chain?: Chain;
  onDone: (chain: Chain) => void;
  onCancel?: () => void;
}

/**
 * The editor of an egress chain: its name, its node (fixed once it is made),
 * its members in the order that the edge tries them, and its health check. An
 * egress is added from the list of those that the node of the chain can use,
 * once, and moved up and down or taken out.
 */
export function ChainEditor({ chain, onDone, onCancel }: ChainEditorProps) {
  const { t } = useTranslation();
  const editing = chain !== undefined;
  const create = useCreateChain();
  const update = useUpdateChain();
  const pending = create.isPending || update.isPending;
  const [baseline, setBaseline] = useState(chain);
  const [members, setMembers] = useState<string[]>(() => [...(chain?.memberIds ?? [])]);
  const form = useFormState<Values>(initialOf(chain));
  const { values } = form;
  const nodes = useNodes();
  const egresses = useEgresses();
  const memberId = useId();

  const byId = new Map((egresses.data ?? []).map((egress) => [egress.id, egress]));
  const usable = (egresses.data ?? []).filter((egress) => egress.nodeId === "" || egress.nodeId === values.nodeId);
  const addable = usable.filter((egress) => !members.includes(egress.id));
  const fields = form.check(validate(values));
  const noMembers = members.length === 0;
  /** The name of a member: an egress that is not in the list is gone only when the list is there. */
  const nameOf = (id: string) => byId.get(id)?.name ?? (egresses.isSuccess ? t("chain.form.missing") : id);

  function validate(v: Values): FieldErrors<Values> {
    return {
      name: validateNodeName(v.name),
      interval: validateCheckInterval(v.interval),
      timeout: validateCheckTimeout(v.timeout),
      fail: validateCheckThreshold(v.fail),
      recover: validateCheckThreshold(v.recover),
    };
  }

  function move(index: number, by: -1 | 1) {
    setMembers((current) => {
      const next = [...current];
      const [moved] = next.splice(index, 1);
      if (moved !== undefined) {
        next.splice(index + by, 0, moved);
      }
      return next;
    });
  }

  /** Another node takes away the members that it cannot use. */
  function setNode(nodeId: string) {
    form.set("nodeId", nodeId);
    setMembers((current) => current.filter((id) => {
      const owner = byId.get(id)?.nodeId ?? "";
      return owner === "" || owner === nodeId;
    }));
  }

  async function submit() {
    if (pending) {
      return;
    }
    form.setSubmitted(true);
    if (!fields.valid || noMembers) {
      return;
    }
    const check = checkOf(values, baseline);
    try {
      if (baseline === undefined) {
        const created = await create.mutateAsync({ name: values.name.trim(), nodeId: values.nodeId, memberIds: members, check });
        onDone(created);
        return;
      }
      const changes: UpdateChainVars = { id: baseline.id };
      if (values.name.trim() !== baseline.name) changes.name = values.name.trim();
      if (!sameMembers(members, baseline.memberIds)) changes.memberIds = members;
      if (!sameCheck(check, checkOf(initialOf(baseline), baseline))) changes.check = check;
      if (Object.keys(changes).length === 1) {
        onDone(baseline);
        return;
      }
      const updated = await update.mutateAsync(changes);
      setBaseline(updated);
      notifySuccess(t("chain.form.saved"));
      onDone(updated);
    } catch {
      // The query client has shown why, and the editor keeps what was done.
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
        <TextInput label={t("chain.form.name")} autoComplete="off" {...fields.bind("name")} />
        <Select
          label={t("chain.form.node")}
          description={t("chain.form.nodeHint")}
          data={[
            { value: EVERY_NODE, label: t("egress.everyNode") },
            ...(nodes.data ?? []).map((node) => ({ value: node.id, label: node.name })),
          ]}
          value={values.nodeId === "" ? EVERY_NODE : values.nodeId}
          onChange={(value) => {
            setNode(value === null || value === EVERY_NODE ? "" : value);
          }}
          disabled={editing}
          error={nodes.isError ? errorMessage(nodes.error) : undefined}
          allowDeselect={false}
        />

        <Stack gap={4}>
          <Text size="sm" fw={500}>
            {t("chain.form.members")}
          </Text>
          <Text size="xs" c="dimmed">
            {t("chain.form.membersHint")}
          </Text>
          {members.length > 0 ? (
            <Stack component="ol" aria-label={t("chain.form.members")} gap={4} p={0} m={0} style={{ listStyle: "none" }}>
              {members.map((id, index) => {
                const egress = byId.get(id);
                const name = nameOf(id);
                // The item is named by its egress, for a screen reader and for a test.
                const nameId = `${memberId}-${id}`;
                return (
                  <Group key={id} component="li" aria-labelledby={nameId} gap="xs" wrap="nowrap" justify="space-between">
                    <Group gap="xs" wrap="nowrap" miw={0}>
                      <Text size="sm" c="dimmed" w={24}>
                        {index + 1}.
                      </Text>
                      <Text id={nameId} size="sm" truncate>
                        {name}
                      </Text>
                      {egress ? (
                        <Badge variant="light" color="gray" size="sm">
                          {kindLabel(t, egress.kind)}
                        </Badge>
                      ) : null}
                      {egress && isExperimental(egress.kind) ? (
                        <Badge variant="light" color="yellow" size="sm">
                          {t("egress.experimental")}
                        </Badge>
                      ) : null}
                    </Group>
                    <Group gap={2} wrap="nowrap">
                      <MemberButton label={t("chain.form.moveUp", { name })} disabled={index === 0} onClick={() => { move(index, -1); }}>
                        <ArrowUpIcon />
                      </MemberButton>
                      <MemberButton
                        label={t("chain.form.moveDown", { name })}
                        disabled={index === members.length - 1}
                        onClick={() => {
                          move(index, 1);
                        }}
                      >
                        <ArrowDownIcon />
                      </MemberButton>
                      <MemberButton
                        label={t("chain.form.remove", { name })}
                        color="red"
                        onClick={() => {
                          setMembers((current) => current.filter((member) => member !== id));
                        }}
                      >
                        <CloseIcon />
                      </MemberButton>
                    </Group>
                  </Group>
                );
              })}
            </Stack>
          ) : form.submitted ? (
            <Text size="sm" c="red" role="alert">
              {t("chain.form.noMembers")}
            </Text>
          ) : null}
          <Select
            label={t("chain.form.add")}
            placeholder={t("chain.form.addPlaceholder")}
            data={addable.map((egress) => ({ value: egress.id, label: egress.name }))}
            value={null}
            onChange={(value) => {
              if (value !== null) {
                setMembers((current) => (current.includes(value) ? current : [...current, value]));
              }
            }}
            disabled={egresses.isPending}
            error={egresses.isError ? errorMessage(egresses.error) : undefined}
            searchable
          />
        </Stack>

        <Stack gap={4}>
          <Text size="sm" fw={500}>
            {t("chain.form.check")}
          </Text>
          <Text size="xs" c="dimmed">
            {t("chain.form.checkHint")}
          </Text>
          <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="sm">
            <TextInput label={t("chain.form.interval")} inputMode="numeric" autoComplete="off" {...fields.bind("interval")} />
            <TextInput label={t("chain.form.timeout")} inputMode="numeric" autoComplete="off" {...fields.bind("timeout")} />
            <TextInput label={t("chain.form.failThreshold")} inputMode="numeric" autoComplete="off" {...fields.bind("fail")} />
            <TextInput label={t("chain.form.recoverThreshold")} inputMode="numeric" autoComplete="off" {...fields.bind("recover")} />
          </SimpleGrid>
        </Stack>

        <Group gap="sm" mt="xs">
          <Button type="submit" loading={pending}>
            {editing ? t("chain.form.save") : t("chain.form.create")}
          </Button>
          {onCancel ? (
            <Button variant="default" onClick={onCancel} disabled={pending}>
              {t("common.cancel")}
            </Button>
          ) : null}
        </Group>
      </Stack>
    </form>
  );
}

function MemberButton({
  label,
  disabled = false,
  color = "gray",
  onClick,
  children,
}: {
  label: string;
  disabled?: boolean;
  color?: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Tooltip label={label}>
      <ActionIcon variant="subtle" color={color} aria-label={label} disabled={disabled} onClick={onClick}>
        {children}
      </ActionIcon>
    </Tooltip>
  );
}
