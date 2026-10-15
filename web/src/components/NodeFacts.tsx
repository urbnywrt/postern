import { Badge, Group, Stack, Text, Tooltip } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { ROLL_EDGE_COMMAND } from "../app/bundle";
import { formatDateTime, formatRelative, orDash } from "../app/format";
import { edgeOutdated } from "../app/node";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { CommandLine } from "./CommandLine";

/** When the panel last heard from the agent of a node: "5 minutes ago", with the date for a hover; "Never" before the first time. */
export function LastSeen({ unix }: { unix: bigint }) {
  const { t } = useTranslation();
  if (unix === 0n) {
    return <>{t("common.never")}</>;
  }
  const date = new Date(Number(unix) * 1000);
  return (
    <Text component="time" size="inherit" dateTime={date.toISOString()} title={formatDateTime(unix)}>
      {formatRelative(unix)}
    </Text>
  );
}

/**
 * The state of a node that the panel wants (desired) and the one that the node
 * reports as applied: "7 / 7". A node that says why it does not run its state
 * (it refused the state of the panel, or its last pass failed: `lastError`) is
 * failing, with the reason on a hover. A node that is online and behind
 * without an error says it is still applying: it is catching up, which is not
 * a fault.
 */
export function Generation({ node }: { node: Node }) {
  const { t } = useTranslation();
  const behind = node.status === "online" && node.appliedGeneration < node.desiredGeneration;
  let badge = null;
  if (node.lastError !== "") {
    badge = (
      <Tooltip label={node.lastError} multiline maw={360} withArrow>
        <Badge variant="light" color="red" size="sm" style={{ cursor: "help" }} tabIndex={0}>
          {t("node.failing")}
        </Badge>
      </Tooltip>
    );
  } else if (behind) {
    badge = (
      <Badge variant="light" color="yellow" size="sm">
        {t("node.applying")}
      </Badge>
    );
  }
  return (
    <Group gap="xs" wrap="nowrap" component="span" display="inline-flex">
      <span>
        {String(node.appliedGeneration)} / {String(node.desiredGeneration)}
      </span>
      {badge}
    </Group>
  );
}

/**
 * Why a node does not run the state that the panel wants it to, in the words of
 * the node: the reason it refused the state of the panel, or why its last pass
 * failed. `lines` clamps a long text, for a tile; the whole text is on a hover.
 */
export function LastError({ node, lines }: { node: Node; lines?: number }) {
  return (
    <Text
      size="sm"
      c="red"
      lineClamp={lines}
      title={lines === undefined ? undefined : node.lastError}
      style={{ whiteSpace: "pre-wrap" }}
    >
      {node.lastError}
    </Text>
  );
}

/** Why the edge of a node is outdated, in a sentence. */
function useEdgeWhy(node: Node): string {
  const { t } = useTranslation();
  return node.edgeVersion === ""
    ? t("node.edgeUnknown", { agent: node.agentVersion })
    : t("node.edgeBehind", { edge: node.edgeVersion, agent: node.agentVersion });
}

/** A mark for an outdated edge (see edgeOutdated), with why and what to do on a hover. */
export function EdgeOutdatedBadge({ node }: { node: Node }) {
  const { t } = useTranslation();
  const why = useEdgeWhy(node);
  if (!edgeOutdated(node)) {
    return null;
  }
  return (
    <Tooltip label={`${why} ${t("node.edgeRoll")} ${ROLL_EDGE_COMMAND}`} multiline maw={360} withArrow>
      <Badge variant="light" color="orange" size="sm" style={{ cursor: "help" }} tabIndex={0}>
        {t("node.edgeOutdated")}
      </Badge>
    </Tooltip>
  );
}

/**
 * The version of the edge of a node, marked when it is outdated. `hint` says, below it, why
 * and how to roll the edge, with the command to copy: for the page of the node.
 */
export function EdgeVersion({ node, hint = false }: { node: Node; hint?: boolean }) {
  const { t } = useTranslation();
  const why = useEdgeWhy(node);
  return (
    <Stack gap={6}>
      <Group gap="xs" wrap="nowrap" component="span" display="inline-flex">
        <span>{orDash(node.edgeVersion)}</span>
        <EdgeOutdatedBadge node={node} />
      </Group>
      {hint && edgeOutdated(node) ? (
        <>
          <Text size="xs" c="dimmed">
            {why}
          </Text>
          <Text size="xs" c="dimmed">
            {t("node.edgeRoll")}
          </Text>
          <CommandLine text={ROLL_EDGE_COMMAND} copyLabel={t("node.copyRollEdge")} />
        </>
      ) : null}
    </Stack>
  );
}
