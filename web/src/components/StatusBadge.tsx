import { Badge, Tooltip } from "@mantine/core";
import { useTranslation } from "react-i18next";

const nodeStatuses = {
  provisioning: "blue",
  online: "teal",
  offline: "orange",
  error: "red",
} as const;

const proxyPhases = {
  unknown: "gray",
  pending: "gray",
  starting: "blue",
  ready: "lime",
  serving: "teal",
  draining: "orange",
  failed: "red",
  paused: "gray",
} as const;

function isNodeStatus(value: string): value is keyof typeof nodeStatuses {
  return Object.hasOwn(nodeStatuses, value);
}

function isProxyPhase(value: string): value is keyof typeof proxyPhases {
  return Object.hasOwn(proxyPhases, value);
}

type StatusBadgeProps =
  /** The status of a node: provisioning, online, offline or error. */
  | { kind: "node"; value: string }
  /** The phase of a proxy as its node reported it; `reason` says why, for a proxy that failed. */
  | { kind: "proxy"; value: string; reason?: string };

/**
 * A colored label for the status of a node or the phase of a proxy. A value that
 * this version does not know, from a newer panel, is shown as it is, in gray.
 */
export function StatusBadge(props: StatusBadgeProps) {
  const { t } = useTranslation();
  let color = "gray";
  let label = props.value;
  if (props.kind === "node" && isNodeStatus(props.value)) {
    color = nodeStatuses[props.value];
    label = t(`status.node.${props.value}`);
  } else if (props.kind === "proxy" && isProxyPhase(props.value)) {
    color = proxyPhases[props.value];
    label = t(`status.proxy.${props.value}`);
  }

  const badge = (
    <Badge variant="light" color={color} miw="max-content">
      {label}
    </Badge>
  );
  const reason = props.kind === "proxy" ? props.reason : undefined;
  if (reason === undefined || reason === "") {
    return badge;
  }
  return (
    <Tooltip label={reason} multiline maw={320} withArrow>
      <Badge variant="light" color={color} miw="max-content" style={{ cursor: "help" }} tabIndex={0}>
        {label}
      </Badge>
    </Tooltip>
  );
}
