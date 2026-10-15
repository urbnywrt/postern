import { ActionIcon, Anchor, Checkbox, Stack, Switch, Table, Text, Tooltip } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useSetProxyEnabled, useTgLink } from "../api/hooks/proxies";
import { useCopy } from "../app/clipboard";
import { proxyTitle } from "../app/proxy";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { Listener, Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { CopyIcon } from "./icons";
import { StatusBadge } from "./StatusBadge";

interface ProxyTableProps {
  proxies: Proxy[];
  /** With the nodes, a column names the node of each proxy and links to it. */
  nodes?: Node[];
  /** With the listeners, a column shows the address that each proxy is served on. */
  listeners?: Listener[];
  /** With a selection, each row has a checkbox, for an action on several proxies. */
  selection?: { selected: string[]; onChange: (ids: string[]) => void };
}

/** Proxies as rows: where they are, how they are doing, a switch to pause them and a button to copy their link. */
export function ProxyTable({ proxies, nodes, listeners, selection }: ProxyTableProps) {
  const { t } = useTranslation();
  return (
    <Table.ScrollContainer minWidth={640}>
      <Table verticalSpacing="sm" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            {selection ? <Table.Th w={32} /> : null}
            <Table.Th>{t("proxies.table.proxy")}</Table.Th>
            {nodes ? <Table.Th>{t("proxies.table.node")}</Table.Th> : null}
            {listeners ? <Table.Th>{t("proxies.table.listener")}</Table.Th> : null}
            <Table.Th>{t("proxies.table.engine")}</Table.Th>
            <Table.Th>{t("proxies.table.version")}</Table.Th>
            <Table.Th>{t("proxies.table.status")}</Table.Th>
            <Table.Th>{t("proxies.table.enabled")}</Table.Th>
            <Table.Th>{t("proxies.table.link")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {proxies.map((proxy) => (
            <ProxyRow key={proxy.id} proxy={proxy} nodes={nodes} listeners={listeners} selection={selection} />
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function ProxyRow({ proxy, nodes, listeners, selection }: { proxy: Proxy } & Pick<ProxyTableProps, "nodes" | "listeners" | "selection">) {
  const { t } = useTranslation();
  const node = nodes?.find((entry) => entry.id === proxy.nodeId);
  const listener = listeners?.find((entry) => entry.id === proxy.listenerId);
  return (
    <Table.Tr>
      {selection ? (
        <Table.Td>
          <Checkbox
            aria-label={t("proxies.table.select", { name: proxyTitle(proxy) })}
            checked={selection.selected.includes(proxy.id)}
            onChange={(event) => {
              const others = selection.selected.filter((id) => id !== proxy.id);
              selection.onChange(event.currentTarget.checked ? [...others, proxy.id] : others);
            }}
          />
        </Table.Td>
      ) : null}
      <Table.Td>
        <Stack gap={0}>
          <Anchor component={Link} to={`/proxies/${proxy.id}`} fw={500}>
            {proxyTitle(proxy)}
          </Anchor>
          {proxy.name !== "" ? (
            <Text size="xs" c="dimmed">
              {proxy.domain}
            </Text>
          ) : null}
        </Stack>
      </Table.Td>
      {nodes ? (
        <Table.Td>
          {node ? (
            <Anchor component={Link} to={`/nodes/${node.id}`} size="sm">
              {node.name}
            </Anchor>
          ) : (
            "—"
          )}
        </Table.Td>
      ) : null}
      {listeners ? (
        <Table.Td>
          <Text size="sm">{listener ? `${listener.bindIp}:${String(listener.port)}` : "—"}</Text>
        </Table.Td>
      ) : null}
      <Table.Td>
        <Text size="sm">{proxy.engine}</Text>
      </Table.Td>
      <Table.Td>
        <ProxyVersionCell proxy={proxy} />
      </Table.Td>
      <Table.Td>
        <StatusBadge kind="proxy" value={proxy.status?.phase ?? "unknown"} reason={proxy.status?.reason} />
      </Table.Td>
      <Table.Td>
        <EnableSwitch proxy={proxy} />
      </Table.Td>
      <Table.Td>
        <CopyTgLinkButton proxy={proxy} />
      </Table.Td>
    </Table.Tr>
  );
}

/**
 * Pauses a proxy or resumes it. The switch shows what the panel says, not what
 * was asked: it moves when the answer is there, and stays where it was when the
 * panel refuses.
 */
function EnableSwitch({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const set = useSetProxyEnabled();
  return (
    <Switch
      checked={proxy.enabled}
      disabled={set.isPending}
      aria-label={t("proxies.table.enabledFor", { name: proxyTitle(proxy) })}
      onChange={(event) => {
        set.mutate({ id: proxy.id, enabled: event.currentTarget.checked });
      }}
    />
  );
}

/**
 * Copies the tg link of a proxy. The link carries the secret, so the page does not
 * hold it: it is fetched when the button is pressed and goes to the clipboard.
 */
function CopyTgLinkButton({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const copy = useCopy();
  const tgLink = useTgLink();
  const label = t("proxies.table.copyLink", { name: proxyTitle(proxy) });
  return (
    <Tooltip label={label}>
      <ActionIcon
        variant="subtle"
        color="gray"
        aria-label={label}
        onClick={() => {
          void copy(tgLink(proxy.id), t("proxies.copyLinkFailed"));
        }}
      >
        <CopyIcon />
      </ActionIcon>
    </Tooltip>
  );
}

/**
 * What runs (as the node reports it) and what should: they differ while a change goes out, or after one failed.
 * The orange mark is the panel's outdated judgement (that of the outdated filter: what runs differs from what
 * should, or what should is older than the newest release on the channel), or a difference that the list shows.
 */
function ProxyVersionCell({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const runningEngine = proxy.status?.runningEngine ?? "";
  const runningVersion = proxy.status?.runningVersion ?? "";
  const differs = (runningEngine !== "" && runningEngine !== proxy.engine) || runningVersion !== proxy.engineVersion;
  const outdated = proxy.outdated || differs;
  const mark = outdated ? { c: "orange", title: t("proxies.table.outdated") } : {};
  return (
    <Stack gap={0}>
      {runningVersion !== "" ? (
        <Text size="sm" {...mark}>
          {t("proxies.table.runningVersion", { engine: runningEngine === "" ? proxy.engine : runningEngine, version: runningVersion })}
        </Text>
      ) : null}
      {differs || runningVersion === "" ? (
        <Text size="xs" c="dimmed" {...(runningVersion === "" ? mark : {})}>
          {t("proxies.table.desiredVersion", { version: proxy.engineVersion === "" ? "—" : proxy.engineVersion })}
        </Text>
      ) : null}
    </Stack>
  );
}
