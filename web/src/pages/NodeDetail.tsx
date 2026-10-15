import { ActionIcon, Alert, Anchor, Badge, Button, Group, Menu, Stack, Tabs, Title, Tooltip } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, Navigate, Outlet, useLocation, useMatches, useNavigate, useParams } from "react-router";

import { useProblems } from "../api/hooks/diagnostics";
import { useDeleteNode, useNode } from "../api/hooks/nodes";
import { isProvisioning } from "../app/node";
import { notifySuccess } from "../app/notify";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { BackIcon, EditIcon, TrashIcon } from "../components/icons";
import { NodeEditDialog } from "../components/NodeEditDialog";
import { NotFoundNotice } from "../components/NotFoundNotice";
import { QueryView } from "../components/QueryView";
import { StatusBadge } from "../components/StatusBadge";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { NodeBanner } from "./node/NodeBanner";
import { NODE_TABS, type NodeTab, type NodeTabHandle, nodeTabPath as tabPath } from "./node/nodeTabs";
import type { NodeOutlet } from "./node/tabs";

/**
 * One node: a header with its name, status and actions, the one action that matters
 * on top (NodeBanner), and its sections in tabs, one route each, so that the address
 * is the tab and back and forward move between them.
 */
export function NodeDetail() {
  const { t } = useTranslation();
  const { nodeId = "" } = useParams();
  const node = useNode(nodeId);

  return (
    <QueryView query={node} notFound={<NotFoundNotice backTo="/nodes" backLabel={t("nodes.title")} />}>
      {(data) => <NodePage node={data} />}
    </QueryView>
  );
}

function useCurrentTab(): NodeTab {
  const matches = useMatches();
  for (const match of matches) {
    const handle = match.handle as Partial<NodeTabHandle> | undefined;
    if (handle?.nodeTab !== undefined) {
      return handle.nodeTab;
    }
  }
  return "overview";
}

function NodePage({ node }: { node: Node }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const tab = useCurrentTab();
  const remove = useDeleteNode();
  const problems = useProblems({ nodeId: node.id });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const provisioning = isProvisioning(node);
  const problemCount =
    problems.data?.problems.filter((problem) => problem.severity === "error" || problem.severity === "warning").length ?? 0;

  async function confirmDelete() {
    try {
      await remove.mutateAsync(node.id);
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("nodes.delete.done"));
    void navigate("/nodes");
  }

  // Before the node connects, only the install is open to it.
  if (provisioning && tab !== "overview") {
    return <Navigate to={tabPath(node.id, "overview")} replace />;
  }
  // A link to a run (?run=, after a change or a fix) opens it in the diagnostics.
  if (!provisioning && tab !== "diagnostics" && new URLSearchParams(location.search).has("run")) {
    return <Navigate to={{ pathname: tabPath(node.id, "diagnostics"), search: location.search }} replace />;
  }

  const outlet: NodeOutlet = {
    node,
    provisioning,
    onDelete: () => {
      setDeleting(true);
    },
  };
  const labels: Record<NodeTab, string> = {
    overview: t("nodes.tabs.overview"),
    proxies: t("nodes.tabs.proxies"),
    egress: t("nodes.tabs.egress"),
    diagnostics: t("nodes.tabs.diagnostics"),
    settings: t("nodes.tabs.settings"),
  };

  return (
    <Stack gap="lg">
      <Anchor component={Link} to="/nodes" size="sm" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <BackIcon />
        {t("nodes.title")}
      </Anchor>

      <Group justify="space-between" align="center" wrap="wrap">
        <Group gap="sm" align="center">
          <Title order={1}>{node.name}</Title>
          <StatusBadge kind="node" value={node.status} />
        </Group>
        <Group gap="xs">
          <Button
            variant="default"
            leftSection={<EditIcon />}
            onClick={() => {
              setEditing(true);
            }}
          >
            {t("nodes.detail.edit")}
          </Button>
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <ActionIcon variant="default" size="lg" aria-label={t("nodes.detail.more")}>
                <span aria-hidden="true">⋯</span>
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item
                color="red"
                leftSection={<TrashIcon />}
                onClick={() => {
                  setDeleting(true);
                }}
              >
                {t("nodes.delete.action")}
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Group>

      {node.mgmtHost === "" ? (
        <Alert color="yellow" variant="light">
          {t("nodes.detail.noHost")}
        </Alert>
      ) : null}

      <NodeBanner node={node} />

      <Tabs
        value={tab}
        keepMounted={false}
        onChange={(value) => {
          const next = NODE_TABS.find((name) => name === value);
          if (next !== undefined && next !== tab) {
            void navigate(tabPath(node.id, next));
          }
        }}
      >
        <Tabs.List style={{ flexWrap: "nowrap", overflowX: "auto", overflowY: "hidden" }} mb="lg">
          {NODE_TABS.map((name) => {
            const badge =
              name === "diagnostics" && problemCount > 0 ? (
                <Badge size="sm" variant="light" color="red" aria-label={t("nodes.tabs.problems", { count: problemCount })}>
                  {problemCount}
                </Badge>
              ) : null;
            const disabled = provisioning && name !== "overview";
            const item = (
              <Tabs.Tab key={name} value={name} disabled={disabled} rightSection={badge} style={{ flexShrink: 0 }}>
                {labels[name]}
              </Tabs.Tab>
            );
            return disabled ? (
              // A disabled tab takes no focus nor hover: its wrapper does, so that the reason
              // shows on a hover, a keyboard focus and a touch alike.
              <Tooltip key={name} label={t("nodes.tabs.waiting")} withArrow events={{ hover: true, focus: true, touch: true }}>
                <span tabIndex={0} style={{ display: "inline-flex", flexShrink: 0 }}>
                  {item}
                </span>
              </Tooltip>
            ) : (
              item
            );
          })}
        </Tabs.List>
        <Tabs.Panel value={tab}>
          <Outlet context={outlet} />
        </Tabs.Panel>
      </Tabs>

      <NodeEditDialog
        node={node}
        opened={editing}
        onClose={() => {
          setEditing(false);
        }}
      />
      <ConfirmDialog
        opened={deleting}
        title={t("nodes.delete.title")}
        message={t("nodes.delete.message", { name: node.name })}
        confirmLabel={t("nodes.delete.confirm")}
        loading={remove.isPending}
        onConfirm={() => {
          void confirmDelete();
        }}
        onClose={() => {
          setDeleting(false);
        }}
      />
    </Stack>
  );
}
