import { Button, Checkbox, Group, Select, Stack, Text, TextInput, Title } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";

import { useListeners } from "../api/hooks/listeners";
import { useNodes } from "../api/hooks/nodes";
import { useProxies } from "../api/hooks/proxies";
import { PlusIcon } from "../components/icons";
import { ProxyCreateDialog } from "../components/ProxyCreateDialog";
import { ProxyTable } from "../components/ProxyTable";
import { QueryView } from "../components/QueryView";
import { SwitchEngineDialog } from "../components/SwitchEngineDialog";

/** The proxies of every node in one table, to filter by node or by text. */
export function Proxies() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  // The node is in the address, so that a link to "the proxies of this node" works,
  // and the filter survives a visit to the page of a proxy and back.
  const nodeId = params.get("node") ?? "";
  const [search, setSearch] = useState("");
  const [query] = useDebouncedValue(search.trim(), 300);
  const [adding, setAdding] = useState(false);
  const [engine, setEngine] = useState("");
  const [outdated, setOutdated] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [switching, setSwitching] = useState(false);

  const nodes = useNodes();
  const listeners = useListeners();
  const proxies = useProxies({ nodeId, query, engine, outdated });
  // Only what the list shows can be selected: a filter drops what it hides.
  const shown = new Set((proxies.data ?? []).map((proxy) => proxy.id));
  const chosen = selected.filter((id) => shown.has(id));

  function chooseNode(id: string | null) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (id === null || id === "") {
          next.delete("node");
        } else {
          next.set("node", id);
        }
        return next;
      },
      { replace: true },
    );
  }

  if (nodes.isSuccess && nodes.data.length === 0) {
    return (
      <Stack gap="sm" align="flex-start">
        <Title order={1}>{t("proxies.title")}</Title>
        <Text c="dimmed">{t("proxies.noNodes")}</Text>
        <Button component={Link} to="/nodes" leftSection={<PlusIcon />}>
          {t("nodes.add")}
        </Button>
      </Stack>
    );
  }

  const filtering = nodeId !== "" || query !== "" || engine !== "" || outdated;

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <Title order={1}>{t("proxies.title")}</Title>
        <Button
          leftSection={<PlusIcon />}
          onClick={() => {
            setAdding(true);
          }}
        >
          {t("proxies.add")}
        </Button>
      </Group>

      <Group align="flex-end" gap="sm">
        <Select
          label={t("proxies.filter.node")}
          placeholder={t("proxies.filter.allNodes")}
          data={(nodes.data ?? []).map((node) => ({ value: node.id, label: node.name }))}
          value={nodeId === "" ? null : nodeId}
          onChange={chooseNode}
          clearable
          // Mantine hides the clear button from the keyboard and from screen readers unless told not to.
          clearButtonProps={{ "aria-label": t("proxies.filter.clear"), "aria-hidden": false, tabIndex: 0 }}
          w={{ base: "100%", sm: 240 }}
        />
        <TextInput
          label={t("proxies.filter.search")}
          placeholder={t("proxies.filter.searchPlaceholder")}
          value={search}
          onChange={(event) => {
            setSearch(event.currentTarget.value);
          }}
          autoComplete="off"
          w={{ base: "100%", sm: 280 }}
        />
        <Select
          label={t("proxies.filter.engine")}
          data={[
            { value: "", label: t("proxies.filter.allEngines") },
            { value: "telemt", label: "telemt" },
            { value: "mtg", label: "mtg" },
          ]}
          value={engine}
          onChange={(value) => {
            setEngine(value ?? "");
          }}
          allowDeselect={false}
          w={{ base: "100%", sm: 180 }}
        />
        <Checkbox
          label={t("proxies.filter.outdated")}
          checked={outdated}
          onChange={(event) => {
            setOutdated(event.currentTarget.checked);
          }}
          mb={8}
        />
        <Button
          variant="light"
          disabled={chosen.length === 0}
          onClick={() => {
            setSwitching(true);
          }}
        >
          {t("proxies.bulkSwitch", { count: chosen.length })}
        </Button>
      </Group>

      <QueryView query={proxies}>
        {(list) =>
          list.length === 0 ? (
            <Text c="dimmed">{filtering ? t("proxies.noMatch") : t("proxies.empty")}</Text>
          ) : (
            <ProxyTable
              proxies={list}
              nodes={nodes.data}
              listeners={listeners.data}
              selection={{ selected: chosen, onChange: setSelected }}
            />
          )
        }
      </QueryView>

      <SwitchEngineDialog
        opened={switching}
        proxyIds={chosen}
        onClose={() => {
          setSwitching(false);
        }}
        onStarted={() => {
          setSelected([]);
        }}
      />
      <ProxyCreateDialog
        opened={adding}
        nodeId={nodeId === "" ? undefined : nodeId}
        onClose={() => {
          setAdding(false);
        }}
      />
    </Stack>
  );
}
