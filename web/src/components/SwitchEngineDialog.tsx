import { Alert, List, Modal, Radio, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useNodes } from "../api/hooks/nodes";
import { useProxies } from "../api/hooks/proxies";
import { proxyTitle } from "../app/proxy";
import { mtgBlockers } from "../app/versions";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import type { Rollout } from "../gen/postern/panel/v1/versions_pb";
import { PageLoader } from "./PageLoader";
import { RolloutForm } from "./RolloutDialog";

const ENGINES = ["telemt", "mtg"] as const;

interface SwitchEngineDialogProps {
  opened: boolean;
  /** The proxies to switch: one from its page, or those selected in the list. */
  proxyIds: string[];
  onClose: () => void;
  onStarted?: (rollout: Rollout) => void;
}

/**
 * Switches proxies to an engine, optionally pinned to a version, as a switch
 * rollout. mtg is offered only when every proxy can run it; otherwise it is
 * disabled and the reasons are listed (with the proxy's name when there are
 * several).
 */
export function SwitchEngineDialog({ opened, proxyIds, onClose, onStarted }: SwitchEngineDialogProps) {
  const { t } = useTranslation();
  const proxies = useProxies({}, { enabled: opened });
  // The capabilities of the nodes decide whether mtg is offered: the form waits for them.
  const nodes = useNodes({ enabled: opened });
  const selected = (proxies.data ?? []).filter((p) => proxyIds.includes(p.id));
  const title =
    selected.length === 1 && selected[0] !== undefined
      ? t("versions.rollout.titleSwitchOne", { name: proxyTitle(selected[0]) })
      : t("versions.rollout.titleSwitchMany", { count: proxyIds.length });
  return (
    <Modal opened={opened} onClose={onClose} title={title} centered size="lg">
      {opened ? (
        proxies.data === undefined || nodes.data === undefined ? (
          <PageLoader />
        ) : (
          <SwitchForm
            key={proxyIds.join(",")}
            proxies={selected}
            nodes={nodes.data}
            onCancel={onClose}
            onStarted={(rollout) => {
              onStarted?.(rollout);
              onClose();
            }}
          />
        )
      ) : null}
    </Modal>
  );
}

interface SwitchFormProps {
  proxies: Proxy[];
  nodes: Node[];
  onCancel: () => void;
  onStarted: (r: Rollout) => void;
}

function SwitchForm({ proxies, nodes, onCancel, onStarted }: SwitchFormProps) {
  const { t } = useTranslation();
  const blocked = proxies.flatMap((proxy) =>
    mtgBlockers(proxy, nodes.find((n) => n.id === proxy.nodeId)).map((reason) => ({ proxy, reason })),
  );
  const mtgAllowed = blocked.length === 0;
  const allOn = (engine: string) => proxies.length > 0 && proxies.every((p) => p.engine === engine);
  // The other engine when it is allowed; else the engine they run (a change of version).
  const initial = allOn("telemt") && mtgAllowed ? "mtg" : allOn("mtg") ? "telemt" : mtgAllowed ? "mtg" : "telemt";
  const [engine, setEngine] = useState<string>(initial);
  const chosen = engine === "mtg" && !mtgAllowed ? "telemt" : engine;

  return (
    <Stack gap="md">
      <Radio.Group
        label={t("versions.switch.engine")}
        value={chosen}
        onChange={setEngine}
      >
        <Stack gap={6} mt={6}>
          {ENGINES.map((name) => (
            <Radio key={name} value={name} label={name} disabled={name === "mtg" && !mtgAllowed} />
          ))}
        </Stack>
      </Radio.Group>
      {!mtgAllowed ? (
        <Alert color="gray" title={t("versions.switch.mtgUnavailable")}>
          <List size="sm" spacing={2}>
            {blocked.map(({ proxy, reason }) => (
              <List.Item key={`${proxy.id}-${reason}`}>
                {proxies.length > 1 ? `${proxyTitle(proxy)}: ` : ""}
                {t(`versions.switch.reason.${reason}`)}
              </List.Item>
            ))}
          </List>
        </Alert>
      ) : null}
      {proxies.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("versions.switch.none")}
        </Text>
      ) : (
        <RolloutForm
          key={chosen}
          target={{ kind: "switch", engine: chosen, proxyIds: proxies.map((p) => p.id) }}
          onCancel={onCancel}
          onStarted={onStarted}
        />
      )}
    </Stack>
  );
}
