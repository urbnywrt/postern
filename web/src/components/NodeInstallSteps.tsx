import { Accordion, Alert, Box, Button, Group, SegmentedControl, Stack, Text, ThemeIcon } from "@mantine/core";
import { type ReactNode, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useNodeInstall } from "../api/hooks/nodes";
import {
  BUNDLE_FILE,
  bundleHref,
  copyCommand,
  DEFAULT_ARCH,
  installCommandFor,
  kitFile,
  kitHref,
} from "../app/bundle";
import type { GetNodeInstallResponse } from "../gen/postern/panel/v1/nodes_pb";
import { CommandLine } from "./CommandLine";
import { DownloadIcon } from "./icons";
import { QueryView } from "./QueryView";

/**
 * How to install a node by hand, as the panel says (GetNodeInstall): download the
 * bundle and the node kit of the architecture of the server, copy both to the
 * server, and run the install command there. Without a kit for the architecture
 * the bundle alone is copied, the command does not unpack a kit, and a note says
 * where the binary and the scripts come from instead.
 */
export function NodeInstallSteps({ nodeId }: { nodeId: string }) {
  const install = useNodeInstall(nodeId);
  return <QueryView query={install}>{(data) => <Steps nodeId={nodeId} install={data} />}</QueryView>;
}

/**
 * The steps, folded away under "Without a registry": the install with one Docker
 * command comes first, and this is for a server that cannot pull the node image.
 */
export function NodeManualInstall({ nodeId }: { nodeId: string }) {
  const { t } = useTranslation();
  return (
    <Accordion variant="contained">
      <Accordion.Item value="manual">
        <Accordion.Control>{t("nodes.install.manualBlock")}</Accordion.Control>
        <Accordion.Panel>
          <NodeInstallSteps nodeId={nodeId} />
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  );
}

function Steps({ nodeId, install }: { nodeId: string; install: GetNodeInstallResponse }) {
  const { t } = useTranslation();
  const archLabelId = useId();
  const arches = install.kits.map((kit) => kit.arch);
  const [picked, setPicked] = useState(DEFAULT_ARCH);
  const arch = arches.includes(picked) ? picked : (arches[0] ?? DEFAULT_ARCH);
  const kit = install.kits.find((entry) => entry.arch === arch);
  const withKit = kit?.available === true;

  return (
    <Stack gap="md">
      <Text size="sm">{t("nodes.install.intro")}</Text>
      <Box
        component="ol"
        role="list"
        style={{
          listStyle: "none",
          margin: 0,
          padding: 0,
          display: "flex",
          flexDirection: "column",
          gap: "var(--mantine-spacing-lg)",
        }}
      >
        <Step number={1} title={t("nodes.install.bundleStep")}>
          <Alert color="yellow" variant="light">
            {t("nodes.install.secret")}
          </Alert>
          <Button
            component="a"
            href={bundleHref(nodeId, install.bundleUrl)}
            download={BUNDLE_FILE}
            leftSection={<DownloadIcon />}
            w="fit-content"
          >
            {t("nodes.install.downloadBundle")}
          </Button>
        </Step>

        <Step number={2} title={t("nodes.install.kitStep")}>
          <Group gap="sm" align="center">
            <Text id={archLabelId} size="sm" fw={500}>
              {t("nodes.install.arch")}
            </Text>
            <SegmentedControl aria-labelledby={archLabelId} data={arches} value={arch} onChange={setPicked} />
          </Group>
          <Text size="xs" c="dimmed">
            {t("nodes.install.archHint")}
          </Text>
          {withKit ? (
            <Button
              component="a"
              href={kitHref(arch, kit.url)}
              download={kitFile(arch)}
              leftSection={<DownloadIcon />}
              w="fit-content"
            >
              {t("nodes.install.downloadKit", { arch })}
            </Button>
          ) : (
            <Alert color="blue" variant="light">
              {t("nodes.install.noKit", { arch, version: kit?.version ?? "" })}
            </Alert>
          )}
        </Step>

        <Step number={3} title={t(withKit ? "nodes.install.copyStep" : "nodes.install.copyStepNoKit")}>
          <CommandLine text={copyCommand(arch, withKit)} copyLabel={t("nodes.install.copyScp")} />
        </Step>

        <Step number={4} title={t("nodes.install.runStep")}>
          <CommandLine
            text={installCommandFor(install.installCommand, arch, withKit)}
            copyLabel={t("nodes.install.copyCommand")}
          />
        </Step>
      </Box>
    </Stack>
  );
}

/** One step: its number, what it is, and what it takes. */
function Step({ number, title, children }: { number: number; title: string; children: ReactNode }) {
  return (
    <Box component="li" style={{ display: "flex", gap: "var(--mantine-spacing-sm)", alignItems: "flex-start" }}>
      {/* The list numbers the steps for a screen reader; this is the number for the eye. */}
      <ThemeIcon variant="light" radius="xl" size="md" aria-hidden="true" style={{ flexShrink: 0 }}>
        <Text size="sm" fw={600} span>
          {number}
        </Text>
      </ThemeIcon>
      <Stack gap="xs" style={{ flex: 1, minWidth: 0 }}>
        <Text size="sm">{title}</Text>
        {children}
      </Stack>
    </Box>
  );
}
