import { Accordion, Alert, Button, Checkbox, Group, List, Stack, Table, Title } from "@mantine/core";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../../api/errors";
import { formatBytes, hostPort, orDash } from "../../app/format";
import { canInstall, issueText } from "../../app/deploy";
import type { PortCheck, PreflightReport } from "../../gen/postern/panel/v1/deploy_pb";
import { DefinitionList } from "../DefinitionList";

function portText(t: TFunction, port: PortCheck | undefined): string {
  if (port === undefined) {
    return "—";
  }
  if (port.free) {
    return t("deploy.report.portFree");
  }
  if (port.postern) {
    return t("deploy.report.portPostern");
  }
  return t("deploy.report.portTaken", { owner: port.owner });
}

function clockText(t: TFunction, skew: bigint): string {
  const seconds = Number(skew);
  if (Math.abs(seconds) < 2) {
    return t("deploy.report.clockOk");
  }
  return seconds > 0
    ? t("deploy.report.clockAhead", { seconds })
    : t("deploy.report.clockBehind", { seconds: -seconds });
}

function archText(t: TFunction, report: PreflightReport): string {
  if (report.arch === "") {
    return t("deploy.report.unsupported", { machine: orDash(report.machine) });
  }
  const arch = report.machine === report.arch ? report.arch : `${report.machine} (${report.arch})`;
  // The Docker path needs no node kit.
  return report.kitAvailable || report.installMethod === "docker" ? arch : t("deploy.report.noKit", { arch });
}

function dockerText(t: TFunction, report: PreflightReport): string {
  if (!report.dockerInstalled) {
    return t("deploy.report.dockerMissing");
  }
  if (report.dockerVersion === "") {
    return t("deploy.report.dockerDown");
  }
  return report.usernsRemap ? t("deploy.report.userns", { version: report.dockerVersion }) : report.dockerVersion;
}

interface PreflightReportViewProps {
  report: PreflightReport;
  installDocker: boolean;
  onInstallDocker: (value: boolean) => void;
  remember: boolean;
  onRemember: (value: boolean) => void;
  installing: boolean;
  checking: boolean;
  /** Why the last try to install, or to check again, failed. */
  error: unknown;
  onInstall: () => void;
  onRecheck: () => void;
  onBack: () => void;
}

/**
 * What the preflight found: the issues first, the blockers and then the
 * warnings, both marked out, then the facts of the server, and the choices of
 * the install.
 */
export function PreflightReportView(props: PreflightReportViewProps) {
  const { t } = useTranslation();
  const { report } = props;
  const blockers = report.issues.filter((issue) => issue.severity === "blocker");
  const warnings = report.issues.filter((issue) => issue.severity !== "blocker");
  const dockerFixes = report.issues.some((issue) => issue.fixedByDockerInstall);
  const ready = canInstall(report, props.installDocker);
  const docker = report.installMethod === "docker";

  return (
    <Stack gap="md">
      <Title order={2} size="h3">
        {t("deploy.report.title")}
      </Title>
      {blockers.length > 0 ? (
        <Alert color="red" title={t("deploy.report.blockers")}>
          <List size="sm" spacing={4}>
            {blockers.map((issue) => (
              <List.Item key={issue.code}>{issueText(t, issue)}</List.Item>
            ))}
          </List>
        </Alert>
      ) : null}
      {warnings.length > 0 ? (
        <Alert color="yellow" title={t("deploy.report.warnings")}>
          <List size="sm" spacing={4}>
            {warnings.map((issue) => (
              <List.Item key={issue.code}>{issueText(t, issue)}</List.Item>
            ))}
          </List>
        </Alert>
      ) : null}

      <DefinitionList
        items={[
          {
            label: t("deploy.report.method"),
            value: docker ? t("deploy.report.methodDocker") : t("deploy.report.methodKit"),
          },
          { label: t("deploy.report.system"), value: orDash(report.os) },
          { label: t("deploy.report.arch"), value: archText(t, report) },
          { label: t("deploy.report.docker"), value: dockerText(t, report) },
          // Compose matters to install.sh only.
          ...(report.dockerInstalled && !docker
            ? [
                {
                  label: t("deploy.report.compose"),
                  value: report.composeVersion === "" ? t("deploy.report.composeMissing") : report.composeVersion,
                },
              ]
            : []),
          {
            label: t("deploy.report.disk", { path: report.diskPath || "/" }),
            value: report.diskTotalBytes === 0n ? t("deploy.report.diskUnknown") : formatBytes(report.diskFreeBytes),
          },
          { label: t("deploy.report.httpsPort"), value: portText(t, report.httpsPort) },
          {
            label: t("deploy.report.mgmtPort", { port: report.mgmtPort?.port ?? 0 }),
            value: portText(t, report.mgmtPort),
          },
          {
            label: t("deploy.report.publicIps"),
            value:
              report.publicIps.length === 0
                ? t("deploy.report.noPublicIps")
                : report.publicIps
                    .map((ip) => (ip === report.dialedIp ? t("deploy.report.dialed", { address: ip }) : ip))
                    .join(", "),
          },
          { label: t("deploy.report.clock"), value: clockText(t, report.clockSkewSeconds) },
          ...(docker ? [] : [{ label: t("deploy.report.installDir"), value: orDash(report.installDir) }]),
        ]}
      />

      {report.listening.length > 0 ? (
        <Accordion variant="contained" chevronPosition="left">
          <Accordion.Item value="listening">
            <Accordion.Control>{t("deploy.report.listening", { count: report.listening.length })}</Accordion.Control>
            <Accordion.Panel>
              <Table.ScrollContainer minWidth={360}>
                <Table striped withTableBorder fz="sm">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t("deploy.report.address")}</Table.Th>
                      <Table.Th>{t("deploy.report.processes")}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {report.listening.map((socket, index) => (
                      // Sockets of SO_REUSEPORT share an address and a port.
                      <Table.Tr key={`${String(index)} ${socket.address}:${String(socket.port)}`}>
                        <Table.Td style={{ whiteSpace: "nowrap" }}>{hostPort(socket.address || "*", socket.port)}</Table.Td>
                        <Table.Td>
                          {socket.processes.length === 0 ? t("deploy.report.unknownProcess") : socket.processes.join(", ")}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      ) : null}

      <Stack gap="xs">
        {dockerFixes ? (
          <Checkbox
            label={t("deploy.report.installDocker")}
            description={t("deploy.report.installDockerHint")}
            checked={props.installDocker}
            onChange={(event) => {
              props.onInstallDocker(event.currentTarget.checked);
            }}
          />
        ) : null}
        <Checkbox
          label={t("deploy.report.remember")}
          description={t("deploy.report.rememberHint")}
          checked={props.remember}
          onChange={(event) => {
            props.onRemember(event.currentTarget.checked);
          }}
        />
      </Stack>

      {props.error === null || props.error === undefined ? null : (
        <Alert color="red" title={t("common.error")}>
          {errorMessage(props.error)}
        </Alert>
      )}
      <Group>
        <Button onClick={props.onInstall} loading={props.installing} disabled={!ready || props.checking}>
          {t("deploy.report.install")}
        </Button>
        <Button variant="default" onClick={props.onRecheck} loading={props.checking} disabled={props.installing}>
          {t("deploy.report.recheck")}
        </Button>
        <Button variant="subtle" onClick={props.onBack} disabled={props.installing || props.checking}>
          {t("common.back")}
        </Button>
      </Group>
    </Stack>
  );
}
