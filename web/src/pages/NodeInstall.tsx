import { Anchor, Paper, Stack, Stepper, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams, useSearchParams } from "react-router";

import { useDeployTarget, useInstall, usePreflight } from "../api/hooks/deploy";
import { useNode, useNodeInstall } from "../api/hooks/nodes";
import { rememberPanelUrl, storedPanelUrl } from "../app/panelUrl";
import { HostKeyChangedView, HostKeyConfirm } from "../components/deploy/HostKeyConfirm";
import { JobLog } from "../components/deploy/JobLog";
import { PreflightReportView } from "../components/deploy/PreflightReportView";
import { SshTargetForm, type TargetValues } from "../components/deploy/SshTargetForm";
import { BackIcon } from "../components/icons";
import { NotFoundNotice } from "../components/NotFoundNotice";
import { QueryView } from "../components/QueryView";
import type {
  GetTargetResponse,
  HostKey,
  HostKeyChanged,
  PreflightReport,
  PreflightResponse,
} from "../gen/postern/panel/v1/deploy_pb";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";

/** Where the wizard is. */
type Stage =
  | { kind: "target" }
  | { kind: "hostKey"; hostKey: HostKey }
  | { kind: "changed"; change: HostKeyChanged }
  | { kind: "report"; report: PreflightReport }
  | { kind: "job"; jobId: string };

const stepOf: Record<Stage["kind"], number> = { target: 0, hostKey: 1, changed: 1, report: 2, job: 3 };

/**
 * The key that the admin confirmed in this wizard, for the server that it was
 * confirmed for. An empty fingerprint that replaces the kept key meets the
 * server again, as for the first time.
 */
interface Confirmed {
  server: string;
  fingerprint: string;
  type: string;
  /** It replaces the key that the panel keeps for the server. */
  replace: boolean;
}

const DEFAULT_SSH_PORT = 22;

/**
 * Installs a node over SSH: the server and how to log in, the host key of the
 * server, the check of the server, and the install with its live log. The job
 * of an install is in the address (?job=), and the panel says which job a node
 * runs, so a reload comes back to the log.
 */
export function NodeInstall() {
  const { t } = useTranslation();
  const { nodeId = "" } = useParams();
  const node = useNode(nodeId);
  return (
    <QueryView query={node} notFound={<NotFoundNotice backTo="/nodes" backLabel={t("nodes.title")} />}>
      {(data) => <Wizard node={data} />}
    </QueryView>
  );
}

function Wizard({ node }: { node: Node }) {
  const { t } = useTranslation();
  const target = useDeployTarget(node.id);
  return (
    <Stack gap="lg">
      <Anchor component={Link} to={`/nodes/${node.id}`} size="sm" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <BackIcon />
        {node.name}
      </Anchor>
      <Stack gap={4}>
        <Title order={1}>{t("deploy.title")}</Title>
        <Text size="sm" c="dimmed">
          {t("deploy.intro", { name: node.name })}
        </Text>
      </Stack>
      <QueryView query={target}>{(saved) => <Steps node={node} saved={saved} />}</QueryView>
    </Stack>
  );
}

function Steps({ node, saved }: { node: Node; saved: GetTargetResponse }) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const preflight = usePreflight();
  const install = useInstall();
  // The node image of the panel makes the install the Docker path (GetNodeInstall.node_image). The form of
  // the server waits for it: a form sent before it is known would take the kit path without a word.
  const nodeInstall = useNodeInstall(node.id);
  const nodeImage = nodeInstall.data?.nodeImage ?? "";

  const [stage, setStage] = useState<Stage>(() => {
    const job = params.get("job") ?? saved.runningJobId;
    return job === "" ? { kind: "target" } : { kind: "job", jobId: job };
  });
  const [values, setValues] = useState<TargetValues>(() => ({
    host: saved.target?.host ?? node.mgmtHost,
    port: String(saved.target?.port ?? DEFAULT_SSH_PORT),
    user: saved.target?.user ?? "root",
    method: saved.savedCredentials === "" ? "password" : "saved",
    password: "",
    privateKey: "",
    passphrase: "",
    panelUrl: storedPanelUrl(),
  }));
  const [confirmed, setConfirmed] = useState<Confirmed | undefined>(undefined);
  const [installDocker, setInstallDocker] = useState(false);
  const [remember, setRemember] = useState(saved.savedCredentials !== "");

  const server = (v: TargetValues) => `${v.host.trim()}:${v.port.trim()}`;

  /** The key that the admin confirmed for the server of the form, if any. */
  const keyFor = (v: TargetValues, key: Confirmed | undefined) => (key?.server === server(v) ? key : undefined);

  /** The node, the target and the credentials of a call, from the form and the key that the admin confirmed. */
  function request(v: TargetValues, key: Confirmed | undefined) {
    const own = keyFor(v, key);
    return {
      nodeId: node.id,
      target: {
        host: v.host.trim(),
        port: Number(v.port.trim()),
        user: v.user.trim(),
        hostKey: own?.fingerprint ?? "",
        hostKeyType: own?.type ?? "",
      },
      credentials:
        v.method === "saved"
          ? { useSaved: true }
          : v.method === "key"
            ? { privateKey: v.privateKey, passphrase: v.passphrase }
            : { password: v.password },
      // Empty on the kit path; the panel takes the Docker path for a valid address.
      panelUrl: nodeImage === "" ? "" : v.panelUrl,
    };
  }

  function answered(response: PreflightResponse) {
    switch (response.result.case) {
      case "hostKey":
        setStage({ kind: "hostKey", hostKey: response.result.value });
        return;
      case "hostKeyChanged":
        setStage({ kind: "changed", change: response.result.value });
        return;
      case "report":
        setStage({ kind: "report", report: response.result.value });
        return;
      default:
        setStage({ kind: "target" });
    }
  }

  function check(v: TargetValues, key: Confirmed | undefined) {
    preflight.mutate({ ...request(v, key), replaceHostKey: keyFor(v, key)?.replace ?? false }, { onSuccess: answered });
  }

  function startInstall() {
    install.mutate(
      { ...request(values, confirmed), installDocker, remember },
      {
        onSuccess: (jobId) => {
          // The credentials are not needed any more: the page lets go of them.
          setValues((v) => ({ ...v, password: "", privateKey: "", passphrase: "" }));
          preflight.reset();
          install.reset();
          setParams({ job: jobId }, { replace: true });
          setStage({ kind: "job", jobId });
        },
      },
    );
  }

  function again() {
    setParams({}, { replace: true });
    preflight.reset();
    install.reset();
    setStage({ kind: "target" });
  }

  const back = () => {
    preflight.reset();
    install.reset();
    setStage({ kind: "target" });
  };

  return (
    <Paper withBorder p="lg" radius="md">
      <Stack gap="lg">
        <Stepper active={stepOf[stage.kind]} size="sm" allowNextStepsSelect={false}>
          <Stepper.Step label={t("deploy.steps.target")} />
          <Stepper.Step label={t("deploy.steps.hostKey")} />
          <Stepper.Step label={t("deploy.steps.check")} />
          <Stepper.Step label={t("deploy.steps.install")} />
        </Stepper>

        {stage.kind === "target" ? (
          <QueryView query={nodeInstall}>
            {(info) => (
              <SshTargetForm
                initial={values}
                saved={saved.target}
                savedCredentials={saved.savedCredentials}
                nodeImage={info.nodeImage}
                pending={preflight.isPending}
                error={preflight.error}
                onSubmit={(v) => {
                  if (info.nodeImage !== "") {
                    rememberPanelUrl(v.panelUrl);
                  }
                  setValues(v);
                  check(v, confirmed);
                }}
              />
            )}
          </QueryView>
        ) : null}
        {stage.kind === "hostKey" ? (
          <HostKeyConfirm
            hostKey={stage.hostKey}
            pending={preflight.isPending}
            error={preflight.error}
            onBack={back}
            onConfirm={() => {
              const key = {
                server: server(values),
                fingerprint: stage.hostKey.fingerprint,
                type: stage.hostKey.type,
                replace: keyFor(values, confirmed)?.replace ?? false,
              };
              setConfirmed(key);
              check(values, key);
            }}
          />
        ) : null}
        {stage.kind === "changed" ? (
          <HostKeyChangedView
            change={stage.change}
            savedCredentials={values.method === "saved"}
            pending={preflight.isPending}
            error={preflight.error}
            onBack={back}
            onTrust={() => {
              const key = {
                server: server(values),
                fingerprint: stage.change.presented?.fingerprint ?? "",
                type: stage.change.presented?.type ?? "",
                replace: true,
              };
              setConfirmed(key);
              check(values, key);
            }}
          />
        ) : null}
        {stage.kind === "report" ? (
          <PreflightReportView
            report={stage.report}
            installDocker={installDocker}
            onInstallDocker={setInstallDocker}
            remember={remember}
            onRemember={setRemember}
            installing={install.isPending}
            checking={preflight.isPending}
            error={install.error ?? preflight.error}
            onInstall={startInstall}
            onRecheck={() => {
              check(values, confirmed);
            }}
            onBack={back}
          />
        ) : null}
        {stage.kind === "job" ? <JobLog jobId={stage.jobId} nodeId={node.id} onAgain={again} /> : null}
      </Stack>
    </Paper>
  );
}
