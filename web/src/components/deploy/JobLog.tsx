import { Alert, Anchor, Badge, Box, Button, Group, Stack, Title } from "@mantine/core";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { errorMessage } from "../../api/errors";
import { useCancelJob, useJob } from "../../api/hooks/deploy";
import { cancelledNotice } from "../../app/deploy";
import type { Job } from "../../gen/postern/panel/v1/deploy_pb";
import { ConfirmDialog } from "../ConfirmDialog";
import { QueryView } from "../QueryView";

const statusColors = { running: "blue", done: "teal", failed: "red", cancelled: "gray" } as const;

function isStatus(value: string): value is keyof typeof statusColors {
  return Object.hasOwn(statusColors, value);
}

interface JobLogProps {
  jobId: string;
  nodeId: string;
  /** Starts the wizard again, after a job that failed or was cancelled. */
  onAgain: () => void;
}

/**
 * The install as it runs: its status, and its log, which the panel is asked
 * for every second until the job ends. The log keeps to its newest lines.
 */
export function JobLog({ jobId, nodeId, onAgain }: JobLogProps) {
  const job = useJob(jobId, nodeId);
  return <QueryView query={job}>{(data) => <JobView job={data} nodeId={nodeId} onAgain={onAgain} />}</QueryView>;
}

function JobView({ job, nodeId, onAgain }: { job: Job; nodeId: string; onAgain: () => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const cancel = useCancelJob();
  const [confirming, setConfirming] = useState(false);
  const logRef = useRef<HTMLPreElement>(null);
  const status = isStatus(job.status) ? job.status : undefined;
  const notice = cancelledNotice(job.error);

  // The newest lines stay in sight while they come.
  useEffect(() => {
    const element = logRef.current;
    if (element !== null) {
      element.scrollTop = element.scrollHeight;
    }
  }, [job.log]);

  return (
    <Stack gap="md">
      <Group gap="sm" align="center">
        <Title order={2} size="h3" id={titleId}>
          {t("deploy.job.log")}
        </Title>
        <Badge variant="light" color={status === undefined ? "gray" : statusColors[status]}>
          {status === undefined ? job.status : t(`deploy.job.${status}`)}
        </Badge>
      </Group>
      <Box
        component="pre"
        ref={logRef}
        role="log"
        aria-labelledby={titleId}
        tabIndex={0}
        m={0}
        p="sm"
        style={{
          maxHeight: "28rem",
          overflow: "auto",
          whiteSpace: "pre-wrap",
          overflowWrap: "anywhere",
          fontFamily: "var(--mantine-font-family-monospace)",
          fontSize: "var(--mantine-font-size-xs)",
          background: "var(--mantine-color-default-hover)",
          borderRadius: "var(--mantine-radius-sm)",
        }}
      >
        {job.log === "" ? t("deploy.job.waiting") : job.log}
      </Box>

      {status === "done" ? (
        <Alert color="teal" title={t("deploy.job.doneMessage")}>
          <Anchor component={Link} to={`/nodes/${nodeId}`} size="sm">
            {t("deploy.job.toNode")}
          </Anchor>
        </Alert>
      ) : null}
      {status === "failed" ? (
        <Alert color="red" title={t("deploy.job.failedMessage", { error: job.error })} />
      ) : null}
      {status === "cancelled" ? (
        <Alert color={notice === "" ? "gray" : "orange"} title={t("deploy.job.cancelledMessage")}>
          {notice === "" ? null : notice}
        </Alert>
      ) : null}
      {cancel.isError ? (
        <Alert color="red" title={t("common.error")}>
          {errorMessage(cancel.error)}
        </Alert>
      ) : null}

      <Group>
        {status === "running" ? (
          <Button
            variant="light"
            color="red"
            onClick={() => {
              setConfirming(true);
            }}
          >
            {t("deploy.job.cancel")}
          </Button>
        ) : (
          <>
            <Button variant="default" onClick={onAgain}>
              {t("deploy.job.again")}
            </Button>
            <Button component={Link} to={`/nodes/${nodeId}`} variant="subtle">
              {t("deploy.job.toNode")}
            </Button>
          </>
        )}
      </Group>

      <ConfirmDialog
        opened={confirming}
        title={t("deploy.job.cancelTitle")}
        message={t("deploy.job.cancelMessage")}
        confirmLabel={t("deploy.job.cancelConfirm")}
        loading={cancel.isPending}
        onConfirm={() => {
          cancel.mutate(job.id, {
            onSettled: () => {
              setConfirming(false);
            },
          });
        }}
        onClose={() => {
          setConfirming(false);
        }}
      />
    </Stack>
  );
}
