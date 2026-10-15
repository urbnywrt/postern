import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { vi } from "vitest";

import { checkPanelUrl } from "../app/panelUrl";
import {
  type CancelJobRequest,
  type GetJobRequest,
  type GetTargetRequest,
  type InstallRequest,
  type Job,
  JobSchema,
  type PreflightReport,
  PreflightReportSchema,
  type PreflightRequest,
  type SshTarget,
  SshTargetSchema,
} from "../gen/postern/panel/v1/deploy_pb";

// An in-memory DeployService. It answers like the panel where the wizard can
// tell: the first contact with a server shows its host key, a changed key is
// refused until it is trusted, the report is the one that the test sets, and a
// job moves on by one step each time it is asked for. The values are
// documentation addresses and made-up keys only.

/** The host key of the fake server: made up, in the form that ssh-keygen prints. */
export const HOST_KEY = "SHA256:K3mLp7bEXAMPLEexampleEXAMPLEexample0123456";
export const HOST_KEY_TYPE = "ssh-ed25519";
/** Another key of the server, for a key that has changed. */
export const NEW_HOST_KEY = "SHA256:N3wK3yEXAMPLEexampleEXAMPLEexample98765432";
/** The password of the server, for the tests to type. Made by repetition: it is no real credential. */
export const SSH_PASSWORD = "s".repeat(14);

type ReportInit = MessageInitShape<typeof PreflightReportSchema>;

/** What a job is at one step. */
export interface JobStep {
  status: string;
  log?: string;
  error?: string;
  finishedUnix?: bigint;
}

/** A report of a server that is ready for the install: Ubuntu, Docker, free ports. */
export function makeReport(init: ReportInit = {}): PreflightReport {
  return create(PreflightReportSchema, {
    os: "Ubuntu 24.04.1 LTS",
    machine: "x86_64",
    arch: "amd64",
    kitAvailable: true,
    installDir: "/root/postern-install",
    dockerInstalled: true,
    dockerVersion: "27.5.1",
    composeVersion: "2.27.1",
    diskPath: "/opt",
    diskFreeBytes: 38_000_000_000n,
    diskTotalBytes: 41_000_000_000n,
    listening: [
      { address: "0.0.0.0", port: 22, processes: ["sshd (pid 1021)"] },
      { address: "127.0.0.53", port: 53, processes: ["systemd-resolve (pid 612)"] },
    ],
    publicIps: ["203.0.113.10", "2001:db8:10::a"],
    clockSkewSeconds: 0n,
    httpsPort: { port: 443, free: true },
    mgmtPort: { port: 61001, free: true },
    issues: [],
    ...init,
  } as ReportInit);
}

/** The steps of a job that installs a node and ends done. */
export const DONE_STEPS: JobStep[] = [
  { status: "running", log: "==> Connecting to root@203.0.113.10:22\n" },
  { status: "running", log: "==> Connecting to root@203.0.113.10:22\n==> Running install.sh\n" },
  {
    status: "done",
    log: "==> Connecting to root@203.0.113.10:22\n==> Running install.sh\n==> Waiting for the node to come online\n==> Done\n",
    finishedUnix: 1n,
  },
];

export interface FakeDeployState {
  /** What GetTarget answers: the target that the panel keeps, and whether it keeps credentials. */
  target?: SshTarget;
  savedCredentials: string;
  /** The key that the server presents. */
  serverKey: string;
  /** The server offers no key of the type of the confirmed one: it presents none, until it is met again. */
  noKeyOfType?: boolean;
  /** The report of the next preflights. */
  report: PreflightReport;
  /** The steps of the next job: each GetJob moves on by one. */
  steps: JobStep[];
  jobs: Map<string, { job: Job; step: number; steps: JobStep[] }>;
  /** The error that the next preflight answers with, once. */
  preflightError?: ConnectError;
  /** The error of a job that is cancelled; "the job was cancelled" when unset. */
  cancelError?: string;
}

/**
 * The handlers of DeployService. `requireSession` throws the 401 of a visitor; `nodeImage` is the node image of the
 * panel, which, with a valid panel address in the request, makes the report one of the Docker path.
 */
export function createFakeDeploy(requireSession: () => void, nodeImage: () => string = () => "") {
  const state: FakeDeployState = {
    savedCredentials: "",
    serverKey: HOST_KEY,
    report: makeReport(),
    steps: DONE_STEPS,
    jobs: new Map(),
  };
  let sequence = 0;

  const needCredentials = (req: { credentials?: { password: string; privateKey: string; useSaved: boolean } }) => {
    const c = req.credentials;
    if (c === undefined || (c.password === "" && c.privateKey === "" && !c.useSaved)) {
      throw new ConnectError("a password or a private key is needed to log in", Code.InvalidArgument);
    }
    if (c.password !== "" && c.password !== SSH_PASSWORD) {
      throw new ConnectError("sshx: the server refused the credentials", Code.PermissionDenied);
    }
  };

  const job = (id: string) => {
    const entry = state.jobs.get(id);
    if (entry === undefined) {
      throw new ConnectError("no such job", Code.NotFound);
    }
    return entry;
  };

  const rpc = {
    getTarget: vi.fn((req: GetTargetRequest) => {
      requireSession();
      const running = [...state.jobs.values()].find((entry) => entry.job.nodeId === req.nodeId && entry.job.status === "running");
      return { target: state.target, savedCredentials: state.savedCredentials, runningJobId: running?.job.id ?? "" };
    }),

    preflight: vi.fn((req: PreflightRequest) => {
      requireSession();
      needCredentials(req);
      if (req.replaceHostKey && req.credentials?.useSaved === true) {
        throw new ConnectError(
          "the saved credentials are not sent to a server whose host key is replaced: give the credentials",
          Code.InvalidArgument,
        );
      }
      const failure = state.preflightError;
      if (failure !== undefined) {
        state.preflightError = undefined;
        throw failure;
      }
      const t = req.target ?? create(SshTargetSchema);
      const known = state.target?.host === t.host && state.target.port === t.port ? state.target.hostKey : "";
      const confirmed = req.replaceHostKey ? t.hostKey : known !== "" ? known : t.hostKey;
      if (confirmed === "") {
        return { result: { case: "hostKey" as const, value: { fingerprint: state.serverKey, type: HOST_KEY_TYPE } } };
      }
      if (confirmed !== state.serverKey) {
        return {
          result: {
            case: "hostKeyChanged" as const,
            value: {
              confirmed: { fingerprint: confirmed, type: HOST_KEY_TYPE },
              presented: { fingerprint: state.noKeyOfType === true ? "" : state.serverKey, type: HOST_KEY_TYPE },
            },
          },
        };
      }
      state.target = create(SshTargetSchema, { ...t, hostKey: state.serverKey, hostKeyType: HOST_KEY_TYPE });
      // As the panel: the Docker path with a node image and a valid panel address, the kit path otherwise.
      const docker = nodeImage() !== "" && checkPanelUrl(req.panelUrl).ok;
      const report = create(PreflightReportSchema, {
        ...state.report,
        installMethod: docker ? "docker" : "kit",
        installDir: docker ? "" : state.report.installDir,
      });
      return { result: { case: "report" as const, value: report } };
    }),

    install: vi.fn((req: InstallRequest) => {
      requireSession();
      needCredentials(req);
      if ((req.target?.hostKey ?? "") === "" && state.target?.hostKey === undefined) {
        throw new ConnectError("the host key of the server has not been confirmed: run the preflight first", Code.FailedPrecondition);
      }
      for (const entry of state.jobs.values()) {
        if (entry.job.nodeId === req.nodeId && entry.job.status === "running") {
          throw new ConnectError("the node is running a job already", Code.FailedPrecondition);
        }
      }
      const id = `job-${String(++sequence)}`;
      const steps = state.steps;
      const first = steps[0] ?? { status: "running" };
      state.jobs.set(id, {
        job: create(JobSchema, { kind: "install", startedUnix: 1n, ...first, id, nodeId: req.nodeId }),
        step: 0,
        steps,
      });
      state.savedCredentials = req.remember ? (req.credentials?.privateKey ? "key" : "password") : "";
      return { jobId: id };
    }),

    getJob: vi.fn((req: GetJobRequest) => {
      requireSession();
      const entry = job(req.id);
      const answer = entry.job;
      if (answer.status === "running" && entry.step + 1 < entry.steps.length) {
        entry.step++;
        entry.job = create(JobSchema, { ...answer, ...entry.steps[entry.step] });
      }
      return { job: answer };
    }),

    cancelJob: vi.fn((req: CancelJobRequest) => {
      requireSession();
      const entry = job(req.id);
      if (entry.job.status !== "running") {
        throw new ConnectError("the job is not running", Code.FailedPrecondition);
      }
      entry.job = create(JobSchema, {
        ...entry.job,
        status: "cancelled",
        error: state.cancelError ?? "the job was cancelled",
        log: `${entry.job.log}==> Removing the bundle, which holds the private key of the node\n`,
      });
      entry.steps = [];
      return {};
    }),
  };

  return { rpc, state };
}
