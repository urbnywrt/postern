import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { configure, screen, waitFor, within } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { PANEL_URL_KEY } from "../app/panelUrl";
import { JobSchema, PreflightIssueSchema, SshTargetSchema } from "../gen/postern/panel/v1/deploy_pb";
import { HOST_KEY, HOST_KEY_TYPE, makeReport, NEW_HOST_KEY, SSH_PASSWORD } from "../test/fakeDeploy";
import { createFakePanel, type FakePanel } from "../test/fakePanel";
import { heldByMutations, renderApp } from "../test/render";
import { t } from "../test/t";

// Under the load of the whole suite, the first render of a page (its lazy route
// included) and the clicks through it take longer than the defaults of 1 s for a
// find and 5 s for a test, so this file waits longer for both.
configure({ asyncUtilTimeout: 5_000 });
const SLOW = { timeout: 20_000 };

const NODE = { id: "node-a", name: "Frankfurt", mgmtHost: "203.0.113.10", mgmtPort: 61001, status: "provisioning" };
// The labels of the form: a radio of the login methods has some of the same names.
const TEXT = { selector: "input:not([type=radio]), textarea" };
const POLL_WAIT = { timeout: 6000 };

function openWizard(setup?: (panel: FakePanel) => void, route = "/nodes/node-a/install") {
  const panel = createFakePanel({ signedIn: true, nodes: [NODE] });
  setup?.(panel);
  const view = renderApp({ route, transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

const ready = () => screen.findByRole("heading", { name: t("deploy.title"), level: 1 });

/** Types the password into the form and sends it. */
async function connect(user: UserEvent, password = SSH_PASSWORD) {
  await user.type(await screen.findByLabelText(t("deploy.target.password"), TEXT), password);
  await user.click(screen.getByRole("button", { name: t("deploy.target.submit") }));
}

/** From the form to the report, through the confirmation of the key. */
async function toReport(user: UserEvent) {
  await connect(user);
  await user.click(await screen.findByRole("button", { name: t("deploy.hostKey.confirm") }));
  return screen.findByRole("heading", { name: t("deploy.report.title") });
}

function issue(code: string, severity: string, params: Record<string, string> = {}, fixedByDockerInstall = false) {
  return create(PreflightIssueSchema, { code, severity, message: `${code} in English`, params, fixedByDockerInstall });
}

describe("NodeInstall: the server and its host key", SLOW, () => {
  it("is reached from the page of the node", async () => {
    const { user, router } = openWizard(undefined, "/nodes/node-a/settings");
    await user.click(await screen.findByRole("link", { name: t("deploy.open") }));
    expect(await ready()).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/nodes/node-a/install");
  });

  it("starts from the address of the node, as root on port 22", async () => {
    openWizard();
    await ready();
    expect(await screen.findByLabelText(t("deploy.target.host"), TEXT)).toHaveValue("203.0.113.10");
    expect(screen.getByLabelText(t("deploy.target.port"), TEXT)).toHaveValue("22");
    expect(screen.getByLabelText(t("deploy.target.user"), TEXT)).toHaveValue("root");
  });

  it("refuses a form with mistakes before it calls the panel", async () => {
    const { panel, user } = openWizard();
    await ready();
    const host = await screen.findByLabelText(t("deploy.target.host"), TEXT);
    await user.clear(host);
    await user.type(host, "not a host");
    await user.clear(screen.getByLabelText(t("deploy.target.user"), TEXT));
    await user.type(screen.getByLabelText(t("deploy.target.user"), TEXT), "ro ot");
    await user.click(screen.getByRole("button", { name: t("deploy.target.submit") }));
    expect(await screen.findByText(t("validation.host"))).toBeInTheDocument();
    expect(screen.getByText(t("validation.sshUser"))).toBeInTheDocument();
    expect(screen.getByText(t("validation.required"))).toBeInTheDocument(); // the password
    expect(panel.rpc.preflight).not.toHaveBeenCalled();
  });

  it("shows the key of a server that it meets first, and checks the server once it is confirmed", async () => {
    const { panel, user } = openWizard();
    await ready();
    await connect(user);

    expect(await screen.findByRole("heading", { name: t("deploy.hostKey.title") })).toBeInTheDocument();
    expect(screen.getByText(HOST_KEY)).toBeInTheDocument();
    expect(screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls[0]?.[0]).toMatchObject({
      nodeId: "node-a",
      target: { host: "203.0.113.10", port: 22, user: "root", hostKey: "" },
      credentials: { password: SSH_PASSWORD },
    });

    await user.click(screen.getByRole("button", { name: t("deploy.hostKey.confirm") }));
    expect(await screen.findByRole("heading", { name: t("deploy.report.title") })).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls[1]?.[0]).toMatchObject({
      target: { hostKey: HOST_KEY, hostKeyType: HOST_KEY_TYPE },
      replaceHostKey: false,
    });
  });

  it("goes straight to the report for a server whose key is confirmed", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.target = create(SshTargetSchema, { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY });
    });
    await ready();
    await connect(user);
    expect(await screen.findByRole("heading", { name: t("deploy.report.title") })).toBeInTheDocument();
    expect(screen.queryByText(t("deploy.hostKey.title"))).not.toBeInTheDocument();
  });

  it("shows both keys of a server whose key changed, and trusts the new one only on purpose", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.target = create(SshTargetSchema, { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY });
      p.deploy.serverKey = NEW_HOST_KEY;
    });
    await ready();
    await connect(user);

    expect(await screen.findByText(t("deploy.hostKey.changedTitle"))).toBeInTheDocument();
    expect(screen.getByText(HOST_KEY)).toBeInTheDocument();
    expect(screen.getByText(NEW_HOST_KEY)).toBeInTheDocument();
    const trust = screen.getByRole("button", { name: t("deploy.hostKey.trust") });
    expect(trust).toBeDisabled();

    await user.click(screen.getByRole("checkbox", { name: t("deploy.hostKey.trustCheck") }));
    await user.click(trust);
    expect(await screen.findByRole("heading", { name: t("deploy.report.title") })).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls.at(-1)?.[0]).toMatchObject({
      target: { hostKey: NEW_HOST_KEY },
      replaceHostKey: true,
    });
  });

  it("meets a server that offers no key of the confirmed type again, only on purpose, and has its new key confirmed", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.target = create(SshTargetSchema, { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY });
      p.deploy.serverKey = NEW_HOST_KEY;
      p.deploy.noKeyOfType = true;
    });
    await ready();
    await connect(user);

    expect(await screen.findByText(t("deploy.hostKey.changedTitle"))).toBeInTheDocument();
    expect(screen.getByText(HOST_KEY)).toBeInTheDocument();
    expect(screen.getByText(t("deploy.hostKey.noKeyOfType", { type: HOST_KEY_TYPE }))).toBeInTheDocument();
    const meetAgain = screen.getByRole("button", { name: t("deploy.hostKey.meetAgain") });
    expect(meetAgain).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: t("deploy.hostKey.meetAgainCheck") }));
    await user.click(meetAgain);

    // As for the first time: the key of the server, to confirm.
    expect(await screen.findByRole("heading", { name: t("deploy.hostKey.title") })).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls.at(-1)?.[0]).toMatchObject({ target: { hostKey: "" }, replaceHostKey: true });
    expect(screen.getByText(NEW_HOST_KEY)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("deploy.hostKey.confirm") }));
    expect(await screen.findByRole("heading", { name: t("deploy.report.title") })).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls.at(-1)?.[0]).toMatchObject({ target: { hostKey: NEW_HOST_KEY }, replaceHostKey: true });
  });

  it("does not send the saved credentials to a server whose key changed", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.target = create(SshTargetSchema, { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY });
      p.deploy.savedCredentials = "password";
      p.deploy.serverKey = NEW_HOST_KEY;
    });
    await ready();
    await user.click(await screen.findByRole("button", { name: t("deploy.target.submit") }));

    expect(await screen.findByText(t("deploy.hostKey.notSaved"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("deploy.hostKey.trust") })).toBeDisabled();
    expect(screen.queryByRole("checkbox", { name: t("deploy.hostKey.trustCheck") })).not.toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls.every(([req]) => !req.replaceHostKey)).toBe(true);
  });

  it("says why the server refused to let the panel in", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.target = create(SshTargetSchema, { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY });
    });
    await ready();
    await connect(user, "wrong password");
    expect(await screen.findByText("sshx: the server refused the credentials")).toBeInTheDocument();
  });

  it("logs in with a private key and its passphrase", async () => {
    const { panel, user } = openWizard();
    await ready();
    await user.click(await screen.findByRole("radio", { name: t("deploy.target.key") }));
    await user.type(screen.getByLabelText(t("deploy.target.privateKey"), TEXT), "-----BEGIN TEST KEY-----");
    await user.type(screen.getByLabelText(t("deploy.target.passphrase"), TEXT), "pass phrase");
    await user.click(screen.getByRole("button", { name: t("deploy.target.submit") }));
    await screen.findByRole("heading", { name: t("deploy.hostKey.title") });
    expect(panel.rpc.preflight.mock.calls[0]?.[0].credentials).toMatchObject({
      password: "",
      privateKey: "-----BEGIN TEST KEY-----",
      passphrase: "pass phrase",
    });
  });

  it("offers the credentials that the panel keeps, and keeps them by default", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.target = create(SshTargetSchema, { host: "198.51.100.5", port: 2222, user: "deploy", hostKey: HOST_KEY });
      p.deploy.savedCredentials = "password";
    });
    await ready();
    expect(await screen.findByLabelText(t("deploy.target.host"), TEXT)).toHaveValue("198.51.100.5");
    expect(screen.getByRole("radio", { name: t("deploy.target.saved") })).toBeChecked();
    expect(screen.getByText(t("deploy.target.savedHint", { user: "deploy", server: "198.51.100.5:2222" }))).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("deploy.target.submit") }));
    expect(await screen.findByRole("heading", { name: t("deploy.report.title") })).toBeInTheDocument();
    expect(panel.rpc.preflight.mock.calls[0]?.[0].credentials).toMatchObject({ useSaved: true, password: "" });
    expect(screen.getByRole("checkbox", { name: t("deploy.report.remember") })).toBeChecked();
  });
});

describe("NodeInstall: the report", SLOW, () => {
  it("shows the facts of the server", async () => {
    const { user } = openWizard((panel) => {
      panel.inventory.nodeImage = ""; // the kit path, with its install directory and Compose
      panel.deploy.report = makeReport({
        httpsPort: { port: 443, owner: "nginx (pid 4120, container shop-nginx)" },
        mgmtPort: { port: 61001, postern: true },
        clockSkewSeconds: -95n,
        publicIps: ["203.0.113.10", "198.51.100.77"],
        dialedIp: "198.51.100.77",
      });
    });
    await ready();
    await toReport(user);
    expect(screen.getByText(t("deploy.report.portTaken", { owner: "nginx (pid 4120, container shop-nginx)" }))).toBeInTheDocument();
    expect(screen.getByText(`203.0.113.10, ${t("deploy.report.dialed", { address: "198.51.100.77" })}`)).toBeInTheDocument();
    expect(screen.getByText("Ubuntu 24.04.1 LTS")).toBeInTheDocument();
    expect(screen.getByText("x86_64 (amd64)")).toBeInTheDocument();
    expect(screen.getByText("27.5.1")).toBeInTheDocument();
    expect(screen.getByText("2.27.1")).toBeInTheDocument();
    expect(screen.getByText(t("deploy.report.portPostern"))).toBeInTheDocument();
    expect(screen.getByText(t("deploy.report.clockBehind", { seconds: 95 }))).toBeInTheDocument();
    expect(screen.getByText("/root/postern-install")).toBeInTheDocument();
    expect(screen.getByText(t("deploy.report.methodKit"))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("deploy.report.listening", { count: 2 }) }));
    expect(await screen.findByText("sshd (pid 1021)")).toBeInTheDocument();
  });

  it("says who else holds a port", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.report = makeReport({ httpsPort: { port: 443, owner: "caddy (pid 812)" } });
    });
    await ready();
    await toReport(user);
    expect(screen.getByText(t("deploy.report.portTaken", { owner: "caddy (pid 812)" }))).toBeInTheDocument();
    expect(screen.getByText("203.0.113.10, 2001:db8:10::a")).toBeInTheDocument();
  });

  it("refuses the install for a blocker, and marks the warnings", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.report = makeReport({
        issues: [
          issue("https_port_taken", "blocker", { port: "443", owner: "nginx (pid 2100)" }),
          issue("low_disk", "warning", { free_bytes: "644520960", path: "/opt" }),
          issue("some_new_issue", "warning"),
        ],
      });
    });
    await ready();
    await toReport(user);

    const blockers = screen.getByRole("alert", { name: t("deploy.report.blockers") });
    expect(within(blockers).getByText(t("deploy.issues.https_port_taken", { port: "443", owner: "nginx (pid 2100)" }))).toBeInTheDocument();
    const warnings = screen.getByRole("alert", { name: t("deploy.report.warnings") });
    expect(within(warnings).getByText(t("deploy.issues.low_disk", { free: "645 MB", path: "/opt" }))).toBeInTheDocument();
    // An issue that this version does not know is said in the words of the panel.
    expect(within(warnings).getByText("some_new_issue in English")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("deploy.report.install") })).toBeDisabled();
  });

  it("installs Docker only when the admin asks for it", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.report = makeReport({
        dockerInstalled: false,
        dockerVersion: "",
        issues: [issue("docker_missing", "blocker", {}, true)],
      });
    });
    await ready();
    await toReport(user);
    const install = screen.getByRole("button", { name: t("deploy.report.install") });
    expect(install).toBeDisabled();
    expect(screen.getByText(t("deploy.report.dockerMissing"))).toBeInTheDocument();

    // The choice says what it does: an installed Docker is never replaced.
    expect(screen.getByText(t("deploy.report.installDockerHint"))).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: t("deploy.report.installDocker") }));
    expect(install).toBeEnabled();
    await user.click(install);
    await screen.findByRole("log");
    expect(panel.rpc.install.mock.calls[0]?.[0]).toMatchObject({ installDocker: true, remember: false });
  });

  it("says when the panel cannot add Compose to the Docker of the server, and offers nothing for it", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.report = makeReport({
        composeVersion: "",
        issues: [issue("compose_missing", "blocker", { origin: "docker.io" })],
      });
    });
    await ready();
    await toReport(user);
    expect(screen.getByText(t("deploy.issues.compose_manual", { origin: "docker.io" }))).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: t("deploy.report.installDocker") })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("deploy.report.install") })).toBeDisabled();
  });

  it("says in its own words that the Docker daemon does not run, and what Docker says otherwise", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.report = makeReport({
        dockerVersion: "",
        issues: [issue("docker_not_running", "blocker", { problem: "the Docker daemon does not run", stopped: "true" }, true)],
      });
    });
    await ready();
    await toReport(user);
    expect(screen.getByText(t("deploy.issues.docker_stopped"))).toBeInTheDocument();
    expect(screen.queryByText(t("deploy.issues.docker_not_running", { problem: "the Docker daemon does not run" }))).not.toBeInTheDocument();

    const said = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?";
    panel.deploy.report = makeReport({
      dockerVersion: "",
      issues: [issue("docker_not_running", "blocker", { problem: said }, true)],
    });
    await user.click(screen.getByRole("button", { name: t("deploy.report.recheck") }));
    expect(await screen.findByText(t("deploy.issues.docker_not_running", { problem: said }))).toBeInTheDocument();
  });

  it("checks the server again", async () => {
    const { panel, user } = openWizard();
    await ready();
    await toReport(user);
    panel.deploy.report = makeReport({ os: "Debian GNU/Linux 12 (bookworm)" });
    await user.click(screen.getByRole("button", { name: t("deploy.report.recheck") }));
    expect(await screen.findByText("Debian GNU/Linux 12 (bookworm)")).toBeInTheDocument();
  });
});

describe("NodeInstall: the install", SLOW, () => {
  it("shows the log as it comes until the node is online, and lets go of the credentials", async () => {
    const { panel, user, router, queryClient } = openWizard();
    await ready();
    await toReport(user);
    expect(heldByMutations(queryClient)).toContain(SSH_PASSWORD);
    await user.click(screen.getByRole("checkbox", { name: t("deploy.report.remember") }));
    await user.click(screen.getByRole("button", { name: t("deploy.report.install") }));

    const log = await screen.findByRole("log");
    expect(log).toHaveTextContent("==> Connecting to root@203.0.113.10:22");
    expect(router.state.location.search).toBe("?job=job-1");
    expect(panel.rpc.install.mock.calls[0]?.[0]).toMatchObject({
      nodeId: "node-a",
      target: { host: "203.0.113.10", port: 22, user: "root", hostKey: HOST_KEY },
      credentials: { password: SSH_PASSWORD },
      installDocker: false,
      remember: true,
    });
    await waitFor(() => {
      expect(heldByMutations(queryClient)).not.toContain(SSH_PASSWORD);
    });

    expect(await screen.findByText(t("deploy.job.doneMessage"), undefined, POLL_WAIT)).toBeInTheDocument();
    expect(screen.getByRole("log")).toHaveTextContent("==> Done");
    expect(panel.rpc.getJob.mock.calls.length).toBeGreaterThanOrEqual(3);
  }, 15_000);

  it("comes back to the log of the job after a reload", async () => {
    const { panel } = openWizard((p) => {
      p.deploy.jobs.set("job-9", {
        job: create(JobSchema, { id: "job-9", nodeId: "node-a", kind: "install", status: "running", log: "==> Running install.sh\n" }),
        step: 0,
        steps: [{ status: "running", log: "==> Running install.sh\n" }],
      });
    });
    await ready();
    expect(await screen.findByRole("log")).toHaveTextContent("==> Running install.sh");
    expect(screen.queryByLabelText(t("deploy.target.host"), TEXT)).not.toBeInTheDocument();
    expect(panel.rpc.getJob.mock.calls[0]?.[0]).toMatchObject({ id: "job-9" });
  });

  it("says why an install failed, and starts again", async () => {
    const { user } = openWizard((panel) => {
      panel.deploy.steps = [
        { status: "failed", log: "==> Running install.sh\ninstall.sh: error: Docker is not installed\n", error: "install.sh failed with exit code 1" },
      ];
    });
    await ready();
    await toReport(user);
    await user.click(screen.getByRole("button", { name: t("deploy.report.install") }));

    expect(await screen.findByText(t("deploy.job.failedMessage", { error: "install.sh failed with exit code 1" }))).toBeInTheDocument();
    expect(screen.getByRole("log")).toHaveTextContent("install.sh: error: Docker is not installed");
    await user.click(screen.getByRole("button", { name: t("deploy.job.again") }));
    expect(await screen.findByLabelText(t("deploy.target.password"), TEXT)).toHaveValue("");
  });

  it("cancels a running install after asking", async () => {
    const { panel, user } = openWizard((p) => {
      p.deploy.steps = [{ status: "running", log: "==> Installing Docker, as asked\n" }];
    });
    await ready();
    await toReport(user);
    await user.click(screen.getByRole("button", { name: t("deploy.report.install") }));
    await screen.findByRole("log");

    await user.click(screen.getByRole("button", { name: t("deploy.job.cancel") }));
    const dialog = await screen.findByRole("dialog", { name: t("deploy.job.cancelTitle") });
    await user.click(within(dialog).getByRole("button", { name: t("deploy.job.cancelConfirm") }));
    expect(await screen.findByText(t("deploy.job.cancelledMessage"))).toBeInTheDocument();
    expect(panel.rpc.cancelJob.mock.calls[0]?.[0]).toMatchObject({ id: "job-1" });
    expect(screen.queryByText(/remove it by hand/)).not.toBeInTheDocument();
  });

  it("names a bundle that a cancelled install could not remove", async () => {
    const notice =
      "the bundle /root/postern-install/postern-node-bundle.tar, which holds the private key of the node, " +
      "may still be on the server: remove it by hand (rm: exit code 1)";
    const { user } = openWizard((p) => {
      p.deploy.steps = [{ status: "running", log: "==> Running install.sh\n" }];
      p.deploy.cancelError = `the job was cancelled; ${notice}`;
    });
    await ready();
    await toReport(user);
    await user.click(screen.getByRole("button", { name: t("deploy.report.install") }));
    await screen.findByRole("log");

    await user.click(screen.getByRole("button", { name: t("deploy.job.cancel") }));
    const dialog = await screen.findByRole("dialog", { name: t("deploy.job.cancelTitle") });
    await user.click(within(dialog).getByRole("button", { name: t("deploy.job.cancelConfirm") }));
    expect(await screen.findByText(t("deploy.job.cancelledMessage"))).toBeInTheDocument();
    expect(screen.getByText(notice)).toBeInTheDocument();
  });
});

describe("NodeInstall: the Docker path", SLOW, () => {
  const PANEL_URL = "https://panel.example.com";

  it("sends the remembered panel address, and the report states the Docker path", async () => {
    window.localStorage.setItem(PANEL_URL_KEY, PANEL_URL);
    const { panel, user } = openWizard();
    await ready();
    expect(await screen.findByLabelText(t("deploy.target.panelUrl"), TEXT)).toHaveValue(PANEL_URL);
    expect(screen.getByText(t("deploy.target.dockerPath", { image: panel.inventory.nodeImage }))).toBeInTheDocument();
    await toReport(user);
    expect(panel.rpc.preflight).toHaveBeenLastCalledWith(expect.objectContaining({ panelUrl: PANEL_URL }), expect.anything());
    expect(screen.getByText(t("deploy.report.methodDocker"))).toBeInTheDocument();
    // The Docker path copies no files and needs no Compose.
    expect(screen.queryByText("/root/postern-install")).not.toBeInTheDocument();
    expect(screen.queryByText("2.27.1")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("deploy.report.install") }));
    await waitFor(() => {
      expect(panel.rpc.install).toHaveBeenCalledWith(expect.objectContaining({ panelUrl: PANEL_URL }), expect.anything());
    });
  });

  it("takes an address that is typed in, in its normal form, and remembers it", async () => {
    const { panel, user } = openWizard();
    await ready();
    const field = await screen.findByLabelText(t("deploy.target.panelUrl"), TEXT);
    await user.clear(field);
    await user.type(field, "HTTPS://Panel.Example.com:8443/");
    await toReport(user);
    expect(panel.rpc.preflight).toHaveBeenLastCalledWith(
      expect.objectContaining({ panelUrl: "https://panel.example.com:8443" }),
      expect.anything(),
    );
    expect(window.localStorage.getItem(PANEL_URL_KEY)).toBe("https://panel.example.com:8443");
  });

  it("refuses a wrong panel address before it calls the panel", async () => {
    const { panel, user } = openWizard();
    await ready();
    const field = await screen.findByLabelText(t("deploy.target.panelUrl"), TEXT);
    await user.clear(field);
    await user.type(field, "http://panel.example.com");
    await connect(user);
    expect(await screen.findByText(t("validation.panelUrlHttp"))).toBeInTheDocument();
    expect(panel.rpc.preflight).not.toHaveBeenCalled();
  });

  it("without a node image asks for no address and takes the kit path", async () => {
    const { panel, user } = openWizard((p) => {
      p.inventory.nodeImage = "";
    });
    await ready();
    await screen.findByLabelText(t("deploy.target.host"), TEXT);
    expect(screen.queryByLabelText(t("deploy.target.panelUrl"), TEXT)).not.toBeInTheDocument();
    await toReport(user);
    expect(panel.rpc.preflight).toHaveBeenLastCalledWith(expect.objectContaining({ panelUrl: "" }), expect.anything());
    expect(screen.getByText(t("deploy.report.methodKit"))).toBeInTheDocument();
  });
});

describe("NodeInstall: the node image is known before the form", SLOW, () => {
  it("holds the form while the panel has not said whether it has a node image", async () => {
    const { panel } = openWizard((p) => {
      p.rpc.getNodeInstall.mockImplementationOnce(() => new Promise<never>(() => undefined));
    });
    await ready();
    expect(await screen.findByText(t("deploy.steps.target"))).toBeInTheDocument();
    expect(screen.getByRole("status", { name: t("common.loading") })).toBeInTheDocument();
    expect(screen.queryByLabelText(t("deploy.target.host"), TEXT)).not.toBeInTheDocument();
    expect(panel.rpc.preflight).not.toHaveBeenCalled();
  });

  it("says why the node image could not be read, and tries again instead of taking the kit path", async () => {
    const { panel, user } = openWizard((p) => {
      p.rpc.getNodeInstall.mockImplementationOnce(() => {
        throw new ConnectError("the database is locked", Code.Internal);
      });
    });
    await ready();
    expect(await screen.findByText("the database is locked")).toBeInTheDocument();
    expect(screen.queryByLabelText(t("deploy.target.host"), TEXT)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: t("common.retry") }));
    expect(await screen.findByLabelText(t("deploy.target.panelUrl"), TEXT)).toBeInTheDocument();
    expect(panel.rpc.preflight).not.toHaveBeenCalled();
  });
});
