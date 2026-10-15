import { Code, ConnectError } from "@connectrpc/connect";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { STALE_FIX, type CheckInit } from "../test/fakeDiagnostics";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { DiagnosticsSection } from "./DiagnosticsSection";

const now = () => Math.floor(Date.now() / 1000);
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));
const dialog = () => screen.findByRole("dialog").then((element) => within(element));

const ENGINE_FAIL: CheckInit = {
  id: "engine.ready",
  layer: "engine",
  target: "proxy:proxy-1",
  status: "fail",
  summary: "the engine is not ready",
  evidence: "ready=false for 3 minutes",
  hint: "look at the engine log",
  fix: "recreate_instance",
  fixAvailable: true,
  vantage: "node",
  sinceUnix: BigInt(now() - 600),
};
const DISK_OK: CheckInit = { id: "host.disk", layer: "host", target: "", status: "ok", summary: "40 GiB free", vantage: "node" };
const VERSIONS_WARN: CheckInit = {
  id: "panel.versions",
  layer: "panel",
  target: "",
  status: "warn",
  summary: "the edge runs 1.2.0, the agent 1.3.0",
  fix: "roll_edge",
  fixAvailable: false,
  fixUnavailableReason: "the node lacks the capability edge-roll-nonce",
  vantage: "panel",
};

function open() {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [{ id: "node-a", name: "Frankfurt" }],
    proxies: [{ id: "proxy-1", nodeId: "node-a", name: "Family" }],
  });
  return { panel, user: userEvent.setup() };
}

function show(panel: ReturnType<typeof open>["panel"], route = "/nodes/node-a") {
  return renderWithProviders(<DiagnosticsSection nodeId="node-a" />, { transport: panel.transport, route });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("DiagnosticsSection: light checks", () => {
  it("groups the checks by layer, with status, summary and since, and shows evidence and hint when opened", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [ENGINE_FAIL, DISK_OK]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    // The first render of a file is slow while the whole suite runs.
    expect(await section.findByText("the engine is not ready", {}, { timeout: 5_000 })).toBeInTheDocument();
    expect(section.getByRole("heading", { name: t("insights.diagnostics.layer.host") })).toBeInTheDocument();
    expect(section.getByRole("heading", { name: t("insights.diagnostics.layer.engine") })).toBeInTheDocument();
    expect(section.getByText(t("insights.diagnostics.since", { when: "10 minutes ago" }))).toBeInTheDocument();
    expect(section.getAllByText(t("insights.diagnostics.status.fail")).length).toBeGreaterThan(0);

    await user.click(section.getByRole("button", { name: t("insights.diagnostics.details") }));
    // The details are in the page at once and become visible as they open,
    // which takes a while on a slow runner.
    await waitFor(() => {
      expect(section.getByText("ready=false for 3 minutes")).toBeVisible();
    });
    expect(section.getByText("look at the engine log")).toBeVisible();
  });
});

describe("DiagnosticsSection: the history", () => {
  it("shows the counts that the panel lists with each run, none for a run in progress", async () => {
    const { panel } = open();
    panel.diagnostics.addRun({ id: "run-old", nodeId: "node-a", startedUnix: BigInt(now() - 7200), okCount: 12, warnCount: 2, failCount: 1, skipCount: 3 });
    panel.diagnostics.addRun({ id: "run-now", nodeId: "node-a", state: "running" });
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    const history = within(await section.findByRole("table", { name: t("insights.diagnostics.history.title") }));
    expect(history.getByRole("columnheader", { name: t("insights.diagnostics.history.results") })).toBeInTheDocument();
    expect(history.getByText(t("insights.diagnostics.run.counts", { ok: "12", warn: "2", fail: "1", skip: "3" }))).toBeInTheDocument();
    expect(history.queryByText(t("insights.diagnostics.run.counts", { ok: "0", warn: "0", fail: "0", skip: "0" }))).not.toBeInTheDocument();
    // The runs are listed without their results: the counts come from the panel.
    expect(panel.rpc.getRun).not.toHaveBeenCalled();
  });
});

describe("DiagnosticsSection: a full run", () => {
  it("asks for the run every second until it is done, then stops", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { panel, user } = open();
    show(panel);
    const section = await region(t("insights.diagnostics.title"));

    await user.click(section.getByRole("button", { name: t("insights.diagnostics.runFull") }));
    expect(await section.findByText(t("insights.diagnostics.run.running"))).toBeInTheDocument();
    expect(panel.rpc.startRun.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", scope: "node" });

    const asked = panel.rpc.getRun.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    await waitFor(() => {
      expect(panel.rpc.getRun.mock.calls.length).toBeGreaterThan(asked);
    });

    panel.diagnostics.finishRun("run-1", { results: [ENGINE_FAIL, DISK_OK, VERSIONS_WARN] });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(
      await section.findByText(t("insights.diagnostics.run.counts", { ok: "1", warn: "1", fail: "1", skip: "0" })),
    ).toBeInTheDocument();
    expect(section.getByText(t("insights.diagnostics.run.state.done"))).toBeInTheDocument();

    const done = panel.rpc.getRun.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(panel.rpc.getRun.mock.calls.length).toBe(done);
  });

  it("stops asking when the page is left", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { panel, user } = open();
    const view = show(panel);
    const section = await region(t("insights.diagnostics.title"));
    await user.click(section.getByRole("button", { name: t("insights.diagnostics.runFull") }));
    await section.findByText(t("insights.diagnostics.run.running"));

    view.unmount();
    const asked = panel.rpc.getRun.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    expect(panel.rpc.getRun.mock.calls.length).toBe(asked);
  });

  it("opens the run named in the address, and the history pairs an after-run with its before-run", async () => {
    const { panel, user } = open();
    panel.diagnostics.addRun({ id: "run-b", nodeId: "node-a", reason: "before_change", change: "proxy.update egress_chain_id", startedUnix: BigInt(now() - 300) });
    panel.diagnostics.addRun({
      id: "run-a",
      nodeId: "node-a",
      reason: "after_change",
      relatedRunId: "run-b",
      regressed: true,
      startedUnix: BigInt(now() - 60),
      results: [ENGINE_FAIL],
    });
    show(panel, "/nodes/node-a?run=run-a");
    const section = await region(t("insights.diagnostics.title"));

    const run = await region(t("insights.diagnostics.run.title"));
    expect(await run.findByText("the engine is not ready")).toBeInTheDocument();
    expect(run.getByText(t("insights.diagnostics.run.regressedHint"))).toBeInTheDocument();

    const history = within(await section.findByRole("table", { name: t("insights.diagnostics.history.title") }));
    expect(history.getByText(t("insights.diagnostics.reason.after_change"))).toBeInTheDocument();
    expect(history.getByText(t("insights.diagnostics.run.regressed"))).toBeInTheDocument();
    expect(history.getByText("proxy.update egress_chain_id")).toBeInTheDocument();

    // The after-run is compared with the before-run: opening it shows that run.
    await user.click(run.getByRole("button", { name: t("insights.diagnostics.history.openBefore") }));
    await waitFor(() => {
      expect(panel.rpc.getRun.mock.calls.at(-1)?.[0]).toMatchObject({ runId: "run-b" });
    });
  });
});

describe("DiagnosticsSection: fixes", () => {
  it("says what a fix changes before it is applied, and applies it from the run that offered it", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [ENGINE_FAIL]);
    panel.diagnostics.addRun({ id: "run-9", nodeId: "node-a", results: [ENGINE_FAIL] });
    show(panel, "/nodes/node-a?run=run-9");

    const run = await region(t("insights.diagnostics.run.title"));
    await user.click(await run.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.recreate_instance") }) }));

    const confirm = await dialog();
    expect(confirm.getByText(t("insights.diagnostics.fix.effect.recreate_instance"))).toBeInTheDocument();
    expect(panel.rpc.applyFix).not.toHaveBeenCalled();
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.applied", { generation: "8" }))).toBeInTheDocument();
    expect(panel.rpc.applyFix.mock.calls[0]?.[0]).toMatchObject({
      nodeId: "node-a",
      checkId: "engine.ready",
      target: "proxy:proxy-1",
      fix: "recreate_instance",
      offeredRunId: "run-9",
    });
  });

  it("says that the edge runs the agent's version after an edge roll", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [{ ...VERSIONS_WARN, fixAvailable: true, fixUnavailableReason: "" }]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    await user.click(await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.roll_edge") }) }));
    const confirm = await dialog();
    expect(confirm.getByText(t("insights.diagnostics.fix.effect.roll_edge"))).toBeInTheDocument();
    expect(confirm.getByText(t("insights.diagnostics.fix.afterwards.roll_edge"))).toBeInTheDocument();
  });

  it("disables a fix that the node cannot take, and says why", async () => {
    const { panel } = open();
    panel.diagnostics.setLatest("node-a", [VERSIONS_WARN]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    const button = await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.roll_edge") }) });
    expect(button).toBeDisabled();
    expect(
      section.getByText(t("insights.diagnostics.fix.unavailableReason", { reason: "the node lacks the capability edge-roll-nonce" })),
    ).toBeInTheDocument();
  });

  it("refuses a stale fix and asks for the checks to be run again", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [ENGINE_FAIL]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    const fix = await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.recreate_instance") }) });
    // The check recovered after the page got it.
    panel.diagnostics.setLatest("node-a", [{ ...ENGINE_FAIL, status: "ok", evidence: "" }]);
    await user.click(fix);
    const confirm = await dialog();
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.stale"))).toBeInTheDocument();
    expect(confirm.getByText(STALE_FIX)).toBeInTheDocument();
    expect(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") })).toBeDisabled();
  });

  it("names and describes the WEB checks, and reissues a certificate with what follows", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [
      { id: "web.cert", layer: "web", target: "proxy:proxy-1", status: "fail", summary: "the certificate expired", fix: "reissue_cert", fixAvailable: true },
      { id: "web.dns", layer: "web", target: "proxy:proxy-1", status: "ok", summary: "the domain points here" },
    ]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    expect(await section.findByText(t("insights.diagnostics.check.webCert.label"))).toBeInTheDocument();
    expect(section.getByText(t("insights.diagnostics.check.webCert.description"))).toBeInTheDocument();
    expect(section.getByText(t("insights.diagnostics.check.webDns.label"))).toBeInTheDocument();
    // The id stays, beside the name.
    expect(section.getByText("web.cert")).toBeInTheDocument();

    await user.click(section.getByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.reissue_cert") }) }));
    const confirm = await dialog();
    expect(confirm.getByText(t("insights.diagnostics.fix.effect.reissue_cert"))).toBeInTheDocument();
    expect(confirm.getByText(t("insights.diagnostics.fix.afterwards.reissue_cert"))).toBeInTheDocument();
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.applied", { generation: "8" }))).toBeInTheDocument();
    expect(panel.rpc.applyFix.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", checkId: "web.cert", target: "proxy:proxy-1", fix: "reissue_cert" });
  });

  it("keeps reissue_cert disabled on a node without the WEB diagnostics", async () => {
    const { panel } = open();
    const reason = "the node lacks the capability web-diagnostics";
    panel.diagnostics.setLatest("node-a", [
      {
        id: "web.cert",
        layer: "web",
        target: "proxy:proxy-1",
        status: "warn",
        summary: "the certificate expires in 5 days",
        fix: "reissue_cert",
        fixAvailable: false,
        fixUnavailableReason: reason,
      },
    ]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    expect(
      await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.reissue_cert") }) }),
    ).toBeDisabled();
    expect(section.getByText(t("insights.diagnostics.fix.unavailableReason", { reason }))).toBeInTheDocument();
  });

  it("says that this panel cannot apply a fix that it answers as unimplemented", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [ENGINE_FAIL]);
    const message = "this panel cannot apply the fix recreate_instance";
    panel.rpc.applyFix.mockImplementationOnce(() => {
      throw new ConnectError(message, Code.Unimplemented);
    });
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    await user.click(await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.recreate_instance") }) }));
    const confirm = await dialog();
    await user.click(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") }));

    expect(await confirm.findByText(t("insights.diagnostics.fix.unavailable", { reason: message }))).toBeInTheDocument();
  });

  it("asks for the chain of change_egress", async () => {
    const { panel, user } = open();
    panel.diagnostics.setLatest("node-a", [
      { id: "egress.dc", layer: "egress", target: "proxy:proxy-1", status: "fail", summary: "no datacenter answered", fix: "change_egress", fixAvailable: true },
    ]);
    show(panel);

    const section = await region(t("insights.diagnostics.title"));
    await user.click(await section.findByRole("button", { name: t("insights.diagnostics.fix.action", { fix: t("insights.diagnostics.fix.name.change_egress") }) }));
    const confirm = await dialog();
    expect(confirm.getByRole("button", { name: t("insights.diagnostics.fix.confirm") })).toBeDisabled();
    expect(confirm.getByText(t("insights.diagnostics.fix.effect.change_egress"))).toBeInTheDocument();
  });
});
