import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { describe, expect, it } from "vitest";

import { DiagnosticRunSchema } from "../gen/postern/panel/v1/diagnostics_pb";
import en from "../i18n/insights.en.json";
import ru from "../i18n/insights.ru.json";
import { t } from "../test/t";
import {
  checkText,
  findChangeRuns,
  fixRefusal,
  groupByLayer,
  journalRequest,
  EMPTY_JOURNAL_FILTER,
  offersFix,
  pairRuns,
  probeClass,
  problemLink,
  proxyOfTarget,
  runCounts,
  runLink,
  scopeOf,
} from "./diagnostics";

const run = (init: Parameters<typeof create<typeof DiagnosticRunSchema>>[1]) => create(DiagnosticRunSchema, init);

describe("runCounts", () => {
  it("takes the counts that the panel gives with a run, also one listed without its results", () => {
    expect(runCounts(run({ okCount: 2, warnCount: 1, failCount: 3, skipCount: 4 }))).toEqual({ ok: 2, warn: 1, fail: 3, skip: 4 });
    expect(runCounts(run({}))).toEqual({ ok: 0, warn: 0, fail: 0, skip: 0 });
  });
});

describe("checkText", () => {
  it("names and describes the WEB checks, in both languages, and leaves the others to their id", () => {
    for (const id of ["web.cert", "web.dns", "web.http2", "web.decoy", "web.base_path"]) {
      const text = checkText(t, id);
      expect(text?.label).toBeTruthy();
      expect(text?.label).not.toContain("insights.");
      expect(text?.description).not.toContain("insights.");
      expect(text?.description.length).toBeGreaterThan(20);
    }
    expect(checkText(t, "web.cert")?.label).toBe(en.insights.diagnostics.check.webCert.label);
    expect(ru.insights.diagnostics.check.webCert.label).not.toBe(en.insights.diagnostics.check.webCert.label);
    expect(checkText(t, "engine.ready")).toBeUndefined();
    expect(checkText(t, "toString")).toBeUndefined();
  });
});

describe("groupByLayer", () => {
  it("orders the layers along the path of a connection, unknown ones last, keeping the order inside", () => {
    const groups = groupByLayer([
      { layer: "engine", id: "engine.ready" },
      { layer: "zeta", id: "z" },
      { layer: "host", id: "host.disk" },
      { layer: "engine", id: "engine.log" },
      { layer: "panel", id: "panel.connection" },
    ]);
    expect(groups.map((group) => group.layer)).toEqual(["panel", "host", "engine", "zeta"]);
    expect(groups[2]?.results.map((result) => result.id)).toEqual(["engine.ready", "engine.log"]);
  });
});

describe("offersFix", () => {
  it("is for a warn or a fail with a fix", () => {
    expect(offersFix({ status: "fail", fix: "recreate_instance" })).toBe(true);
    expect(offersFix({ status: "warn", fix: "roll_edge" })).toBe(true);
    expect(offersFix({ status: "ok", fix: "roll_edge" })).toBe(false);
    expect(offersFix({ status: "fail", fix: "" })).toBe(false);
  });
});

describe("pairRuns and findChangeRuns", () => {
  const runs = [
    run({ id: "r4", reason: "after_change", relatedRunId: "r3", startedUnix: 400n }),
    run({ id: "r3", reason: "before_change", startedUnix: 300n }),
    run({ id: "r2", reason: "before_change", startedUnix: 200n }),
    run({ id: "r1", reason: "manual", startedUnix: 100n }),
  ];

  it("pairs an after-run with its before-run", () => {
    const pairs = pairRuns(runs);
    expect(pairs[0]?.before?.id).toBe("r3");
    expect(pairs[1]?.before).toBeUndefined();
  });

  it("finds the before-run that the panel answered a save with, and its after-run", () => {
    expect(findChangeRuns(runs, "r3")).toMatchObject({ before: { id: "r3" }, after: { id: "r4" } });
    // r3 started later and is in the list too; the id, not the time, names the run.
    expect(findChangeRuns(runs, "r2")).toEqual({ before: runs[2] });
    // Not listed yet: neither is found; no before-run: nothing.
    expect(findChangeRuns(runs, "r9")).toEqual({});
    expect(findChangeRuns(runs, "")).toEqual({});
    expect(findChangeRuns(runs.slice(0, 1), "r3")).toEqual({ after: runs[0] });
  });
});

describe("fixRefusal", () => {
  it("tells a stale fix from one the node cannot take, and from one this panel cannot apply", () => {
    expect(
      fixRefusal(new ConnectError("this fix is stale: engine.ready no longer offers recreate_instance; run diagnostics again", Code.FailedPrecondition)),
    ).toMatchObject({ kind: "stale" });
    expect(fixRefusal(new ConnectError("the node lacks restart-nonce", Code.FailedPrecondition))).toEqual({
      kind: "refused",
      message: "the node lacks restart-nonce",
    });
    expect(fixRefusal(new ConnectError("reissue_cert comes with the WEB diagnostics", Code.Unimplemented))).toMatchObject({ kind: "unavailable" });
    expect(fixRefusal(new ConnectError("database", Code.Internal))).toEqual({ kind: "failed" });
    expect(fixRefusal(new Error("x"))).toEqual({ kind: "failed" });
  });
});

describe("links and scopes", () => {
  it("links a problem to its proxy, its node, or the settings", () => {
    expect(problemLink({ nodeId: "n1", proxyId: "p1" })).toBe("/proxies/p1");
    expect(problemLink({ nodeId: "n1", proxyId: "" })).toBe("/nodes/n1/diagnostics");
    expect(problemLink({ nodeId: "", proxyId: "" })).toBe("/settings");
    expect(runLink("n 1", "r/1")).toBe("/nodes/n%201/diagnostics?run=r%2F1");
  });

  it("names scopes and targets", () => {
    expect(scopeOf(undefined)).toBe("node");
    expect(scopeOf("p1")).toBe("proxy:p1");
    expect(proxyOfTarget("proxy:p1")).toBe("p1");
    expect(proxyOfTarget("listener:l1")).toBe("");
  });
});

describe("journalRequest", () => {
  it("sends only the filters of the source asked", () => {
    const filter = { ...EMPTY_JOURNAL_FILTER, nodeId: "n1", minSeverity: "warning", kindPrefix: " check. ", actionPrefix: "diagnostics." };
    expect(journalRequest(filter, 1_000_000, "")).toEqual({
      source: "events",
      fromUnix: 0n,
      toUnix: 0n,
      cursor: "",
      limit: 50,
      nodeId: "n1",
      proxyId: "",
      minSeverity: "warning",
      kindPrefix: "check.",
    });
    expect(journalRequest({ ...filter, source: "audit", period: "24h" }, 1_000_000, "c2")).toEqual({
      source: "audit",
      fromUnix: 1_000_000n - 86_400n,
      toUnix: 0n,
      cursor: "c2",
      limit: 50,
      actionPrefix: "diagnostics.",
    });
  });
});

describe("probeClass", () => {
  it("classes a probe as through, the proxy only (L1), or failed", () => {
    expect(probeClass({ ok: true, l1Ok: true })).toBe("ok");
    expect(probeClass({ ok: false, l1Ok: true })).toBe("l1");
    expect(probeClass({ ok: false, l1Ok: false })).toBe("failed");
    expect(probeClass({ ok: false })).toBe("failed");
  });
});
