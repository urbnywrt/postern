import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  CreateEgressRequestSchema,
  type Egress,
  UpdateEgressRequestSchema,
  ValidateEgressRequestSchema,
} from "../gen/postern/panel/v1/egress_pb";
import { makeEgress } from "../test/fakeEgress";
import { createFakePanel } from "../test/fakePanel";
import { heldByMutations, renderWithProviders } from "../test/render";
import { t, type TKey } from "../test/t";
import { EgressForm } from "./EgressForm";

const NODE = { id: "node-a", name: "Frankfurt" };
// Made-up credentials, obviously fake.
const PASSWORD = "pass-word-not-real";
const NEW_PASSWORD = "new-pass-word-not-real";
const LINK = "vless://00000000-0000-4000-8000-000000000001@vless.example.com:443?type=tcp#exit";
const SUB_URL = "https://sub.example.com/sub-token-not-real-0";

type User = ReturnType<typeof userEvent.setup>;

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };
const field = (key: TKey) => screen.getByLabelText(t(key), FIELD);
const queryField = (key: TKey) => screen.queryByLabelText(t(key), FIELD);
const button = (key: TKey) => screen.getByRole("button", { name: t(key) });

async function choose(user: User, key: TKey, option: string) {
  await user.click(field(key));
  await user.click(await screen.findByRole("option", { name: option }));
}

/** Puts a long text into a field at once: typing it key by key takes long. */
async function fill(user: User, key: TKey, text: string) {
  await user.click(field(key));
  await user.paste(text);
}

function open(egress?: Egress) {
  const onDone = vi.fn<(egress: Egress) => void>();
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], egresses: egress ? [egress] : [] });
  const view = renderWithProviders(<EgressForm egress={egress} onDone={onDone} onCancel={vi.fn()} />, { transport: panel.transport });
  return { panel, onDone, user: userEvent.setup(), ...view };
}

/** The request that a call of the panel was sent, exactly: every field, empty ones too. */
const createRequest = (init: MessageInitShape<typeof CreateEgressRequestSchema>) => create(CreateEgressRequestSchema, init);

/** The fields of each kind, by the keys of their labels. */
const FIELDS_OF: Record<string, TKey[]> = {
  direct: ["egress.form.interface", "egress.form.bindIp"],
  socks5: ["egress.form.addr", "egress.form.username", "egress.form.password"],
  http: ["egress.form.addr", "egress.form.username", "egress.form.password"],
  "xray-uri": ["egress.form.uri"],
  "xray-subscription": ["egress.form.url", "egress.form.select"],
  warp: [],
  psiphon: ["egress.form.country"],
};
const ALL_FIELDS = [...new Set(Object.values(FIELDS_OF).flat())];

const KIND_LABELS: Record<string, TKey> = {
  direct: "egress.kinds.direct",
  socks5: "egress.kinds.socks5",
  http: "egress.kinds.http",
  "xray-uri": "egress.kinds.xrayUri",
  "xray-subscription": "egress.kinds.xraySubscription",
  warp: "egress.kinds.warp",
  psiphon: "egress.kinds.psiphon",
};
const kindLabel = (kind: string) => t(KIND_LABELS[kind] ?? "egress.kinds.direct");

describe("EgressForm: the fields of each kind", () => {
  it.each(Object.keys(FIELDS_OF))("shows the fields of %s and no others", async (kind) => {
    const { user } = open();
    await choose(user, "egress.form.kind", kindLabel(kind));

    const own = FIELDS_OF[kind] ?? [];
    for (const key of ALL_FIELDS) {
      if (own.includes(key)) {
        expect(queryField(key), key).toBeInTheDocument();
      } else {
        expect(queryField(key), key).not.toBeInTheDocument();
      }
    }
    if (kind === "warp") {
      expect(screen.getByText(t("egress.form.warpHint"))).toBeInTheDocument();
    }
    // Psiphon alone is labelled experimental.
    if (kind === "psiphon") {
      expect(screen.getByText(t("egress.experimentalHint"))).toBeInTheDocument();
    } else {
      expect(screen.queryByText(t("egress.experimentalHint"))).not.toBeInTheDocument();
    }
  });

  it("creates a SOCKS5 egress of a node with what was typed, and lets go of the password", async () => {
    const { panel, user, onDone, queryClient } = open();
    await user.type(field("egress.form.name"), "  Office  ");
    await choose(user, "egress.form.kind", t("egress.kinds.socks5"));
    await choose(user, "egress.form.node", NODE.name);
    await user.type(field("egress.form.addr"), " 198.51.100.9:1080 ");
    await user.type(field("egress.form.username"), "user");
    await user.type(field("egress.form.password"), PASSWORD);
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(onDone).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({
        name: "Office",
        kind: "socks5",
        nodeId: NODE.id,
        params: { addr: "198.51.100.9:1080", username: "user", password: PASSWORD },
      }),
    );
    // The answer has no password, and the mutation does not keep the one that was sent.
    expect(onDone.mock.calls[0]?.[0]?.params?.password).toBe("");
    await waitFor(() => {
      expect(heldByMutations(queryClient)).not.toContain(PASSWORD);
    });
  });

  it("sends a subscription with a selection by name", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Subscription");
    await choose(user, "egress.form.kind", t("egress.kinds.xraySubscription"));
    await user.type(field("egress.form.url"), SUB_URL);
    await choose(user, "egress.form.select", t("egress.form.selectName"));
    await user.type(field("egress.form.selectText"), "Germany");
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({ name: "Subscription", kind: "xray-subscription", params: { url: SUB_URL, select: "name:Germany" } }),
    );
  });

  it("sends the country of a psiphon egress", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Psiphon");
    await choose(user, "egress.form.kind", t("egress.kinds.psiphon"));
    await user.click(field("egress.form.country"));
    await user.click(await screen.findByRole("option", { name: /\bDE\b/ }));
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({ name: "Psiphon", kind: "psiphon", params: { country: "DE" } }),
    );
  });

  it("sends the partner ids of a psiphon egress, both or neither", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Psiphon");
    await choose(user, "egress.form.kind", t("egress.kinds.psiphon"));
    await user.click(field("egress.form.country"));
    await user.click(await screen.findByRole("option", { name: /\bDE\b/ }));
    await user.click(screen.getByRole("button", { name: t("egress.form.partner") }));
    // The panel opens on the next animation frame: what is typed before that is lost.
    await waitFor(() => {
      expect(field("egress.form.propagationChannelId")).toBeVisible();
    });
    await user.type(field("egress.form.propagationChannelId"), " 0123456789abcdef ");
    expect(field("egress.form.propagationChannelId")).toHaveValue(" 0123456789abcdef ");
    await user.click(button("egress.form.create"));
    // One without the other is not sent.
    expect(await screen.findAllByText(t("validation.partnerPair"))).not.toHaveLength(0);
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();

    await user.type(field("egress.form.sponsorId"), "FEDCBA987654321");
    expect(await screen.findByText(t("validation.partnerId"))).toBeInTheDocument();
    await user.type(field("egress.form.sponsorId"), "0");
    await user.click(button("egress.form.create"));
    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({
        name: "Psiphon",
        kind: "psiphon",
        params: { country: "DE", propagationChannelId: "0123456789ABCDEF", sponsorId: "FEDCBA9876543210" },
      }),
    );
  });

  it("sends the interface and the source address of a direct egress of a node", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Tunnel");
    await choose(user, "egress.form.kind", t("egress.kinds.direct"));
    await choose(user, "egress.form.node", NODE.name);
    await user.type(field("egress.form.interface"), " wg0 ");
    await user.type(field("egress.form.bindIp"), "198.51.100.7");
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({ name: "Tunnel", kind: "direct", nodeId: NODE.id, params: { interface: "wg0", bindIp: "198.51.100.7" } }),
    );
  });

  it("sends the address and the credentials of an HTTP proxy", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Squid");
    await choose(user, "egress.form.kind", t("egress.kinds.http"));
    await user.type(field("egress.form.addr"), "proxy.example.com:3128");
    await user.type(field("egress.form.username"), "user");
    await user.type(field("egress.form.password"), PASSWORD);
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(
      createRequest({ name: "Squid", kind: "http", params: { addr: "proxy.example.com:3128", username: "user", password: PASSWORD } }),
    );
  });

  it("sends a WARP egress without parameters", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "WARP");
    await choose(user, "egress.form.kind", t("egress.kinds.warp"));
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(createRequest({ name: "WARP", kind: "warp", params: {} }));
  });

  it.each([
    ["a share link", "xray-uri", "egress.form.uri", LINK, "direct"],
    ["a password", "socks5", "egress.form.password", PASSWORD, "warp"],
  ] as const)("does not send %s that was typed for another kind", async (_name, first, key, secret, then) => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "Switched");
    await choose(user, "egress.form.kind", kindLabel(first));
    if (first === "socks5") {
      await user.type(field("egress.form.addr"), "198.51.100.9:1080");
      await user.type(field("egress.form.username"), "user");
    }
    await user.type(field(key), secret);
    await choose(user, "egress.form.kind", kindLabel(then));
    await user.click(button("egress.form.create"));

    await waitFor(() => {
      expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.createEgress.mock.calls[0]?.[0]).toEqual(createRequest({ name: "Switched", kind: then, params: {} }));
  });

  it.each([
    ["a SOCKS5 egress without an address", "socks5", "egress.form.addr", "", t("validation.required")],
    ["a SOCKS5 egress with an address without a port", "socks5", "egress.form.addr", "198.51.100.9", t("validation.hostPort")],
    ["an HTTP egress with IPv6 out of brackets", "http", "egress.form.addr", "2001:db8::1:3128", t("validation.hostPort")],
    ["an address with a port out of range", "socks5", "egress.form.addr", "proxy.example.com:65536", t("validation.hostPortPort")],
    ["an address with a space", "socks5", "egress.form.addr", "proxy example.com:1080", t("validation.hostPortChars")],
    ["a name in brackets", "http", "egress.form.addr", "[proxy.example.com]:3128", t("validation.hostPortBrackets")],
    ["a SOCKS5 username of more than 255 bytes", "socks5", "egress.form.username", "u".repeat(256), t("validation.bytesLong", { max: 255 })],
    ["an HTTP username with a colon", "http", "egress.form.username", "user:name", t("validation.usernameColon")],
    ["an HTTP username of more than 1024 bytes", "http", "egress.form.username", "u".repeat(1025), t("validation.bytesLong", { max: 1024 })],
    ["an interface of more than 15 characters", "direct", "egress.form.interface", "a".repeat(16), t("validation.interface")],
    ["an interface with a slash", "direct", "egress.form.interface", "eth0/1", t("validation.interface")],
    ["a source address that is not an IP address", "direct", "egress.form.bindIp", "eth0", t("validation.sourceIp")],
    ["a share link that is missing", "xray-uri", "egress.form.uri", "", t("validation.required")],
    ["a subscription without a URL", "xray-subscription", "egress.form.url", "", t("validation.required")],
    ["a subscription URL of more than 2048 bytes", "xray-subscription", "egress.form.url", `${SUB_URL}/${"a".repeat(2048)}`, t("validation.bytesLong", { max: 2048 })],
    ["a subscription URL with a space", "xray-subscription", "egress.form.url", `${SUB_URL} x`, t("validation.urlSpaces")],
  ] as const)("refuses %s before it calls the panel", async (_name, kind, key, text, message) => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "x");
    await choose(user, "egress.form.kind", kindLabel(kind));
    if (text !== "") {
      await fill(user, key, text);
    }
    await user.click(button("egress.form.create"));

    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();
  });

  it("refuses a password of more than 255 bytes for SOCKS5", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "x");
    await choose(user, "egress.form.kind", t("egress.kinds.socks5"));
    await user.type(field("egress.form.addr"), "198.51.100.9:1080");
    await user.type(field("egress.form.username"), "user");
    await fill(user, "egress.form.password", "p".repeat(256));
    await user.click(button("egress.form.create"));

    expect(await screen.findByText(t("validation.bytesLong", { max: 255 }))).toBeInTheDocument();
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();
  });

  it("refuses a selection by a name of more than 128 bytes", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "x");
    await choose(user, "egress.form.kind", t("egress.kinds.xraySubscription"));
    await user.type(field("egress.form.url"), SUB_URL);
    await choose(user, "egress.form.select", t("egress.form.selectName"));
    await fill(user, "egress.form.selectText", "n".repeat(129));
    await user.click(button("egress.form.create"));

    expect(await screen.findByText(t("validation.bytesLong", { max: 128 }))).toBeInTheDocument();
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();
  });

  it.each(["my_proxy.internal:1080", "proxy.example.com.:1080", "прокси.example:1080"])(
    "takes the address %s, as the node does",
    async (addr) => {
      const { panel, user } = open();
      await user.type(field("egress.form.name"), "x");
      await choose(user, "egress.form.kind", t("egress.kinds.socks5"));
      await fill(user, "egress.form.addr", addr);
      await user.click(button("egress.form.create"));

      await waitFor(() => {
        expect(panel.rpc.createEgress).toHaveBeenCalledTimes(1);
      });
      expect(panel.rpc.createEgress.mock.calls[0]?.[0]?.params?.addr).toBe(addr);
    },
  );

  it("refuses a password without a username", async () => {
    const { panel, user } = open();
    await user.type(field("egress.form.name"), "x");
    await choose(user, "egress.form.kind", t("egress.kinds.socks5"));
    await user.type(field("egress.form.addr"), "198.51.100.9:1080");
    await user.type(field("egress.form.password"), PASSWORD);
    await user.click(button("egress.form.create"));

    expect(await screen.findByText(t("validation.passwordUser"))).toBeInTheDocument();
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();
  });
});

describe("EgressForm: an egress that exists", () => {
  const office = () =>
    makeEgress({
      id: "eg-1", name: "Office", kind: "socks5", passwordSet: true,
      params: { addr: "198.51.100.9:1080", username: "user" },
    });

  it.each([
    ["a share link", () => makeEgress({ kind: "xray-uri", masked: "vless://vless.example.com:443" }), "egress.form.uri"],
    ["the URL of a subscription", () => makeEgress({ kind: "xray-subscription", masked: "https://sub.example.com", params: { select: "all" } }), "egress.form.url"],
    ["a password", office, "egress.form.password"],
  ] as const)("does not fill in %s, which the panel never sends", (_name, egress, key) => {
    open(egress());
    expect(field(key)).toHaveValue("");
  });

  it("keeps the stored password while the address and the username stay: it sends no parameters", async () => {
    const { panel, user } = open(office());
    expect(screen.getByText(t("egress.form.passwordKept"))).toBeInTheDocument();
    // Kind and node are fixed.
    expect(field("egress.form.kind")).toBeDisabled();

    await user.clear(field("egress.form.name"));
    await user.type(field("egress.form.name"), "Office 2");
    await user.click(button("egress.form.save"));

    await waitFor(() => {
      expect(panel.rpc.updateEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateEgress.mock.calls[0]?.[0]).toEqual(create(UpdateEgressRequestSchema, { id: "eg-1", name: "Office 2" }));
  });

  it.each([
    ["address", "egress.form.addr", "198.51.100.10:1080", { addr: "198.51.100.10:1080", username: "user" }],
    ["username", "egress.form.username", "admin", { addr: "198.51.100.9:1080", username: "admin" }],
  ] as const)("asks for the password again for a new %s, and then lets go of it", async (_name, key, text, sent) => {
    const { panel, user, queryClient } = open(office());
    await user.clear(field(key));
    await user.type(field(key), text);
    await user.click(button("egress.form.save"));

    expect(await screen.findByText(t("validation.passwordAgain"))).toBeInTheDocument();
    expect(panel.rpc.updateEgress).not.toHaveBeenCalled();

    await user.type(field("egress.form.password"), NEW_PASSWORD);
    await user.click(button("egress.form.save"));
    await waitFor(() => {
      expect(panel.rpc.updateEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateEgress.mock.calls[0]?.[0]).toEqual(
      create(UpdateEgressRequestSchema, { id: "eg-1", params: { ...sent, password: NEW_PASSWORD } }),
    );
    // Saved: the field is empty again, and nothing keeps the password.
    expect(await screen.findByText(t("egress.form.saved"))).toBeInTheDocument();
    await waitFor(() => {
      expect(field("egress.form.password")).toHaveValue("");
    });
    expect(heldByMutations(queryClient)).not.toContain(NEW_PASSWORD);
  });

  it("shows what is stored of a share link, keeps it when nothing is typed, and sends only the name when only it changed", async () => {
    const egress = makeEgress({ id: "eg-2", name: "Link", kind: "xray-uri", masked: "vless://vless.example.com:443" });
    const { panel, user } = open(egress);
    expect(screen.getByText(t("egress.form.uriKept", { masked: "vless://vless.example.com:443" }))).toBeInTheDocument();

    await user.clear(field("egress.form.name"));
    await user.type(field("egress.form.name"), "Renamed");
    await user.click(button("egress.form.save"));
    await waitFor(() => {
      expect(panel.rpc.updateEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.updateEgress.mock.calls[0]?.[0]).toEqual(create(UpdateEgressRequestSchema, { id: "eg-2", name: "Renamed" }));
  });

  it("shows the refusal of the panel as it is, keeps what was typed and says nothing of success", async () => {
    const refusal = "upgrade node Frankfurt to use egresses through an interface of the node (egress-interface)";
    const egress = makeEgress({ id: "eg-3", name: "Tunnel", kind: "direct", nodeId: NODE.id });
    const { panel, user, onDone } = open(egress);
    panel.rpc.updateEgress.mockImplementation(() => {
      throw new ConnectError(refusal, Code.FailedPrecondition);
    });

    await user.type(field("egress.form.interface"), "wg0");
    await user.click(button("egress.form.save"));

    expect(await screen.findByText(refusal)).toBeInTheDocument();
    expect(screen.queryByText(t("egress.form.saved"))).not.toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(field("egress.form.interface")).toHaveValue("wg0");
  });
});

describe("EgressForm: the check", () => {
  it("asks the panel and shows what it says", async () => {
    const { panel, user } = open();
    await choose(user, "egress.form.kind", t("egress.kinds.xrayUri"));
    await user.type(field("egress.form.uri"), LINK);
    await user.click(button("egress.form.check"));

    expect(await screen.findByText(t("egress.form.valid"))).toBeInTheDocument();
    expect(screen.getByText(t("egress.form.validLink", { protocol: "vless", security: "none", network: "tcp", masked: "vless://vless.example.com:443" }))).toBeInTheDocument();
    expect(panel.rpc.validateEgress.mock.calls[0]?.[0]).toEqual(
      create(ValidateEgressRequestSchema, { kind: "xray-uri", id: "", params: { uri: LINK } }),
    );

    panel.rpc.validateEgress.mockImplementationOnce(() => ({ valid: false, problem: "params: uri: vless: the server address is missing" }));
    await user.click(button("egress.form.check"));
    expect(await screen.findByText("params: uri: vless: the server address is missing")).toBeInTheDocument();
    expect(panel.rpc.createEgress).not.toHaveBeenCalled();
  });

  it("asks about an egress that exists by its id, so that the panel fills in the stored secrets", async () => {
    const egress = makeEgress({ id: "eg-s", name: "Sub", kind: "xray-subscription", masked: "https://sub.example.com", params: { select: "first" } });
    const { panel, user } = open(egress);
    await user.click(button("egress.form.check"));

    await waitFor(() => {
      expect(panel.rpc.validateEgress).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.validateEgress.mock.calls[0]?.[0]).toEqual(
      create(ValidateEgressRequestSchema, { kind: "xray-subscription", id: "eg-s", params: { select: "first" } }),
    );
  });

  it("takes the verdict away once the parameters change", async () => {
    const { user } = open();
    await choose(user, "egress.form.kind", t("egress.kinds.xrayUri"));
    await user.type(field("egress.form.uri"), LINK);
    await user.click(button("egress.form.check"));
    expect(await screen.findByText(t("egress.form.valid"))).toBeInTheDocument();

    await user.type(field("egress.form.uri"), "x");
    expect(screen.queryByText(t("egress.form.valid"))).not.toBeInTheDocument();
  });
});
