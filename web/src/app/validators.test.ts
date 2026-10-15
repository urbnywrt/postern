import { describe, expect, it } from "vitest";

import { t } from "../test/t";
import { validationMessage } from "./validation";
import {
  isValidHost,
  parseCheckValue,
  parseLimit,
  validateAdTag,
  validateBindIp,
  validateCheckInterval,
  validateCheckThreshold,
  validateCheckTimeout,
  validateDomain,
  validateHost,
  validateHostPort,
  validateInterface,
  validateLimit,
  validateListenerPort,
  validateMaskTarget,
  validateNodeName,
  validateNote,
  validateOptionalHost,
  validateOptionalPort,
  validatePort,
  validateProxyName,
  validateProxyPassword,
  validateProxyUsername,
  validateSecret,
  validatePartnerId,
  validateSelectName,
  validateSourceIp,
  validateSshUser,
  validateStoredPassword,
  validateSubscriptionUrl,
} from "./validators";

// These are the rules of the panel for what an admin types (internal/panel/nodes and
// internal/panel/proxies). The panel checks them again; the forms check them first
// so that a mistake is pointed out at once.

describe("names and notes", () => {
  it.each([
    ["", "required"],
    ["   ", "required"],
    ["Frankfurt 1", null],
    ["  padded  ", null], // the panel trims it
    ["a".repeat(64), null],
    ["a".repeat(65), "nameLong"],
    ["😀".repeat(64), null], // characters, not bytes or UTF-16 units
    ["😀".repeat(65), "nameLong"],
    ["tab\tin it", "controlChars"],
    ["line\nbreak", "controlChars"],
  ] as const)("a node name %j gives %s", (value, expected) => {
    expect(validateNodeName(value)).toBe(expected);
  });

  it("lets a proxy go without a name, and holds it to the same limits otherwise", () => {
    expect(validateProxyName("")).toBeNull();
    expect(validateProxyName("   ")).toBeNull();
    expect(validateProxyName("a".repeat(64))).toBeNull();
    expect(validateProxyName("a".repeat(65))).toBe("nameLong");
    expect(validateProxyName("bell\u0007")).toBe("controlChars");
  });

  it("limits a note to 1024 characters, and allows line breaks in it", () => {
    expect(validateNote("")).toBeNull();
    expect(validateNote("first line\nsecond line")).toBeNull();
    expect(validateNote("я".repeat(1024))).toBeNull();
    expect(validateNote("я".repeat(1025))).toBe("noteLong");
    expect(validateNote("😀".repeat(1025))).toBe("noteLong");
  });
});

describe("hosts", () => {
  it.each([
    ["203.0.113.7", true],
    ["192.0.2.1", true],
    ["2001:db8::1", true],
    ["::1", true],
    ["::ffff:192.0.2.1", true],
    ["node.example.com", true],
    ["Node-1.Example.COM", true],
    ["localhost", true],
    [`${"a".repeat(63)}.example.com`, true],
    // not a host
    ["", false],
    ["http://node.example.com", false],
    ["node.example.com:22", false],
    ["node.example.com/path", false],
    ["203.0.113.7:22", false],
    ["[2001:db8::1]", false], // no brackets
    ["fe80::1%eth0", false], // no zone
    ["2001:db8::g", false],
    ["::1]:80/x[", false],
    ["node..example.com", false],
    [".example.com", false],
    ["example.com.", false],
    ["-node.example.com", false],
    ["node-.example.com", false],
    ["no_de.example.com", false],
    ["no de.example.com", false],
    ["узел.example.com", false],
    [`${"a".repeat(64)}.example.com`, false],
    [`${"a".repeat(60)}.`.repeat(5) + "com", false], // longer than 253
    ["203.0.113", false], // a mistyped address: the last label is all digits
    ["203.0.113.256", false],
    ["203.00.113.7", false], // a leading zero
    ["203.0.113.7.1", false],
  ] as const)("%j is a host: %s", (value, expected) => {
    expect(isValidHost(value)).toBe(expected);
  });

  it("is required for the management host, and may be empty for a link host", () => {
    expect(validateHost("")).toBe("required");
    expect(validateHost("   ")).toBe("required");
    expect(validateHost("example.com:22")).toBe("host");
    expect(validateHost(" 203.0.113.7 ")).toBeNull(); // the panel trims it
    expect(validateOptionalHost("")).toBeNull();
    expect(validateOptionalHost("  ")).toBeNull();
    expect(validateOptionalHost("example.com:22")).toBe("host");
    expect(validateOptionalHost("link.example.com")).toBeNull();
  });
});

describe("ports", () => {
  it.each([
    ["1", null],
    ["443", null],
    ["65535", null],
    [" 443 ", null],
    ["", "required"],
    ["0", "port"],
    ["65536", "port"],
    ["-1", "port"],
    ["80.5", "port"],
    ["1e3", "port"],
    ["0x50", "port"],
    ["abc", "port"],
    ["٤٤٣", "port"], // Arabic-Indic digits
    ["99999999999999999999", "port"],
  ] as const)("the port %j gives %s", (value, expected) => {
    expect(validatePort(value)).toBe(expected);
  });

  it("may be left out where the panel picks one", () => {
    expect(validateOptionalPort("")).toBeNull();
    expect(validateOptionalPort("  ")).toBeNull();
    expect(validateOptionalPort("8443")).toBeNull();
    expect(validateOptionalPort("0")).toBe("port");
    expect(validateOptionalPort("70000")).toBe("port");
  });
});

describe("bind addresses", () => {
  it.each([
    ["", null], // 0.0.0.0
    ["0.0.0.0", null],
    ["127.0.0.1", null],
    ["127.0.0.2", null],
    ["203.0.113.7", null],
    ["192.0.2.55", null],
    [" 203.0.113.7 ", null],
    ["224.0.0.1", "bindIp"], // multicast
    ["169.254.0.1", "bindIp"], // link-local
    ["255.255.255.255", "bindIp"],
    ["::1", "bindIp"], // no IPv6 listeners
    ["2001:db8::1", "bindIp"],
    ["::", "bindIp"],
    ["203.0.113", "bindIp"],
    ["203.0.113.256", "bindIp"],
    ["203.00.113.7", "bindIp"],
    ["node.example.com", "bindIp"],
  ] as const)("the address %j gives %s", (value, expected) => {
    expect(validateBindIp(value)).toBe(expected);
  });
});

describe("the port of a listener", () => {
  it.each([
    // The node keeps 20000-40999 on the loopback for its own services, so a listener on
    // 0.0.0.0 or on 127.0.0.1 cannot take a port there.
    ["443", "0.0.0.0", null],
    ["443", "", null],
    ["19999", "0.0.0.0", null],
    ["20000", "0.0.0.0", "portInternal"],
    ["25000", "", "portInternal"], // empty is 0.0.0.0
    ["40999", "0.0.0.0", "portInternal"],
    ["41000", "0.0.0.0", null],
    ["25000", "127.0.0.1", "portInternal"],
    ["25000", " 127.0.0.1 ", "portInternal"],
    // a specific address does not collide with the loopback
    ["25000", "203.0.113.7", null],
    ["25000", "127.0.0.2", null],
    // the port itself has to be right first
    ["", "0.0.0.0", "required"],
    ["0", "0.0.0.0", "port"],
    ["70000", "0.0.0.0", "port"],
    // an address that is not valid is the problem of the address, not of the port
    ["25000", "::1", null],
  ] as const)("the port %j on %j gives %s", (port, bindIp, expected) => {
    expect(validateListenerPort(port, bindIp)).toBe(expected);
  });
});

describe("mask targets", () => {
  it.each([
    ["", null],
    ["www.example.com", null],
    ["www.example.com:8443", null],
    ["203.0.113.7", null],
    ["203.0.113.7:443", null],
    ["2001:db8::1", null], // a bare IPv6 address is a host
    ["[2001:db8::1]:443", null],
    [" www.example.com ", null],
    ["127.0.0.1:443", null], // only 20000-40999 on the loopback is kept
    ["127.0.0.1:41000", null],
    ["127.0.0.1:19999", null],
    ["example.com:25000", null], // a real host may use any port
    ["http://www.example.com", "maskTarget"],
    ["www.example.com/path", "maskTarget"],
    ["www.example.com:0", "maskTarget"],
    ["www.example.com:65536", "maskTarget"],
    ["www.example.com:", "maskTarget"],
    ["www.example.com:https", "maskTarget"],
    ["exa mple.com", "maskTarget"],
    ["[2001:db8::1]", "maskTarget"], // brackets need a port
    ["example.com.", "maskTarget"],
    ["localhost:20000", "maskTargetInternal"],
    ["LocalHost:40999", "maskTargetInternal"],
    ["127.0.0.1:25000", "maskTargetInternal"],
    ["0.0.0.0:30000", "maskTargetInternal"],
    ["[::1]:30000", "maskTargetInternal"],
    ["[::ffff:127.0.0.1]:35000", "maskTargetInternal"],
  ] as const)("the target %j gives %s", (value, expected) => {
    expect(validateMaskTarget(value)).toBe(expected);
  });
});

describe("domains", () => {
  it.each([
    ["www.example.com", null],
    ["Example.COM", null], // the case is kept
    ["a-b.example.com", null],
    ["localhost", null],
    ["  www.example.com  ", null], // the panel trims it
    ["", null], // the panel picks one from its pool
    ["   ", null],
    ["www.example.com.", "domain"], // no dot at the end
    ["ex_ample.com", "domain"],
    ["пример.рф", "domain"], // plain ASCII only: no IDN
    ["xn--e1afmkfd.xn--p1ai", null], // its punycode form is plain ASCII
    ["-a.example.com", "domain"],
    ["a-.example.com", "domain"],
    ["a..example.com", "domain"],
    ["203.0.113.7", "domain"], // an IP address is not a name
    ["2001:db8::1", "domain"],
    ["www.example.com:443", "domain"],
    ["https://www.example.com", "domain"],
    ["www example.com", "domain"],
    [`${"a".repeat(64)}.example.com`, "domain"],
    [`${"a.".repeat(127)}com`, "domain"], // 257 characters
  ] as const)("the domain %j gives %s", (value, expected) => {
    expect(validateDomain(value)).toBe(expected);
  });
});

describe("secrets and ad tags", () => {
  const hex = "0123456789abcdef0123456789ABCDEF";

  it.each([
    ["", null], // the panel makes a random secret
    [hex, null],
    [` ${hex} `, null], // the panel trims it
    ["a".repeat(32), null],
    ["a".repeat(31), "secret"],
    ["a".repeat(33), "secret"],
    ["g".repeat(32), "secret"],
    [`${"a".repeat(31)}-`, "secret"],
    [`ee${hex}`, "secret"], // the link form, not the secret
    [`0x${"a".repeat(30)}`, "secret"],
    ["١".repeat(32), "secret"],
  ] as const)("the secret %j gives %s", (value, expected) => {
    expect(validateSecret(value)).toBe(expected);
  });

  it("holds the ad tag to the same shape, with a message of its own", () => {
    expect(validateAdTag("")).toBeNull();
    expect(validateAdTag(hex)).toBeNull();
    expect(validateAdTag("a".repeat(31))).toBe("adTag");
    expect(validateAdTag("z".repeat(32))).toBe("adTag");
  });
});

describe("limits", () => {
  it.each([
    ["", null], // no limit
    ["0", null],
    ["5", null],
    [" 5 ", null],
    ["4294967295", null],
    ["4294967296", "limit"],
    ["-1", "limit"],
    ["1.5", "limit"],
    ["1e3", "limit"],
    ["abc", "limit"],
    ["٥", "limit"],
  ] as const)("the limit %j gives %s", (value, expected) => {
    expect(validateLimit(value)).toBe(expected);
  });

  it("is a number, and 0 when the field is empty", () => {
    expect(parseLimit("")).toBe(0);
    expect(parseLimit("  ")).toBe(0);
    expect(parseLimit("25")).toBe(25);
    expect(parseLimit(" 7 ")).toBe(7);
    expect(parseLimit("4294967295")).toBe(4294967295);
  });
});

describe("the user of an SSH target", () => {
  it.each([
    ["", "required"],
    ["root", null],
    ["  ubuntu  ", null], // the form trims it
    ["deploy.bot-2", null],
    ["_svc", null],
    ["admin@corp.example", null],
    ["host$", null], // a machine account
    ["a".repeat(64), null],
    ["a".repeat(65), "sshUser"],
    ["ro ot", "sshUser"],
    ["-x", "sshUser"],
    [".hidden", "sshUser"],
    ["semi;colon", "sshUser"],
    ["ünïcode", "sshUser"],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateSshUser(value)).toBe(expected);
  });
});

// The rules of the node for the parameters of an egress (internal/node/state,
// internal/edge/rules), which the panel applies (internal/panel/egress).
describe("the address of the proxy of an egress", () => {
  it.each([
    ["proxy.example.com:1080", null],
    [" proxy.example.com:1080 ", null], // the panel trims it
    ["198.51.100.9:1080", null],
    ["[2001:db8::1]:1080", null],
    ["[::ffff:198.51.100.9]:1080", null],
    // A name is any host that can stand in a request: as the edge reads it.
    ["my_proxy.internal:1080", null],
    ["proxy.example.com.:1080", null],
    ["прокси.example:1080", null],
    ["proxy.example.com:01080", null],
    ["", "required"],
    ["198.51.100.9", "hostPort"],
    ["2001:db8::1:3128", "hostPort"],
    ["[2001:db8::1]", "hostPort"],
    [":1080", "hostPort"],
    ["proxy.example.com:", "hostPortPort"],
    ["proxy.example.com:0", "hostPortPort"],
    ["proxy.example.com:65536", "hostPortPort"],
    ["proxy.example.com:socks", "hostPortPort"],
    ["proxy example.com:1080", "hostPortChars"],
    ["user@proxy.example.com:1080", "hostPortChars"],
    ["proxy.example.com/path:1080", "hostPortChars"],
    ["proxy%25.example.com:1080", "hostPortChars"],
    [`proxy${String.fromCodePoint(0xa0)}example.com:1080`, "hostPortChars"], // a space beyond ASCII: the node refuses it
    ["proxy\u0085example.com:1080", "hostPortChars"],
    ["[proxy.example.com]:1080", "hostPortBrackets"],
    ["[198.51.100.9]:1080", "hostPortBrackets"],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateHostPort(value)).toBe(expected);
  });

  it("says what is wrong, in a message of its own for each", () => {
    const messages = (["hostPort", "hostPortPort", "hostPortChars", "hostPortBrackets"] as const).map((error) =>
      validationMessage(t, error),
    );
    expect(new Set(messages).size).toBe(4);
    expect(validationMessage(t, "hostPortPort")).toContain("65535");
  });
});

describe("the credentials of the proxy of an egress", () => {
  it("holds a SOCKS5 username and password to 255 bytes, as the protocol does", () => {
    expect(validateProxyUsername("socks5", "u".repeat(255))).toBeNull();
    expect(validateProxyUsername("socks5", "u".repeat(256))).toBe("credentialLong");
    expect(validateProxyUsername("socks5", "я".repeat(128))).toBe("credentialLong"); // 256 bytes
    expect(validateProxyPassword("socks5", "user", "p".repeat(255))).toBeNull();
    expect(validateProxyPassword("socks5", "user", "p".repeat(256))).toBe("credentialLong");
    expect(validationMessage(t, "credentialLong")).toBe(t("validation.bytesLong", { max: 255 }));
  });

  it("takes no colon in the username of an HTTP proxy, which Basic authentication joins with one", () => {
    expect(validateProxyUsername("http", "user:name")).toBe("usernameColon");
    expect(validateProxyUsername("socks5", "user:name")).toBeNull();
    expect(validateProxyPassword("http", "user", "pass:word")).toBeNull();
  });

  it("holds an HTTP username and password to 1 KiB each, as the panel, the node and the edge do", () => {
    expect(validateProxyUsername("http", "u".repeat(300))).toBeNull(); // more than SOCKS5 takes
    expect(validateProxyUsername("http", "u".repeat(1024))).toBeNull();
    expect(validateProxyUsername("http", "u".repeat(1025))).toBe("httpCredentialLong");
    expect(validateProxyUsername("http", "я".repeat(513))).toBe("httpCredentialLong"); // 1026 bytes
    expect(validateProxyPassword("http", "user", "p".repeat(1024))).toBeNull();
    expect(validateProxyPassword("http", "user", "p".repeat(1025))).toBe("httpCredentialLong");
    expect(validationMessage(t, "httpCredentialLong")).toBe(t("validation.bytesLong", { max: 1024 }));
  });

  it("needs a username for a password", () => {
    expect(validateProxyPassword("socks5", "", "secret-not-real")).toBe("passwordUser");
    expect(validateProxyPassword("http", "", "")).toBeNull();
  });

  it("keeps a stored password for the same address and username only", () => {
    const stored = { addr: "198.51.100.9:1080", username: "user", passwordSet: true };
    expect(validateStoredPassword(stored, "198.51.100.9:1080", "user", "")).toBeNull();
    expect(validateStoredPassword(stored, " 198.51.100.9:1080 ", "user", "")).toBeNull();
    expect(validateStoredPassword(stored, "198.51.100.10:1080", "user", "")).toBe("passwordAgain");
    expect(validateStoredPassword(stored, "198.51.100.9:1080", "admin", "")).toBe("passwordAgain");
    // A password that is typed, or no username (which takes the password with it), is fine.
    expect(validateStoredPassword(stored, "198.51.100.10:1080", "user", "new-secret-not-real")).toBeNull();
    expect(validateStoredPassword(stored, "198.51.100.10:1080", "", "")).toBeNull();
    // Nothing is stored: nothing is kept.
    expect(validateStoredPassword({ ...stored, passwordSet: false }, "198.51.100.10:1080", "user", "")).toBeNull();
    expect(validateStoredPassword(undefined, "198.51.100.10:1080", "user", "")).toBeNull();
  });
});

describe("a direct egress", () => {
  it.each([
    ["", null],
    ["wg0", null],
    [" wg0 ", null],
    ["a".repeat(15), null],
    ["a".repeat(16), "interface"],
    ["eth0/1", "interface"],
    ["eth0:1", "interface"],
    ["eth 0", "interface"],
    ["wgé", "interface"],
    [".", "interface"],
    ["..", "interface"],
  ] as const)("takes the interface %j: %s", (value, expected) => {
    expect(validateInterface(value)).toBe(expected);
  });

  it.each([
    ["", null],
    ["198.51.100.7", null],
    ["2001:db8::7", null],
    ["::ffff:198.51.100.7", null],
    ["[2001:db8::7]", "sourceIp"],
    ["198.51.100.7:80", "sourceIp"],
    ["fe80::1%eth0", "sourceIp"],
    ["eth0", "sourceIp"],
    ["198.51.100.256", "sourceIp"],
  ] as const)("takes the source address %j: %s", (value, expected) => {
    expect(validateSourceIp(value)).toBe(expected);
  });
});

describe("a subscription", () => {
  const base = "https://sub.example.com/";

  it("takes a URL of up to 2048 bytes, without spaces or control characters", () => {
    expect(validateSubscriptionUrl(`${base}${"a".repeat(2048 - base.length)}`, true)).toBeNull();
    expect(validateSubscriptionUrl(`${base}${"a".repeat(2049 - base.length)}`, true)).toBe("urlLong");
    expect(validateSubscriptionUrl(`${base}a b`, true)).toBe("urlSpaces");
    expect(validateSubscriptionUrl(`${base}a\tb`, true)).toBe("urlSpaces");
    expect(validateSubscriptionUrl(`${base}a${String.fromCodePoint(0x3000)}b`, true)).toBe("urlSpaces");
    expect(validateSubscriptionUrl(`  ${base}token  `, true)).toBeNull();
    expect(validationMessage(t, "urlLong")).toBe(t("validation.bytesLong", { max: 2048 }));
  });

  it("needs a URL only for a new subscription: an empty one keeps the stored one", () => {
    expect(validateSubscriptionUrl("", true)).toBe("required");
    expect(validateSubscriptionUrl("  ", false)).toBeNull();
  });

  it("takes a text of 1 to 128 bytes for a selection by name", () => {
    expect(validateSelectName("Germany")).toBeNull();
    expect(validateSelectName("  ")).toBe("required");
    expect(validateSelectName("n".repeat(128))).toBeNull();
    expect(validateSelectName("n".repeat(129))).toBe("selectLong");
    expect(validateSelectName("я".repeat(65))).toBe("selectLong"); // 130 bytes
    expect(validationMessage(t, "selectLong")).toBe(t("validation.bytesLong", { max: 128 }));
  });

  it("takes the Psiphon partner ids as 16 hex digits, both or neither", () => {
    expect(validatePartnerId("", "")).toBeNull();
    expect(validatePartnerId(" 0123456789abcdef ", "FEDCBA9876543210")).toBeNull();
    expect(validatePartnerId("", "FEDCBA9876543210")).toBe("partnerPair");
    expect(validatePartnerId("0123456789ABCDE", "")).toBe("partnerId");
    expect(validatePartnerId("0123456789ABCDEG", "")).toBe("partnerId");
    expect(validationMessage(t, "partnerPair")).toBe(t("validation.partnerPair"));
  });
});

describe("the health check of a chain", () => {
  it.each([
    [validateCheckInterval, 3600, "checkInterval"],
    [validateCheckTimeout, 60, "checkTimeout"],
    [validateCheckThreshold, 100, "checkThreshold"],
  ] as const)("takes 0 to the maximum, %#", (validate, max, error) => {
    expect(validate("")).toBeNull(); // the default of the node
    expect(validate("0")).toBeNull();
    expect(validate(String(max))).toBeNull();
    expect(validate(` ${String(max)} `)).toBeNull();
    expect(validate(String(max + 1))).toBe(error);
    expect(validate("-1")).toBe(error);
    expect(validate("1.5")).toBe(error);
    expect(validate("ten")).toBe(error);
    expect(validationMessage(t, error)).toContain(String(max));
  });

  it("has a message of its own for each field", () => {
    const messages = (["checkInterval", "checkTimeout", "checkThreshold"] as const).map((error) => validationMessage(t, error));
    expect(new Set(messages).size).toBe(3);
  });

  it("reads an empty field as 0", () => {
    expect(parseCheckValue("")).toBe(0);
    expect(parseCheckValue(" 30 ")).toBe(30);
  });
});
