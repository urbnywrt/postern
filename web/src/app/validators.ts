import type { ValidationError } from "./validation";

// The rules of the panel for what an admin types into the forms of nodes,
// listeners and proxies: internal/panel/nodes/service.go and
// internal/panel/proxies/validate.go. The panel checks everything again, and a
// rule that is wrong here only costs a round trip, so these follow the panel as
// closely as a browser allows and stay on its side where the two could differ.

export const MAX_NAME_CHARS = 64;
export const MAX_NOTE_CHARS = 1024;
export const MAX_LIMIT = 4_294_967_295; // a uint32
const MAX_HOST_LENGTH = 253; // a DNS name
const MAX_LABEL_LENGTH = 63;
const SECRET_HEX_LENGTH = 32; // 16 bytes

/**
 * A node keeps these loopback ports for its own services (engines, their APIs,
 * the SOCKS ports of the edge and of the egresses): a listener on 0.0.0.0 or on
 * 127.0.0.1 there would collide with one of them, and the node refuses it.
 */
export const INTERNAL_PORT_FIRST = 20000;
export const INTERNAL_PORT_LAST = 40999;

/** Code points, not UTF-16 units: the panel counts runes. */
const charCount = (text: string) => Array.from(text).length;

// ---- names and notes ---------------------------------------------------------

function nameProblem(name: string): ValidationError | null {
  if (charCount(name) > MAX_NAME_CHARS) {
    return "nameLong";
  }
  return /\p{Cc}/u.test(name) ? "controlChars" : null;
}

/** The name of a node: 1 to 64 characters, no control characters. */
export function validateNodeName(value: string): ValidationError | null {
  const name = value.trim();
  return name === "" ? "required" : nameProblem(name);
}

/** The name of a proxy: the same, and it may be empty. */
export function validateProxyName(value: string): ValidationError | null {
  const name = value.trim();
  return name === "" ? null : nameProblem(name);
}

export function validateNote(value: string): ValidationError | null {
  return charCount(value) > MAX_NOTE_CHARS ? "noteLong" : null;
}

// ---- hosts and addresses -----------------------------------------------------

const IPV4_OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`);

/** Four decimal octets, without leading zeros. */
export function isIPv4(text: string): boolean {
  return IPV4.test(text);
}

/** An IPv6 address without brackets and without a zone. The URL parser is the judge of the notation. */
export function isIPv6(text: string): boolean {
  // Only these characters, so that the text cannot close the brackets and add a port or a path.
  if (!text.includes(":") || !/^[0-9A-Fa-f:.]+$/.test(text)) {
    return false;
  }
  try {
    return new URL(`http://[${text}]/`).hostname !== "";
  } catch {
    return false;
  }
}

/**
 * A host name: dot-separated labels of 1 to 63 letters, digits and hyphens that
 * neither start nor end with a hyphen, at most 253 characters in all, and a last
 * label that is not all digits (that would be a mistyped IPv4 address). No dot at
 * the end, no underscore, no characters beyond ASCII.
 */
export function isValidHostName(text: string): boolean {
  if (text === "" || text.length > MAX_HOST_LENGTH) {
    return false;
  }
  const labels = text.split(".");
  for (const label of labels) {
    if (label === "" || label.length > MAX_LABEL_LENGTH || label.startsWith("-") || label.endsWith("-")) {
      return false;
    }
    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return false;
    }
  }
  return /\D/.test(labels.at(-1) ?? "");
}

/** An IP address (IPv6 without brackets) or a host name. */
export function isValidHost(text: string): boolean {
  return isIPv4(text) || isIPv6(text) || isValidHostName(text);
}

/** The host of a node that is to be reached: required. */
export function validateHost(value: string): ValidationError | null {
  const host = value.trim();
  if (host === "") {
    return "required";
  }
  return isValidHost(host) ? null : "host";
}

/** A host that may be left out: a link host, and the link host of a listener. */
export function validateOptionalHost(value: string): ValidationError | null {
  return value.trim() === "" ? null : validateHost(value);
}

// ---- ports -------------------------------------------------------------------

/** A whole number of 1 to 65535, in ASCII digits. */
export function validatePort(value: string): ValidationError | null {
  const port = value.trim();
  if (port === "") {
    return "required";
  }
  return /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535 ? null : "port";
}

/** A port that the panel picks when it is left out. */
export function validateOptionalPort(value: string): ValidationError | null {
  return value.trim() === "" ? null : validatePort(value);
}

function isListenable(ip: string): boolean {
  const first = Number(ip.split(".")[0]);
  const multicast = first >= 224 && first <= 239;
  const linkLocal = ip.startsWith("169.254.");
  return !multicast && !linkLocal && ip !== "255.255.255.255";
}

/**
 * The bind address of a listener: an IPv4 address that a node can listen on, or
 * empty for 0.0.0.0, all of them. There are no IPv6 listeners yet.
 */
export function validateBindIp(value: string): ValidationError | null {
  const ip = value.trim();
  if (ip === "") {
    return null;
  }
  return isIPv4(ip) && isListenable(ip) ? null : "bindIp";
}

/**
 * The port of a listener on a bind address. On 0.0.0.0 and on 127.0.0.1 (and not
 * on another loopback address) the ports that the node keeps are refused.
 */
export function validateListenerPort(port: string, bindIp: string): ValidationError | null {
  const problem = validatePort(port);
  if (problem !== null) {
    return problem;
  }
  const ip = bindIp.trim() === "" ? "0.0.0.0" : bindIp.trim();
  const number = Number(port.trim());
  const collides = (ip === "0.0.0.0" || ip === "127.0.0.1") && number >= INTERNAL_PORT_FIRST && number <= INTERNAL_PORT_LAST;
  return collides ? "portInternal" : null;
}

// ---- the mask target of a listener ------------------------------------------

/** What Go's net.SplitHostPort makes of text; nothing where it gives an error. */
function splitHostPort(text: string): { host: string; port: string } | undefined {
  const colon = text.lastIndexOf(":");
  if (colon < 0) {
    return undefined;
  }
  let host: string;
  if (text.startsWith("[")) {
    // The first ] has to be just before the last colon.
    const end = text.indexOf("]");
    if (end < 0 || end + 1 !== colon) {
      return undefined;
    }
    host = text.slice(1, end);
  } else {
    host = text.slice(0, colon);
    if (host.includes(":")) {
      return undefined; // a bare IPv6 address, which has no port
    }
  }
  if (host.includes("[") || host.includes("]")) {
    return undefined;
  }
  return { host, port: text.slice(colon + 1) };
}

/** The loopback or the unspecified address, or an IPv4 one wrapped in IPv6: dialing it reaches the node itself. */
function isOwnAddress(host: string): boolean {
  if (isIPv4(host)) {
    return host.startsWith("127.") || host === "0.0.0.0";
  }
  if (!isIPv6(host)) {
    return false;
  }
  // The URL parser writes an address in its shortest form, and an IPv4 address inside IPv6 in hex.
  const form = new URL(`http://[${host}]/`).hostname.slice(1, -1).toLowerCase();
  return form === "::1" || form === "::" || form === "::ffff:0:0" || /^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(form);
}

/**
 * Where a listener relays the connections of strangers to: empty (the server name
 * of the stranger), a host, or host:port ([IPv6]:port). A target on the internal
 * loopback ports of the node is refused: the edge would relay strangers to an
 * engine of the node.
 */
export function validateMaskTarget(value: string): ValidationError | null {
  const target = value.trim();
  if (target === "") {
    return null;
  }
  let host = target;
  let port = 443;
  const split = splitHostPort(target);
  if (split !== undefined) {
    if (!/^\d+$/.test(split.port) || Number(split.port) < 1 || Number(split.port) > 65535) {
      return "maskTarget";
    }
    host = split.host;
    port = Number(split.port);
  }
  if (!isValidHost(host)) {
    return "maskTarget";
  }
  const named = host.replace(/\.$/, "").toLowerCase() === "localhost";
  const internal = port >= INTERNAL_PORT_FIRST && port <= INTERNAL_PORT_LAST && (named || isOwnAddress(host));
  return internal ? "maskTargetInternal" : null;
}

// ---- egresses ----------------------------------------------------------------

// The rules of the node for the parameters of an egress (internal/node/state,
// and internal/edge/rules for the proxies), which the panel applies to them
// (internal/panel/egress), and its bounds of the check of a chain.

/** The longest username, and password, of a SOCKS5 proxy: one byte of length each (RFC 1929). */
export const MAX_SOCKS5_CREDENTIAL_BYTES = 255;
/** The longest username, and password, of an HTTP proxy, which go in a header of every CONNECT (rules.MaxHTTPCredential). */
export const MAX_HTTP_CREDENTIAL_BYTES = 1024;
export const MAX_SUBSCRIPTION_URL_BYTES = 2048;
/** The longest text that a selection of the servers of a subscription by name looks for. */
export const MAX_SELECT_NAME_BYTES = 128;
/** The longest name of a network interface of Linux (IFNAMSIZ less its NUL). */
const MAX_INTERFACE_LENGTH = 15;
export const MAX_CHECK_INTERVAL = 3600; // seconds
export const MAX_CHECK_TIMEOUT = 60; // seconds
export const MAX_CHECK_THRESHOLD = 100;

/** Bytes of UTF-8, which the panel counts. */
const byteCount = (text: string) => new TextEncoder().encode(text).length;

/** Characters that a host cannot have where the edge puts it: in a request, and in a CONNECT line. */
const HOST_SYNTAX = "/\\@#?[]%";

/**
 * The address of the proxy that an egress goes through, host:port, as the edge
 * reads it (rules.ParseHostPort) and the node checks it (state.CheckHostPort): a
 * port of 1 to 65535; a host that is not empty and has no space, no control
 * character and none of / \ @ # ? [ ] % (so that it can stand in a request);
 * and brackets for an IPv6 address, which needs them. A name is not checked
 * further: underscores, a dot at the end and names beyond ASCII are taken, as
 * the edge takes them. Each kind of mistake has a message of its own.
 */
export function validateHostPort(value: string): ValidationError | null {
  const text = value.trim();
  if (text === "") {
    return "required";
  }
  const split = splitHostPort(text);
  if (split === undefined || split.host === "") {
    return "hostPort";
  }
  if (!/^\d+$/.test(split.port) || Number(split.port) < 1 || Number(split.port) > 65535) {
    return "hostPortPort";
  }
  const { host } = split;
  const syntax = Array.from(host).some((c) => c <= " " || c === "\u007f" || HOST_SYNTAX.includes(c));
  if (syntax || /[\p{White_Space}\p{Cc}]/u.test(host)) {
    return "hostPortChars";
  }
  const bracketed = text.startsWith("[");
  if (isIPv4(host) || isIPv6(host)) {
    return bracketed === isIPv6(host) ? null : "hostPortBrackets";
  }
  return bracketed ? "hostPortBrackets" : null;
}

/**
 * The username of the proxy of an egress, as the panel sends it (it is not
 * trimmed): at most 255 bytes for SOCKS5; at most 1024 bytes for HTTP, and no
 * colon, which Basic authentication joins it to the password with.
 */
export function validateProxyUsername(kind: string, username: string): ValidationError | null {
  if (kind === "socks5" && byteCount(username) > MAX_SOCKS5_CREDENTIAL_BYTES) {
    return "credentialLong";
  }
  if (kind === "http" && byteCount(username) > MAX_HTTP_CREDENTIAL_BYTES) {
    return "httpCredentialLong";
  }
  return kind === "http" && username.includes(":") ? "usernameColon" : null;
}

/**
 * The password of the proxy of an egress needs a user (SOCKS5 and HTTP send
 * the two together), and has at most 255 bytes for SOCKS5 and 1024 for HTTP.
 */
export function validateProxyPassword(kind: string, username: string, password: string): ValidationError | null {
  if (username === "" && password !== "") {
    return "passwordUser";
  }
  if (kind === "socks5" && byteCount(password) > MAX_SOCKS5_CREDENTIAL_BYTES) {
    return "credentialLong";
  }
  return kind === "http" && byteCount(password) > MAX_HTTP_CREDENTIAL_BYTES ? "httpCredentialLong" : null;
}

/**
 * The panel keeps a stored password, for an empty one, only while the address
 * and the username stay as they were stored (UpdateEgressRequest): a password
 * goes only to the proxy and the user that it was given for. With a new address
 * or username it has to be typed again.
 */
export function validateStoredPassword(
  stored: { addr: string; username: string; passwordSet: boolean } | undefined,
  addr: string,
  username: string,
  password: string,
): ValidationError | null {
  if (stored === undefined || !stored.passwordSet || username === "" || password !== "") {
    return null;
  }
  return addr.trim() !== stored.addr || username !== stored.username ? "passwordAgain" : null;
}

/**
 * The interface of a direct egress, or empty for the one of the default route:
 * a Linux interface name, 1 to 15 ASCII characters without a space, a control
 * character, / or :, and neither "." nor "..".
 */
export function validateInterface(value: string): ValidationError | null {
  const name = value.trim();
  if (name === "") {
    return null;
  }
  const valid = name.length <= MAX_INTERFACE_LENGTH && name !== "." && name !== ".." && /^[\x21-\x7e]+$/.test(name) && !/[/:]/.test(name);
  return valid ? null : "interface";
}

/** The source address of a direct egress, or empty to let the node pick: an IPv4 or IPv6 address, without a zone. */
export function validateSourceIp(value: string): ValidationError | null {
  const ip = value.trim();
  return ip === "" || isIPv4(ip) || isIPv6(ip) ? null : "sourceIp";
}

/**
 * The URL of a subscription: at most 2048 bytes, without a space or a control
 * character (the node takes what is a space to Go, and the controls of ASCII).
 * It is required for a new subscription; empty keeps the stored one.
 */
export function validateSubscriptionUrl(value: string, required: boolean): ValidationError | null {
  const url = value.trim();
  if (url === "") {
    return required ? "required" : null;
  }
  if (byteCount(url) > MAX_SUBSCRIPTION_URL_BYTES) {
    return "urlLong";
  }
  const spaceOrControl = (c: string) => c <= " " || c === "\u007f" || /\p{White_Space}/u.test(c);
  return Array.from(url).some(spaceOrControl) ? "urlSpaces" : null;
}

/** The text that a selection of the servers of a subscription by name looks for: 1 to 128 bytes. */
/**
 * A Psiphon partner id of a psiphon egress (propagation channel or sponsor):
 * empty, or 16 hexadecimal digits; the two go together (both or neither), as
 * internal/node/state ParsePsiphonParams has it.
 */
export function validatePartnerId(value: string, other: string): ValidationError | null {
  const id = value.trim();
  if (id === "") {
    return other.trim() === "" ? null : "partnerPair";
  }
  return /^[0-9A-Fa-f]{16}$/.test(id) ? null : "partnerId";
}

export function validateSelectName(value: string): ValidationError | null {
  const text = value.trim();
  if (text === "") {
    return "required";
  }
  return byteCount(text) > MAX_SELECT_NAME_BYTES ? "selectLong" : null;
}

/** A value of the check of a chain: a whole number from 0 (the default of the node, also when empty) to `max`. */
function checkValue(value: string, max: number, error: ValidationError): ValidationError | null {
  const text = value.trim();
  if (text === "") {
    return null;
  }
  return /^\d+$/.test(text) && Number(text) <= max ? null : error;
}

export const validateCheckInterval = (value: string) => checkValue(value, MAX_CHECK_INTERVAL, "checkInterval");
export const validateCheckTimeout = (value: string) => checkValue(value, MAX_CHECK_TIMEOUT, "checkTimeout");
export const validateCheckThreshold = (value: string) => checkValue(value, MAX_CHECK_THRESHOLD, "checkThreshold");

/** A value of the check of a chain as it is sent: empty is 0, the default of the node. */
export function parseCheckValue(value: string): number {
  const text = value.trim();
  return text === "" ? 0 : Number(text);
}

// ---- proxies -----------------------------------------------------------------

/**
 * The domain of a proxy, the server name that its clients send: a host name of
 * plain ASCII, not an IP address, no dot at the end. It may be empty, and the
 * panel picks a free one from its pool. Its case is kept.
 */
export function validateDomain(value: string): ValidationError | null {
  const domain = value.trim();
  return domain === "" || isValidHostName(domain) ? null : "domain";
}

function isHex(text: string, length: number): boolean {
  return new RegExp(`^[0-9a-fA-F]{${String(length)}}$`).test(text);
}

/** The secret of a proxy: exactly 32 hex digits, or empty for a random one. */
export function validateSecret(value: string): ValidationError | null {
  const secret = value.trim();
  return secret === "" || isHex(secret, SECRET_HEX_LENGTH) ? null : "secret";
}

/** The promotion tag of a proxy: exactly 32 hex digits, or empty. */
export function validateAdTag(value: string): ValidationError | null {
  const tag = value.trim();
  return tag === "" || isHex(tag, SECRET_HEX_LENGTH) ? null : "adTag";
}

/** A limit: a whole number of 0 to 4294967295, and empty is 0, no limit. */
export function validateLimit(value: string): ValidationError | null {
  const limit = value.trim();
  if (limit === "") {
    return null;
  }
  return /^\d+$/.test(limit) && Number(limit) <= MAX_LIMIT ? null : "limit";
}

// ---- WEB proxies and http-upstream listeners ---------------------------------

/** The domain of a WEB proxy: a host name of at least two labels; it is also the address. */
export function validateWebDomain(value: string): ValidationError | null {
  const domain = value.trim();
  if (domain === "") {
    return "required";
  }
  if (!isValidHostName(domain)) {
    return "domain";
  }
  return domain.includes(".") ? null : "webDomain";
}

export const MAX_BASE_PATH_SEGMENT = 128;

/**
 * The base path of a WEB proxy: empty, or segments of [A-Za-z0-9][A-Za-z0-9_-]*
 * of at most 128 bytes, joined by single slashes, none at either end. It is
 * required on an http-upstream listener.
 */
export function validateBasePath(value: string, required: boolean): ValidationError | null {
  const path = value.trim();
  if (path === "") {
    return required ? "basePathRequired" : null;
  }
  const segments = path.split("/");
  const ok = segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(segment) && segment.length <= MAX_BASE_PATH_SEGMENT);
  return ok ? null : "basePath";
}

/** A loopback or private IPv4 or IPv6 address (RFC 1918, RFC 4193): where http-upstream listeners live and whom they trust. */
function isLoopbackOrPrivate(ip: string): boolean {
  if (isIPv4(ip)) {
    const [a = 0, b = 0] = ip.split(".").map(Number);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (!isIPv6(ip)) {
    return false;
  }
  const form = new URL(`http://[${ip}]/`).hostname.slice(1, -1).toLowerCase();
  return form === "::1" || /^f[cd]/.test(form);
}

/** The bind address of an http-upstream listener: a loopback or private IPv4 address (127.0.0.1 when empty). */
export function validateUpstreamBindIp(value: string): ValidationError | null {
  const ip = value.trim();
  if (ip === "") {
    return null;
  }
  return isIPv4(ip) && isLoopbackOrPrivate(ip) ? null : "upstreamBindIp";
}

/**
 * The trusted CIDRs of an http-upstream listener, one per line: prefixes or
 * addresses inside the loopback or private ranges, at least one. The panel
 * judges the prefix length for real; here a prefix only has to be a number.
 */
export function validateTrustedCidrs(value: string): ValidationError | null {
  const entries = parseLines(value);
  if (entries.length === 0) {
    return "trustedCidrsRequired";
  }
  for (const entry of entries) {
    const slash = entry.indexOf("/");
    const address = slash < 0 ? entry : entry.slice(0, slash);
    const bits = slash < 0 ? null : entry.slice(slash + 1);
    const maxBits = isIPv4(address) ? 32 : isIPv6(address) ? 128 : -1;
    if (maxBits < 0 || !isLoopbackOrPrivate(address)) {
      return "trustedCidr";
    }
    if (bits !== null && !(/^\d{1,3}$/.test(bits) && Number(bits) <= maxBits)) {
      return "trustedCidr";
    }
  }
  return null;
}

/** The non-empty lines of a textarea, trimmed. */
export function parseLines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** The contact of an ACME account: empty, or something like an email address. */
export function validateAcmeEmail(value: string): ValidationError | null {
  const email = value.trim();
  if (email === "") {
    return null;
  }
  const at = email.indexOf("@");
  return at > 0 && at < email.length - 1 && !email.slice(at + 1).includes("@") && !/[\s\p{Cc}]/u.test(email) ? null : "email";
}

/** An imported certificate: the chain and the key go together, and look like PEM. */
export function validateCertificatePair(chain: string, key: string, required: boolean): ValidationError | null {
  const c = chain.trim();
  const k = key.trim();
  if (c === "" && k === "") {
    return required ? "certificate" : null;
  }
  return c.includes("-----BEGIN CERTIFICATE-----") && k.includes("PRIVATE KEY-----") ? null : "certificate";
}

export function parseLimit(value: string): number {
  const limit = value.trim();
  return limit === "" ? 0 : Number(limit);
}

// ---- SSH ---------------------------------------------------------------------

const MAX_SSH_USER_LENGTH = 64;

/**
 * The user that the panel logs in to a server as (internal/panel/deploy):
 * letters, digits and . _ @ -, not starting with a dot or a hyphen, perhaps
 * ending in $, at most 64 characters.
 */
export function validateSshUser(value: string): ValidationError | null {
  const user = value.trim();
  if (user === "") {
    return "required";
  }
  return user.length <= MAX_SSH_USER_LENGTH && /^[A-Za-z0-9_@][A-Za-z0-9._@-]*\$?$/.test(user) ? null : "sshUser";
}
