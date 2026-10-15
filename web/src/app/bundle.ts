// The manual install of a node: the bundle of the node and the node kit of the
// architecture of its server, both downloads from the panel, and the command that
// installs the node from them (NodeService.GetNodeInstall).

/** What the panel names the bundle of a node when it is downloaded (GET /api/nodes/{id}/bundle.tar). */
export const BUNDLE_FILE = "postern-node-bundle.tar";

/** Where the install command of the panel has the architecture of the node kit. */
export const ARCH_PLACEHOLDER = "<ARCH>";

/** The architecture that the install steps start with. */
export const DEFAULT_ARCH = "amd64";

/** What the panel names the node kit of an architecture when it is downloaded (GET /api/node-kit/{arch}). */
export function kitFile(arch: string): string {
  return `postern-node-kit-linux-${arch}.tar`;
}

/** The directory on the server that the files go to, and that the install command runs in. */
export const SERVER_DIR = "/root/postern";

/**
 * The command that rolls the edge of a node, run on the server: it asks the agent to start a new
 * generation of the edge, with the binary of the agent, beside the one that runs, which then
 * drains. An edge keeps the binary that it was started with when the node is updated, until then.
 * It writes the file that install.sh --roll-edge writes, so it works for a node installed with
 * install.sh and for one in Docker alike; umask 077 makes it root's alone (mode 0600), as the
 * agent wants it.
 */
export const ROLL_EDGE_COMMAND = "sudo sh -c 'umask 077; date +%s > /opt/postern/data/run/roll-edge'";

/** The part of the install command of the panel that unpacks the node kit. */
const UNPACK_KIT = /^tar -xf \S+ && /;

/**
 * The install command of the panel with the architecture of the kit filled in. Without the kit
 * (the panel has none for the architecture) the part that unpacks it is left out: the binary and
 * the scripts are put on the server by hand.
 */
export function installCommandFor(command: string, arch: string, withKit = true): string {
  const filled = command.replaceAll(ARCH_PLACEHOLDER, arch);
  return withKit ? filled : filled.replace(UNPACK_KIT, "");
}

/**
 * The command line that copies the files of the install to the server; the admin puts in its
 * address for <SERVER>. It makes the directory first, which a fresh server does not have and scp
 * does not make, and then, when that worked, copies the bundle and, when the panel has it, the
 * node kit. It is one line on purpose: ssh may ask for a password, or whether to trust the key of
 * the server, and that prompt would swallow a second line pasted with the first.
 */
export function copyCommand(arch: string, withKit = true): string {
  const files = withKit ? `${kitFile(arch)} ${BUNDLE_FILE}` : BUNDLE_FILE;
  return `ssh root@<SERVER> mkdir -p ${SERVER_DIR} && scp ${files} root@<SERVER>:${SERVER_DIR}/`;
}

/**
 * A path that the panel names in its answer, if it is a path of its own API: it
 * starts with a single slash and /api/. Anything else, another host above all, is
 * not followed.
 */
function apiPath(fromPanel: string | undefined): string | undefined {
  return fromPanel?.startsWith("/api/") === true ? fromPanel : undefined;
}

/** Where an admin downloads the bundle of a node: the path that the panel names, or the one it serves it at. */
export function bundleHref(nodeId: string, fromPanel?: string): string {
  return apiPath(fromPanel) ?? `/api/nodes/${encodeURIComponent(nodeId)}/bundle.tar`;
}

/** Where an admin downloads the node kit of an architecture: the path that the panel names, or the one it serves it at. */
export function kitHref(arch: string, fromPanel?: string): string {
  return apiPath(fromPanel) ?? `/api/node-kit/${encodeURIComponent(arch)}`;
}
