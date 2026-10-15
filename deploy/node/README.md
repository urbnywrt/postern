# Postern node: deployment files

A Postern node runs one container, `postern-agent`: a stock Alpine image with the
`postern-node` binary mounted from `/opt/postern/bin`. The agent creates every other
container (the edge, the proxy engines, the egress helpers) through the Docker socket.
A small POSIX shell launcher starts the binary, counts failed starts and rolls back to
the previous version when a new one does not come up.

| File | What it is |
|---|---|
| `install.sh` | Installs or updates a node: layout, keys, binary, launcher, compose file, reserved ports, start. With `--roll-edge`, asks the agent for a new generation of the edge. |
| `launcher.sh` | The container's entrypoint: runs `bin/current`, rolls back to `bin/previous` after 3 unhealthy starts. |
| `compose.yaml` | The `postern-agent` service. |
| `launcher_test.sh`, `install_test.sh` | Tests for the two scripts (see [Tests](#tests)). |

`install.sh`, `launcher.sh` and `compose.yaml` must stay in one directory: the installer
copies the other two from beside itself.

A node is installed in one of two ways. The usual one is
[one Docker command](#install-with-one-docker-command) from the panel: the container
`postern-agent` then runs the node image (`Dockerfile` here), which lays out `/opt/postern` and
installs its binary there itself. The other, [without a registry](#without-a-registry), copies a
kit and a bundle to the server and runs `install.sh`. Either way the agent runs
`/opt/postern/bin/current` through the launcher, and everything after the two install sections
holds for both.

## Install with one Docker command

The server needs Linux on x86-64 or arm64, root, and Docker Engine without user namespace
remapping (see [Requirements](#requirements)); Compose, bash and the kit are not needed. The panel
needs the node image, `POSTERN_NODE_IMAGE` (an image such as `ghcr.io/<OWNER>/postern-node`, see
[the panel's README](../panel/README.md)): without it the page of the node offers only the ways
[without a registry](#without-a-registry).

1. In the panel, create the node. Its management address may stay empty: the panel then takes the
   address that the node joins from, when that is a public one.
2. On the page of the node, under **Install with one command**, check **Panel address for
   nodes**: the address at which the server reaches the panel. Then **Get the command**.
3. Run the command on the server as root:

   ```sh
   docker run -d --name postern-agent --restart unless-stopped \
     --network host --pid host --read-only --tmpfs /tmp \
     --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /opt/postern:/opt/postern \
     -v /etc/os-release:/host/etc/os-release:ro \
     -e POSTERN_JOIN='https://panel.example.com#<TOKEN>' \
     ghcr.io/<OWNER>/postern-node:<VERSION>
   ```

   Or save the `compose.yaml` of the second tab on the server and run `docker compose up -d` next
   to it: it is the same container.
4. Let the panel's address, and only that, reach the management port that the page shows:
   `ufw allow from <PANEL_IP> to any port <MGMT_PORT> proto tcp`. Or turn on
   [hidden management](#hidden-management), and no port is opened.
5. The node is online in the panel within seconds.

**The token** in `POSTERN_JOIN` lets one server join as this node. It works once, for 24 hours,
and a node has one at a time: getting a new command cancels the one before. Until it is used,
treat the command as a secret. The node makes its private key itself and sends the panel only a
request for a certificate, so the panel never holds the key, and there is no bundle for a node
that joined (its download answers 409).

**The panel address** is `https://host[:port]`, with no path, query, fragment or user name: the
node takes the CA that it trusts from that answer, so nothing on the way may change it. `http://`
works only for a loopback address (`127.0.0.0/8`, `::1`, `localhost`), which is for tests. The node
goes to the panel directly, not through `HTTP_PROXY` or `HTTPS_PROXY`.

**What the container does when it starts** (`postern-node bootstrap`, then the launcher):

- it checks that it runs as root, that Docker answers and does not remap user namespaces, and
  that `/opt/postern` (`POSTERN_HOME`) is mounted at the same path on the host: the agent mounts
  paths of the host into the containers that it starts;
- it lays out `/opt/postern` as `install.sh` does;
- it joins the panel when the node has no keys yet, or when `POSTERN_JOIN` holds another token
  than the one it last joined with (`data/state/join-token.sha256`). A failed join with keys in
  place is a warning, and the node starts with its keys; without keys the container exits, and
  Docker starts it again;
- it copies the binary of the image to `bin/postern-node-<version>` and makes it `bin/current`
  when there is none or the image is newer. An older image changes nothing: the node has updated
  itself past it ([Self-update](#self-update-updateself));
- it reserves the ports 20000-40999 and sets `net.ipv4.tcp_migrate_req=1`, as `install.sh` does,
  through a privileged one-shot container `postern-sysctl-<hex>` on the runner image, and writes
  `/etc/sysctl.d/90-postern.conf`. It does so at every start; a failure is only a warning;
- it starts the agent with `bin/launcher.sh agent`.

So `docker restart postern-agent` is safe and does not join again: for a node of the Docker
command it takes the place of running `install.sh` again.

**Joining again** (a new server for the node, a lost `/opt/postern/pki`): get a new command on the
page of the node, then on the server run `docker rm -f postern-agent` and the new command. The
node keeps its id, its proxies and their links, and gets a new key. The edge and the engines keep
serving while the agent is away.

**Moving a node installed with the kit to Docker:** stop its agent with
`docker compose -f /opt/postern/compose.yaml down`, then run the command of the same node from the
panel (with a new token). `/opt/postern` stays: the node joins with a new key and goes on with its
state, its edge and its engines.

**Install over SSH** ([below](#from-the-panel-over-ssh)) runs this same command when the panel has
a node image and the wizard knows the panel address: it gets a token, sets up Docker when you let
it, removes an old `postern-agent` container and waits for the node to come online.

**Uninstall** as in [Uninstall](#uninstall), with `docker rm -f postern-agent` in place of
`docker compose ... down`, and the node image among the images to remove.

## Requirements

These are those of `install.sh`. The [Docker command](#install-with-one-docker-command) needs the
same but Compose, and reserves the ports itself.

- Linux on x86-64 or arm64, and root.
- Docker Engine with the Compose v2 plugin (`docker compose version` works). The script does
  not install Docker. On Debian and Ubuntu: `apt-get install -y docker.io docker-compose-v2`.
- Docker without user namespace remapping. When `userns-remap` is on, the installer refuses:
  the edge generations must share their ports (`SO_REUSEPORT`) under one UID. Remove
  `userns-remap` from `/etc/docker/daemon.json` and restart Docker. That changes the file
  ownership seen by every container on the host, so do it deliberately.
- The runner image `alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`.
  Docker pulls it on the first start; on a host without registry access load it first with
  `docker load`.
- The loopback ports 20000-40999 reserved in `net.ipv4.ip_local_reserved_ports`. The script
  does that (see [The loopback ports](#the-loopback-ports)).

## Without a registry

Without a node image in a registry, a node is installed from its bundle, which the panel makes
when the node is created, and a `postern-node` binary with the three files of this directory. There are two ways to get those:
the node kit that the panel serves, which is the usual one, and a release download. The panel
can also do the steps of the node kit by itself, over SSH.

### From the panel, over SSH

On the page of the node, **Install over SSH** asks for the server (host, SSH port, user) and a
password or a private key. The user is `root`, or a user with passwordless sudo (`NOPASSWD`); the
server needs bash 4 or newer. When the panel has a node image, the install runs the
[Docker command](#install-with-one-docker-command) instead, and the server needs neither bash 4
nor Compose nor the kit; the steps below are those of the kit.

1. The first time, the panel shows the SHA-256 fingerprint of the server's host key and sends no
   credentials until you have compared it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
   on the server and confirmed it. The panel keeps the confirmed key with the node, and refuses a
   server that later presents another one, showing both, until you trust the new key.
2. The panel checks the server and shows what it found: the system and its architecture, Docker
   and Compose, userns-remap, the free space on `/opt`, the listening ports and who holds them,
   the public addresses and the clock. It refuses to install when
   the panel has no node kit for the architecture, when Docker remaps user namespaces, or when port
   443 or the management port is held by something that is not Postern. The panel sets up Docker
   only when you tick **Let the panel set up Docker**, and never replaces an engine that is
   installed: it starts a Docker that does not answer, and gives it some 20 seconds to answer, or
   adds the Compose v2 plugin of the packages that the engine comes from (`docker-compose-plugin`
   for docker-ce with apt, dnf or yum, `docker-compose-v2` for docker.io of Ubuntu,
   `docker-cli-compose` on Alpine; for docker.io of Debian, or docker-ce with zypper or pacman,
   install Compose v2 by hand). Only where Docker is not installed does it install it: with the
   script of get.docker.com, or the packages of the distribution when that fails. apt waits up to
   2 minutes for the lock of dpkg that another apt holds.
3. The install copies the node kit and the bundle to `/root/postern-install`, also through sudo,
   which runs every command as root (a directory there that root does not own is refused; a bundle
   that an earlier install left there is removed). It runs `install.sh` there under a wrapper that
   removes the bundle when `install.sh` ends, also when the install is cancelled, and the panel
   checks that the bundle is gone; when it is not, the job fails, or ends as cancelled, and says so
   in its error. Then the install waits up to 3 minutes for the node to come online. Its log is
   shown as it runs. Installing again is safe.

The credentials are used for that install only, unless you tick **Keep the credentials,
sealed**: the panel then keeps them sealed with its master key. Open the management port to the
panel in the firewall as in step 5 below; the install waits for the panel to reach it.

### From the panel: the node kit

The panel image carries a node kit for each architecture: `postern-node` of the panel's own
version, built for `linux/amd64` or `linux/arm64`, with `install.sh`, `launcher.sh` and
`compose.yaml`. So the node needs no release host, and runs the version of the panel. The page of
the node in the panel shows these steps, with the commands for the architecture that you pick.
Build a panel image that nodes are installed from with `--build-arg VERSION=<version>` (see
`deploy/panel/Dockerfile`): the script installs the binary under the version that it prints, and
the binary of a build without it says `dev`, which can be installed only once on a host, since
an installed version is never replaced.

1. In the panel, create the node and download `postern-node-bundle.tar`. It holds the node's
   private key, so treat it as a secret and do not paste it into a shell.
2. Download the node kit for the server's architecture (`uname -m`: `x86_64` is amd64, `aarch64`
   is arm64): `postern-node-kit-linux-amd64.tar` or `postern-node-kit-linux-arm64.tar`.
3. Copy both into one directory on the server, with one command line: it makes the directory,
   and copies the files only when that worked. Keep it on one line: when `ssh` stops to ask for a
   password, or whether to trust the key of the server, it takes the next line that was pasted
   with it as the answer, and the files would never be copied.

   ```sh
   ssh root@<SERVER> mkdir -p /root/postern && scp postern-node-kit-linux-<ARCH>.tar postern-node-bundle.tar root@<SERVER>:/root/postern/
   ```

4. On the server, unpack the kit and install from it:

   ```sh
   cd /root/postern
   tar -xf postern-node-kit-linux-<ARCH>.tar && sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node
   ```

5. The script prints the management port. Let the panel's address, and only that, reach it:

   ```sh
   ufw allow from <PANEL_IP> to any port <MGMT_PORT> proto tcp
   ```

6. The node goes online in the panel. Delete the bundle: `rm postern-node-bundle.tar`.

The kit is a plain tar of four files at its top level: `postern-node`, `install.sh`, `launcher.sh`
and `compose.yaml`, owned by root, without directories. Its binary runs as root on the node, so
download the kit, like the bundle, only over a connection that nobody can change: the panel
behind HTTPS, or an SSH tunnel to it (see the warning in [the panel's README](../panel/README.md)).

A panel that does not run from its Docker image (`go run`, or a binary built by hand) has no kit,
unless one is laid out for it (see `POSTERN_NODE_KIT_DIR` in the panel's README); its node page
then says which version of `postern-node` to use. Put such a binary next to the three files of
this directory and install with `--binary`, as in step 4 without the `tar`.

### From a release

Copy the bundle, `install.sh`, `launcher.sh` and `compose.yaml` into one directory on the server
(one command line, as in step 3 above), and let the script download the binary of a release (see
[Release downloads](#release-downloads)):

```sh
ssh root@<SERVER> mkdir -p /root/postern && scp install.sh launcher.sh compose.yaml postern-node-bundle.tar root@<SERVER>:/root/postern/
```

```sh
cd /root/postern
sudo POSTERN_RELEASE_BASE=https://git.example.com/<OWNER>/postern/releases/download \
  bash install.sh --bundle postern-node-bundle.tar --version v1.2.3
```

Or install a binary that you already have (built, or verified with minisign):
`sudo bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node`. Then open the
management port to the panel and delete the bundle, as in steps 5 and 6 above.

### What the script checks

The script checks everything it can before it changes anything: arguments, root, Docker and
Compose, userns-remap, the bundle (exactly the four files of a version 1 bundle, each at most
64 KiB, a node id of 26 characters `0-9A-Z`, a port from 1 to 65535) and the binary (it must run
on this host; its `version` output names it). The bundle is never unpacked: the content of
each file is copied out, so the archive cannot choose paths, modes or owners, and only as far
as 64 KiB and one byte, so a member of any size cannot fill the disk.

`--binary <path>` without `--version` names the file after the version the binary prints
(`postern-node version`). `--version <v>` together with `--binary` names it `<v>` without
downloading. With neither option the installed binary is kept, which is how to refresh the
bundle or the launcher alone.

### The loopback ports

The node's own services listen on the loopback, on ports from 20000 to 40999: the engines and
their APIs, the SOCKS ports of the edge and of the egress helpers, and the service listeners.
The kernel must not give one of those ports to an outgoing connection as its local port, which
it does by default with the ports from 32768 to 60999: an engine whose port is held by such a
connection cannot start. So the script reserves them. It writes
`/etc/sysctl.d/90-postern.conf` with

```text
net.ipv4.ip_local_reserved_ports = 20000-40999
```

and sets the same list in the running kernel at once, with
`sysctl -w net.ipv4.ip_local_reserved_ports=<the list>`: that one setting, from no file (not
`sysctl --system`, which would load every setting of the host again). The file is for the next
boots. A reserved port is still free for a program that names it, so the node's services bind
theirs as before; the kernel only leaves it out when it picks a port by itself.

Ports that are reserved already when the script runs, by other software or by hand, stay
reserved: the file holds them together with 20000-40999 (`8080,20000-40999`, for example). A
later change of those other reservations is not followed: run the script again after one, or
edit the file. A file of `/etc/sysctl.d` whose name sorts after `90-postern.conf` and that sets
the same key replaces the list at boot.

None of this stops the install. When the list cannot be read, is not a list of ports, the file
cannot be written (a read-only `/etc/sysctl.d`, for example), or the setting cannot be made, the
script says so in a warning, goes on, and starts the agent: the node works without the
reservation, with the risk above. If only the file cannot be written, the ports are reserved
until the next reboot; if only the setting cannot be made, they are reserved from the next boot
on. To check: `sysctl net.ipv4.ip_local_reserved_ports` has to cover 20000-40999.

### A safe edge handoff

An edge roll starts a new generation beside the running one and drains the old one: the old
one closes its listeners and keeps the connections it accepted. Connections that the kernel
has not handed to the old edge yet (its accept queue) and half-open handshakes are aborted,
unless `net.ipv4.tcp_migrate_req = 1` moves them to the new generation's listener of the same
`SO_REUSEPORT` group (Linux 5.14 or later; the default is 0). So the script writes, into the
same `/etc/sysctl.d/90-postern.conf`,

```text
net.ipv4.tcp_migrate_req = 1
```

and sets it at once with `sysctl -w net.ipv4.tcp_migrate_req=1`. A kernel without the key
(before 5.14) is a warning; the install goes on, and an edge roll on that node may abort the
connections waiting to be accepted at that moment. The agent reads
`/proc/sys/net/ipv4/tcp_migrate_req` at its start: when it is not 1, `GetInfo.warnings` holds
`edge-handoff-unsafe` and the agent records the event `edge_handoff_unsafe` once per start.

**Nodes installed before this setting** have to run `install.sh` once more (the same command;
it keeps the node's identity and state) to get it.

### Release downloads

`--version <v>` downloads `<v>` (the release tag, `v1.2.3`) from the base URL in
`POSTERN_RELEASE_BASE`:

```text
<POSTERN_RELEASE_BASE>/<v>/postern-node-linux-amd64      (or -arm64, from uname -m)
<POSTERN_RELEASE_BASE>/<v>/SHA256SUMS
<POSTERN_RELEASE_BASE>/<v>/postern-node-linux-amd64.minisig   (the signature, kept)
```

The signature is kept beside the binary as `bin/.postern-node-<v>.minisig` (0644), where
`UpdateSelf` keeps one, once its trusted comment reads `postern postern-node <v> linux/<arch>`;
a signature that names another version or architecture stops the install. The script does not
verify the key (it has no minisign); the agent does, with its release keys, before it rolls the
edge to a version that it does not run itself (Edge update below). A release without the
signature installs with a warning, and its edge can then run it only while the agent runs it.
With `--binary <path>`, a signature at `<path>.minisig` is checked and kept the same way. A
re-run keeps the signature again, and a re-run of `--version` for a release that is installed
without one fetches it (nodes installed by an older `install.sh`).

The file must match its line in `SHA256SUMS`. That catches a broken or partial download, but
the checksum file comes from the same host as the binary, so it does not protect against a
compromised release host. When that matters, verify the release signature (minisign) yourself
and install with `--binary`. The script has no built-in base URL; without `POSTERN_RELEASE_BASE`
`--version` stops with a message.

`POSTERN_RELEASE_BASE` has to start with `https://`, or with `file://` for a mirror on the
host itself. Anything else, `http://` first of all, is refused before anything is downloaded:
the binary runs as root, so it is never taken over a connection that is not encrypted. The
download takes `curl`, which is told to take https and file URLs only, and to follow a redirect
over https only. Without `curl` the script stops: install `curl`, or install the `postern-node`
binary of the panel's node kit with `--binary` (see
[From the panel](#from-the-panel-the-node-kit)). `wget` is not used, because it cannot be kept
from following a redirect from https to http. A base may carry a user name and a password
(`https://<USER>:<PASSWORD>@...`); the messages of the script leave them out of every URL that
they show.

### Running it again

The script is safe to repeat; the same arguments change nothing except that the agent is
recreated (`docker compose up -d --force-recreate`), which is how the agent picks up a new binary
or bundle. Only the management agent restarts: the edge and the engines are separate containers
and keep serving. **Running the script again does not roll the edge**: the edge keeps the binary
that it was started with until a new generation of it starts, which `install.sh --roll-edge`
asks for (see [Rolling the edge](#rolling-the-edge)).

- A new binary (another version) becomes `bin/current`, and what `bin/current` pointed to becomes
  `bin/previous`. The same version again changes neither. The agent runs the new binary at once,
  the edge after `--roll-edge`.
- A version file is never replaced: installing different content under a version that is
  installed already is refused, because `bin/current` or `bin/previous` may be running it.
- `launcher.sh` and `compose.yaml` are overwritten with the shipped versions. Local edits to them
  are lost.

### Rolling the edge

The edge is a container of its own, `postern-edge-g<N>` (generation N), and runs the binary that
was `bin/current` when the agent started it. An update of the binary recreates the agent, not the
edge: the edge keeps running the old binary until a new generation of it starts, and the panel
shows the version of the edge that runs. After an update of the binary, move the edge to it:

```sh
sudo bash install.sh --roll-edge
```

A node installed with the Docker command has no `install.sh` on the host: press **Roll edge** in
the versions card of the node's page in the panel, or write the file by hand:

```sh
sudo sh -c 'umask 077; date +%s > /opt/postern/data/run/roll-edge'
```

That writes `data/run/roll-edge` (see [Asking for an edge roll](#asking-for-an-edge-roll)) and
changes nothing else; it needs neither the bundle nor a binary. On its next pass, within about 30
seconds, the agent starts generation N+1 beside generation N, on the same ports, and only then
tells generation N to drain: it stops taking connections and keeps those it has until they end,
for up to an hour, and is then removed. One kind of connection can still be lost: a connection
that is waiting in the accept backlog of generation N when it stops listening (its handshake is
done, but the edge has not accepted it yet) may be reset, unless the kernel moves it to
generation N+1, which it does when `net.ipv4.tcp_migrate_req` is 1 (Linux 5.14 and later; the
default is 0, and Postern does not change it). The client connects again.
`docker logs -f postern-agent` shows the roll. If the edge does not roll, see
[Asking for an edge roll](#asking-for-an-edge-roll).

Without the script, the edge that runs can be stopped by hand, but only when the node shows no
last error in the panel (**Last error** on the page of the node is empty). A port that another
process holds would leave the node without an edge: the agent could not start generation N+1 on
it, and generation N would be gone. `--roll-edge` keeps generation N in that case, because it
drains N only when N+1 is up. With no last error:

```sh
docker stop postern-edge-g<N>
```

The agent finds no edge running and starts generation N+1 on its next pass, within about 30
seconds. Until then nothing listens on the edge's ports, and the stop itself waits up to 30
seconds for the open connections: count on up to about a minute of refused connections.

### Node identity and state

`data/state/node-id` holds the id of the node the state belongs to. When the bundle's id differs
from it, or the state directory has contents and no id file, the state directory is moved aside
to `data/state.bak-<unix time>` (the running agent is stopped first), and a fresh one is started
with the new id. Without that, a node installed again under a new identity would report the old
desired generation and the panel's generation 1 would be refused as stale. The panel sends the
desired state again when the node connects. Backups are never deleted by Postern.

The agent checks the same file when it starts: when it names another node than `pki/bundle.json`
the agent refuses to start (run `install.sh` with the bundle again), and when it is missing the
agent writes it. Its record buffer, `data/stats.db`, carries the node id too; a buffer of another
node is deleted, so that its records never reach the panel as this node's.

## The agent

`postern-node agent` is what the container runs (`launcher.sh agent`). It reads the bundle from
`pki/`, serves the panel over gRPC with mutual TLS (TLS 1.3, only the panel's client certificate),
runs the reconciler that keeps the edge, the engines and the egresses in line with the desired state, and keeps
seven days of records (state reports, minutes of statistics, events, results of its own checks) in `data/stats.db` for the
panel to read after a disconnection. It also checks itself all the time and keeps client addresses only as the IP policy of the panel allows (see [statistics, privacy and diagnostics](../../docs/diagnostics.md)).

| Variable | Default | Meaning |
|---|---|---|
| `POSTERN_HOME` | `/opt/postern` | the node's directory (compose sets it) |
| `POSTERN_MGMT_LISTEN` | `0.0.0.0:<mgmt_port of the bundle>` | address of the management listener |

`GetInfo` reads the host's `/etc/os-release` (compose mounts it at `/host/etc/os-release`), the
public addresses of the host's interfaces (when there is none, it asks the public "what is my
address" services that the edge also uses, over IPv4, with short timeouts), and the owners of the
listening ports from `/proc` (the container runs with `pid: host`; a process whose descriptors
it may not read is reported as `unknown`, unless the port is one of the agent's own containers).

### Hidden management

By default the panel reaches the agent on a port of its own (mode `port`): `<MGMT_PORT>`, mutual
TLS, open to the panel's address in the firewall. A scanner finds that port and sees a TLS server
that wants a client certificate. In mode `hidden` the node has no such port. The panel connects
to the public port of one of the node's `tls` listeners with a **management SNI** that only the
panel knows; the edge routes that name, as raw TCP with a PROXY v2 header, to a hidden listener
of the agent on `127.0.0.1`, which reads the header and then does the same mutual TLS. Every
other name goes where it went before, and a scanner sees an ordinary proxy port with its mask.

Switch it on the node's page, **Management of the node** (mode, SNI, public port). The SNI is a
plausible host name that is not a domain of the node's proxies or of its domain pool (nobody
needs to resolve it); the port is a `tls` listener of the node. The panel opens the hidden
listener first, checks that it can reach the agent through the public port, and only then moves
over and has the node close `<MGMT_PORT>`; a check that fails puts the old settings back. Switching
back to `port` runs the same steps the other way. You can drop the firewall rule for
`<MGMT_PORT>` once the node is hidden.

Failsafe: if the hidden path delivers no authenticated request for 15 minutes while the plain
port is closed, the agent opens the plain port again and records the event `mgmt.fallback`
(a broken hidden path must not strand the node). The edge needs a running `tls` listener, so a
node with none has to stay in mode `port`.

### Egresses

The edge goes out directly, through an interface or through a SOCKS5 or HTTP proxy by itself.
The other egresses run in containers of their own, `postern-egr-<id>-g<N>`: Xray for a share
link (XRAY_URI), a subscription (XRAY_SUBSCRIPTION) and WARP, warp-plus for Psiphon. The agent
starts one for every egress that a chain in use takes (the chain of an enabled proxy, its scope
chains, the node's default chain), with a SOCKS5 port on `127.0.0.1` (35000-39999) per server,
and gives the edge those ports as the members of the chains. A change of what an egress runs
makes a new generation beside the old one; the old one is removed two minutes after the edge
has the new ports.

- A subscription is fetched when its egress needs it, when the panel asks for a refresh, and
  then every six hours: by the node itself first, then through the first three members of the
  node's default chain that are up, 15 s each and a minute in all; a newer desired state cuts
  a fetch short. The last one that could be read stays in
  `data/instances/egr-<id>/subscription.txt` and is used while a fetch fails, which is tried
  again ten minutes later. An egress has 64 members at most, those the provider can take.
- A WARP egress registers a device with Cloudflare once and keeps its account in
  `data/state/egress/<id>/warp-account.json`, which no container mounts. Once no chain in use
  takes the egress and its last generation has drained, the device is deleted, and then the
  account. A deletion that fails keeps the account and is tried again, a minute later and then
  twice as late each time, six hours apart at the most; Cloudflare saying that the device is gone
  already counts as deleted. After a week of failures, or at once for an account that cannot be
  read, the agent gives up with the warning event `egress_warp_device_kept`, which names the
  egress: the account then stays, for deleting the device by hand.
- warp-plus (Psiphon) keeps its cache in `data/instances/egr-<id>/cache-g<N>`, one per
  generation: a new generation gets a copy of the canonical cache, the symlink `cache`, and once
  the generation before it is removed its own cache becomes the canonical one. No two warp-plus
  processes share a cache; the canonical one outlives the generations.
- The agent reads the addresses of Telegram's middle proxies (`getProxyConfig`,
  `getProxyConfigV6`) at its start and every six hours, keeps the last good list in
  `data/state/me-addrs.json`, and gives it to the edge: telemt does not tag its connections to
  the middle proxies, so the edge tells them by their address and port (some are on the
  address of a datacenter, at port 8888) and sends them through the scope chain `me` of the
  proxy. While the node knows no middle proxy, a list that failed is fetched again a minute
  later, otherwise fifteen.
- A proxy that uses the middle proxy presents the exit address of that chain (the first member
  that is up) as its NAT address. A chain of direct members without an interface goes out from
  the node itself: until its exit address is known, the engine keeps the NAT address it has, or
  takes the public address of the chain's first member or of the node; a chain through a proxy,
  a provider or an interface waits for its exit address. An engine without a NAT address takes
  the exit address as soon as it is known; one with an address takes a new exit address once
  two health checks in a row report it, once in ten minutes at the most (a limit that the
  agent keeps in memory: it starts afresh when the agent starts).
- A new engine generation gets the route only once its way out works: a datacenter answers
  through its SOCKS port, the proxy secret comes through it when the proxy uses the middle
  proxy, and an L2 probe through the edge's test listener reaches a datacenter.
- The server of a share link or a subscription may be a host name, which the provider
  resolves itself, on the host network, and which may resolve to anything: a name that points
  at the loopback or at a cloud metadata service is not refused (only such addresses written
  as literals are). The edge's policy of destinations (no loopback, private, link-local or
  metadata addresses) applies to what the engines ask for, not to where a provider connects.

### Asking for an edge roll

A file asks the agent for a new generation of the edge (see [Rolling the edge](#rolling-the-edge)):

| | |
|---|---|
| Path | `$POSTERN_HOME/data/run/roll-edge`, root's, mode 0600 |
| Writer | `install.sh --roll-edge`, the panel's **Roll edge**, or by hand: `sudo sh -c 'umask 077; date +%s > /opt/postern/data/run/roll-edge'` |
| Content | the time of the request, in Unix seconds |
| Reader | the agent: on its next pass it takes the request, which deletes the file at once, then starts edge generation N+1 beside generation N, with the binary of `bin/current`, and lets generation N drain |

The file is deleted when the agent takes the request, before generation N+1 starts, and nothing
remembers the request after that. If the agent stops, or the pass fails, before N+1 is up, no
roll happens and nothing is left to try it again; `docker logs postern-agent` says why. A minute
after `--roll-edge`, `docker ps` should list generation N+1 of the edge (`postern-edge-g<N+1>`).
The panel marks an edge that runs another version than the agent as **Outdated**, and it asks
the node again about every five minutes, so the mark can outlive the roll by that long. When
the new generation is not running a minute after the request, or the panel still shows
**Outdated** after five minutes, run `--roll-edge` again (once the cause is mended, if the log
names one).

## Layout

```text
/opt/postern/
  compose.yaml                 0644  the postern-agent service
  bin/                         0755
    launcher.sh                0755  the container's entrypoint
    postern-node-<version>     0755  one file per installed version
    current  -> postern-node-<version>     relative symlinks: the edge and the engines
    previous -> postern-node-<version>     see the volume under other paths
  pki/                         0700  keys of the node
    ca.pem  node.pem  node-key.pem  bundle.json    0600
  data/                        0700  everything below is root only unless noted
    state/                     0700  desired.json, desired.prev.json, runtime.json, node-id,
                                     me-addrs.json, egress/<id>/warp-account.json
    edge/  run/  instances/  certs/
    instances/egr-<id>/        0700  subscription.txt, g<N>/ (a generation), cache-g<N>/ and
                                     cache -> cache-g<N> (warp-plus)
    run/launcher/              launcher bookkeeping, see below
    run/roll-edge              0600  an edge roll that was asked for, see above
    artifacts/                 0755  verified engine binaries
    stats.db                   0600  the agent's buffer of records for the panel (7 days)
    geoip/                     0700  the country database the panel sent (<sha256>.mmdb, current and previous)
```

## The launcher and the healthy marker

`launcher.sh <args>` replaces itself with `$POSTERN_HOME/bin/current <args>` (`POSTERN_HOME`
defaults to `/opt/postern`), so no shell is left in between: the binary is the container's main
process and gets Docker's signals directly. Before that it judges the previous start:

- A start is healthy when the binary wrote the marker file (below). At every start the launcher
  deletes the marker, so a marker that is there at the next start was written by the process
  that ran in between.
- The previous start did not write it: the counter of unhealthy starts goes up. It did: the counter
  goes back to zero. When `bin/current` points elsewhere than at the previous start (an update, a
  switch by hand), the counter starts over, so a new version is not blamed for the old one's
  failures.
- With 3 unhealthy starts in a row and a usable `bin/previous` (an executable file),
  `bin/current` is pointed at it in one atomic rename, `bin/previous` is removed (the failed
  version is never picked again), the counter is reset and the launcher logs what it did to
  stderr (`docker logs postern-agent`). Without a usable `bin/previous` it logs why and starts
  `bin/current` again.
- A `bin/current` that is missing or not executable is an unhealthy start (exit status 127), so a
  half-finished update is rolled back like a crashing one.
- Bookkeeping never stops the binary from starting: if a file cannot be written the launcher
  warns and goes on.

### Marker contract (what the agent must do)

| | |
|---|---|
| Path | `$POSTERN_HOME/data/run/launcher/healthy` |
| Writer | the `postern-node agent` process, never the launcher |
| When | once, after all of: the gRPC server is serving, the desired state is loaded, and the first reconcile pass has run without a failure of the agent's own. Not after a fixed delay of being alive. A pass that fails because the agent cannot do its work (Docker unreachable, the edge not answering or not coming up) does not count. A pass that fails because its desired state is refused (the state does not validate, or the edge refuses the configuration, a listener it cannot bind for one) counts: the agent works, the panel has to change the state, and the reason is in the state report (`last_error`). |
| Content | irrelevant; the agent writes its version |

The rest of the directory belongs to the launcher:

| File | Content |
|---|---|
| `started` | `<unix time> <binary name>`, written before every start |
| `crashes` | the counter of unhealthy starts, as of the latest start |
| `rollback` | `<unix time> <from> <to>`, left after a rollback. The agent reports it to the panel as an `agent_rolled_back` event, logs it as a warning and deletes it. |

Do not run one-off commands through the launcher: that counts as a start and deletes the
marker of the running agent. Use `docker exec postern-agent /opt/postern/bin/current <command>`.

### Self-update (UpdateSelf)

The panel updates the agent by sending it a signed release binary (`UpdateSelf`, capability
`update-self`). The agent checks its size and SHA-256, the minisign signature by a release key
compiled into the running binary and its trusted comment (`postern postern-node <version>
linux/<arch>`), that it is a static ELF for the node's architecture, and that
`<file> version` prints `<version> (`. It then installs it as `bin/postern-node-<version>`
(0755), points `bin/previous` at what `bin/current` pointed to and `bin/current` at the new file
(relative links, each made beside and renamed over), answers `restarting`, stops as for
SIGTERM and exits with code 75. Docker (`restart: unless-stopped`) starts the launcher again,
which starts the new `bin/current`. A build without a release key installs nothing ("this node
build trusts no release key"). Only the binary is replaced: `launcher.sh` and `compose.yaml`
change only with `install.sh`.

- **A downgrade is only the rollback to `bin/previous`.** A version older than the running one
  is refused unless the request is an explicit rollback and the version is the one `bin/previous`
  points to. A version that is installed already with other content is refused.
- **Healthy, not just answering.** `GetInfo.healthy` is true once the running process wrote its
  marker. The panel's node update succeeds only when the node answers `healthy` with
  `agent_version` = the target. An agent that has not written its marker 10 minutes after its
  start logs why and exits with code 1, so that the launcher counts the start as unhealthy.
- **What the launcher cannot catch.** The launcher's counter resets whenever the previous start
  wrote the marker, so a binary that writes the marker and crashes later is never rolled back
  by the launcher. The panel's node update fails such a step instead: an agent restart during
  the step or its pause fails it, and the panel reverts it.
- **Old binaries.** At the start and after every `UpdateSelf` the agent removes old
  `bin/postern-node-*` files while more than 3 versions remain, oldest first. It never removes
  the targets of `bin/current` and `bin/previous`, its own executable, or a binary that a
  container labelled `postern.managed=true` mounts (an edge keeps the binary it was started
  with). When Docker cannot be asked, nothing is removed.
- **Docker down is not the binary's fault.** When the marker is still missing at the 10-minute
  deadline and Docker does not answer either, the agent logs it and waits another 10 minutes
  instead of exiting: a good binary is not rolled back because the daemon was away.

### Edge update (UpdateEdge)

`UpdateEdge(<version>)` (capability `update-edge`) rolls the edge to an agent binary that is
installed already, `bin/postern-node-<version>`, verified as `UpdateSelf` verifies one: a
regular executable file (not a link), signed by a release key of the running agent (`UpdateSelf`
keeps the signature beside the binary as `bin/.postern-node-<version>.minisig`, and so does
`install.sh`) unless it is the running agent's own binary, a static ELF for the node, and its
`version` prints `<version> (`. A binary without a kept signature that the agent does not run
(one installed by an older `install.sh`, or from a release or `--binary` without a signature)
is refused: update the agent and the edge to it together. GetInfo
reports the versions with a kept signature (`binaries.signed_versions`), and the panel plans
no edge-only roll to another version. A version older than the running edge's is refused unless
the request is a rollback (`rollback`), and a rollback goes only to the version the edge ran
before its last roll (`edge_previous_binary` of the runtime record). The reconciler hashes the
file again right before the edge mounts it. An edge that runs that version already and answers
is not rolled. Otherwise a new generation starts on that
binary beside the running one, exactly as for `--roll-edge`: it takes over only when it answers
and binds every listener the running one binds, and the running one drains. The call answers,
within 120 s, with the new generation once it answers with `<version>`; a roll that fails
removes the new generation, leaves the old one serving and is answered `Aborted` with the
reason (event `edge_roll_failed`). One call at a time: a second one is `Unavailable`.

The runtime record (`data/state/runtime.json`, `edge_binaries`) keeps the binary of every edge
generation. A generation that the agent makes for another reason (the old one crashed, it
needs other capabilities) runs the binary of the generation it replaces, or the agent's own
when that file is gone; `--roll-edge` and the panel's edge roll nonce use the agent's own
binary.

The record is saved as soon as a new generation's container exists. An agent that is killed in
the middle of a roll finds both generations at its next start: the newer one takes over only
when it answers and binds every listener the one in the record binds (the same rule as a roll);
otherwise it is removed, and the old one serves on.

## Uninstall

Stop the agent only. The edge and the engines keep serving, and come back after a reboot:

```sh
docker compose -f /opt/postern/compose.yaml down    # installed with the kit
docker rm -f postern-agent                          # installed with the Docker command
```

Remove everything Postern created on the host: the agent, the edge, every engine and egress
container. **This stops all proxies on the node.**

```sh
docker ps -aq --filter label=postern.managed=true | xargs -r docker rm -f
rm -rf /opt/postern    # the node's key, its state, its statistics and the state backups
docker image rm alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
docker image rm ghcr.io/<OWNER>/postern-node:<VERSION>    # the image of the Docker command, if any
rm /etc/sysctl.d/90-postern.conf    # the reserved ports, from the next boot on
```

Delete the node in the panel and remove the firewall rule for the management port.

## Tests

From the repository root (the tests run on Linux; from Windows use `bash scripts/wsl '<command>'`):

```sh
sh deploy/node/launcher_test.sh        # the launcher, under the system's sh
bash deploy/node/install_test.sh       # the installer, against a fake root with a fake docker and sysctl
```

The installer reads the bundle with the tar of the host, which is busybox tar on Alpine and
other small systems. `install_test.sh` checks that too: with a stand-in that refuses the options
busybox tar does not know, and with busybox tar of the runner image when the Docker daemon has
that image (the test does not pull it).

The launcher is written for the busybox `ash` of the runner image. To run its tests there:

```sh
docker run --rm -v "$PWD":/src:ro \
  alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
  sh /src/deploy/node/launcher_test.sh
```

`POSTERN_TEST_SHELL=bash sh deploy/node/launcher_test.sh` runs the launcher under another shell.
The install tests use `POSTERN_HOME` to point at a temporary directory; do not set it for a real
install, because `compose.yaml` mounts `/opt/postern`.
