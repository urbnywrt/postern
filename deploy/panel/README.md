# Postern panel: deployment files

The panel is one container, `postern-panel`: the `postern-panel` binary with the admin UI
embedded in it, on the runner image that every Postern container uses. It keeps a SQLite
database in `/data` and its master key in `/keys`, and listens on port 8080. The image also
carries the [node kit](#the-node-kit): the node binaries of its own version for amd64 and arm64,
with the installer of `deploy/node`, which the panel serves for the manual install of nodes.

| File | What it is |
|---|---|
| `Dockerfile` | Three stages: the web UI (`node:24-alpine`), the binaries (`golang:1.27-alpine`: the panel, and `postern-node` for `linux/amd64` and `linux/arm64`), and the image (the runner image plus `su-exec`). With `--build-arg PREBUILT=dist` it builds nothing and takes the signed binaries of a release instead (see [The image of a release](#the-image-of-a-release)). |
| `compose.yaml` | The `postern-panel` service, with `./data` and `./keys` as its volumes. |
| `entrypoint.sh` | The entrypoint. Runs as root only to make `/data` and `/keys` belong to the panel's user, then drops root. |
| `launcher.sh` | Starts the panel and rolls back to the previous binary after 3 unhealthy starts. Same contract as the node launcher. |
| `launcher_test.sh`, `entrypoint_test.sh`, `compose_test.sh` | Tests for the two scripts, and for the port that `compose.yaml` publishes (see [Tests](#tests)). |

## Run it

From this directory, on a host with Docker and the Compose v2 plugin:

```sh
docker compose up -d --build
docker compose logs postern-panel
```

The first start prints the URL of the setup page, once, and does not log it:

```text
postern-panel: the panel has no admin yet. Open this URL within an hour to create the first one;
it works once, and a restart makes a new one:

  http://localhost:8080/setup?token=...
```

`localhost:8080` is the address inside the container. Open the URL with the address and the
port of the host instead (`http://<SERVER_IP>:8080/setup?token=...`, or the port in
`POSTERN_PORT`), but read the warning below first. The token is good for an hour and until the
first admin exists; to get a new one, restart the panel (`docker compose restart postern-panel`).
Setup asks for a user name and a password of at least 12 characters; TOTP can be switched on
afterwards, in the settings.

> **Warning: the panel serves plain HTTP.** Whatever goes to it over the network can be read, and
> changed, by anybody on the way: the **setup token** (it is in the URL above), the **admin
> password** (typed on the setup page and at every sign-in) and the **session cookie** (marked
> `Secure` only when a TLS proxy in `POSTERN_TRUSTED_PROXIES` says that the request came over
> HTTPS). By default `compose.yaml` publishes the port on every interface of the host, IPv4 and
> IPv6, so on a server on the Internet all three are open to the world. Do not make the first
> admin that way. Use one of these:
>
> - a **reverse proxy with TLS** (Caddy or nginx) in front of the panel, see
>   [Behind a reverse proxy](#behind-a-reverse-proxy);
> - an **SSH tunnel**, for the first setup and for every sign-in after it, see
>   [Keeping the port off the network](#keeping-the-port-off-the-network).
>
> With either, publish the port on the loopback only: `POSTERN_BIND=127.0.0.1`.

### Keeping the port off the network

`POSTERN_BIND` is the address of the host that the port is published on: every interface,
IPv4 and IPv6, unless it is set. For a reverse proxy on the same host, or for an SSH tunnel,
publish on the loopback:

```sh
# .env, next to compose.yaml
POSTERN_BIND=127.0.0.1
```

```sh
docker compose up -d
```

The URL of the setup page is in the log as before. From your own computer open a tunnel, and
open the URL as it is printed, with `localhost` in it:

```sh
ssh -N -L 8080:127.0.0.1:8080 <USER>@<SERVER_IP>
# then, in a browser on your computer: http://localhost:8080/setup?token=...
```

Here 8080 is the port of the host, `POSTERN_PORT`. An IPv6 address for `POSTERN_BIND` goes in
brackets: `[::1]`.

## Configuration

The image is configured by environment variables, and their defaults are right for it.

| Variable | Default | What it is |
|---|---|---|
| `POSTERN_DATA` | `/data` | The data directory: the database (`postern.db`), its backups (`backups/`, made before a migration), the releases of the engines and of the egress providers (Xray, warp-plus) that the panel downloads for its nodes (`artifacts/`), the country database (`geoip/`, see below). |
| `POSTERN_KEYS` | `/keys` | The directory of the master key, `master.key`. |
| `POSTERN_LISTEN` | `:8080` | The address to listen on, `host:port`. Leave it, and use `POSTERN_BIND` and `POSTERN_PORT` in `compose.yaml` to choose the address and the port of the host. |
| `POSTERN_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | Comma-separated IP addresses and CIDR prefixes of the reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` are believed, and that the on-demand TLS question `/api/tls/ask` is answered for (the loopback always is). See [Behind a reverse proxy](#behind-a-reverse-proxy). |
| `POSTERN_HEALTHY_FILE` | none | A file that the panel creates once it is serving. `launcher.sh` sets it; leave it alone. |
| `POSTERN_NODE_KIT_DIR` | `/usr/local/share/postern/node-kit` | The directory of the [node kit](#the-node-kit), where the image has it. |
| `POSTERN_NODE_IMAGE` | the image of the build, if any | The Docker image of the node that the one-command install of a node runs, e.g. `ghcr.io/<OWNER>/postern-node`. Without a tag or a digest the panel adds its version as the tag; a `dev` build, or a version that cannot be a tag (such as `1.2.3+build`), then has none and offers no one-command install (the panel warns of the latter as it starts: give the tag). A value that is no image reference stops the panel from starting. An image built with `--build-arg NODE_IMAGE=...` has that as its default. |
| `POSTERN_GEOIP_BASE_URL` | `https://download.db-ip.com/free` | The `http://` or `https://` address of the directory that the [country database](#the-country-database) is downloaded from, for a mirror of it; it must not carry a user name or password. |
| `POSTERN_PUBLIC_PAGE` | on | `off` serves the admin on every host and the [public page](../../docs/diagnostics.md#the-public-page) on none: the way back in when the page was given the name that you reach the panel by. Remove it (and restart) to bring the page back. |

Compose reads five more, all optional: `POSTERN_BIND` (the address of the host that the port is
published on: every interface, IPv4 and IPv6, unless it is set; see
[Keeping the port off the network](#keeping-the-port-off-the-network)), `POSTERN_PORT` (the port
on the host, 8080), `POSTERN_IMAGE` (an image that was built or pulled elsewhere) and
`POSTERN_TRUSTED_PROXIES` and `POSTERN_NODE_IMAGE` (both passed on to the container; empty means the
default).

An empty variable is the same as one that is not set.

## The two volumes and the master key

- `/data` holds the database, which has password hashes and every secret **sealed** with the
  master key: the CA that the nodes trust, the private keys of the nodes, the secrets of the
  proxies, the TOTP secrets.
- `/keys` holds `master.key`, 32 random bytes. It is a volume of its own on purpose: a backup of
  `/data` that does not have the key reveals none of the secrets.

**Keep a copy of `./keys/master.key` somewhere that is not the place of your backups of
`./data`.** Without it a backup of the database cannot be opened.

A new installation (an empty database) makes the key by itself and says so in the log. If the key
is missing and the database already holds anything that it sealed, the panel does not start. It
does not make a new key: the sealed values could never be opened with it, and every node would
stop trusting the panel. The usual cause is a `/keys` volume that was not mounted, or was
recreated. Mount the right volume, or put the key back from your backup. If you really want to
start from nothing, delete the database too.

### Who owns the files

The panel runs as user and group `65532`. Docker makes a bind-mounted directory that does not
exist, such as `./data` on the first start, owned by root, so the entrypoint hands `/data` and
`/keys` to `65532:65532` when something in them belongs to somebody else, and then drops root.
On the host the files are therefore owned by `65532` (use `sudo` to read a backup). A volume
that is already right is left alone. With `docker run --user`, or `user:` in the compose file,
nothing is changed and the volumes have to be writable for that user already.

## Behind a reverse proxy

The limits on sign-in count failed attempts per client address. 5 failures in 15 minutes lock
the address, for 15 minutes and then twice as long each time, up to a day; 5 failures for one
user name from one address lock that user name for that address alone. A user name is never
locked for everybody, so knowing the admin's name is not enough to lock the admin out. When
more than 100 attempts have failed in the last minute, from all addresses together, every
attempt waits a second before it is checked: that slows an attack from many addresses down,
and locks nobody out.

Clients may share one address without any proxy of yours. Docker's userland proxy carries the
connections to a port published on the loopback, such as those of an SSH tunnel (see
[Keeping the port off the network](#keeping-the-port-off-the-network)), and those to a port
published on IPv6 when the container has no IPv6; the panel sees all of them come from the
gateway of the Docker network, and five failures from any of them lock all of them out. For
accounting per client, put a reverse proxy with TLS in front of the panel and list it in
`POSTERN_TRUSTED_PROXIES`.

Behind a proxy every connection comes from the proxy, so the panel has to be told which peers
are proxies and may say who the client is, or all clients share one address, and five failures
from anybody lock everybody out. The panel believes the `X-Forwarded-For` header **only** from
the peers named in `POSTERN_TRUSTED_PROXIES`. A private or loopback address is not a proxy for
being one.

Name the address that the proxy connects from, as the panel sees it. For a proxy on the same
host that reaches the published port through Docker, that is the gateway of the Docker network:

```sh
docker network inspect postern-panel_default --format '{{(index .IPAM.Config 0).Gateway}}'
```

```sh
# .env, next to compose.yaml
POSTERN_TRUSTED_PROXIES=<gateway>
# or, for a proxy container on the same Docker network:
POSTERN_TRUSTED_PROXIES=<network>
```

`<gateway>` is the address that the command above prints. `<network>` is the subnet of the same
Docker network, as a CIDR prefix, which `--format '{{(index .IPAM.Config 0).Subnet}}'` prints.

The proxy must also send `X-Forwarded-Proto: https`, so that the session cookie is marked
`Secure`, and must overwrite `X-Forwarded-For` with the address that it sees (most do). The
panel believes `X-Forwarded-Proto` on the same terms as `X-Forwarded-For`, only from the
peers in `POSTERN_TRUSTED_PROXIES`, and reads only its last value, the one that the proxy
wrote.

### Caddy

The recommended Caddyfile, for Caddy on the same host:

```text
{
	on_demand_tls {
		ask http://127.0.0.1:8080/api/tls/ask
	}
}

panel.example.com {
	reverse_proxy 127.0.0.1:8080
}

https:// {
	tls {
		on_demand
	}
	reverse_proxy 127.0.0.1:8080
}
```

`panel.example.com` is the name you reach the admin by. The `https://` site serves every other
name that points at the server, and gets its certificate on the first visit (on-demand TLS):
the [public page](../../docs/diagnostics.md#the-public-page) whose host you set in the UI works
by itself, without an edit of the Caddyfile or a restart. Before Caddy asks for a certificate it
asks the panel, `GET /api/tls/ask?domain=<name>`, and the panel approves only its own names: the
host of the public page while the page is on, and the names the admin pages have been served
on. Every other name gets a 404, so nobody can make Caddy fetch certificates for names of his
choosing. The panel answers that question only to a peer on the loopback or in
`POSTERN_TRUSTED_PROXIES`, by the address of the connection, and never to a request that
carries `X-Forwarded-For`, which a proxy adds to what it relays for somebody else. **Caddy has
to be in `POSTERN_TRUSTED_PROXIES`**, as above: through a port that Docker publishes, the panel
sees it come from the gateway of the Docker network, not from the loopback, and without that
every on-demand name is refused and the public page has no certificate. Other peers that reach
a published port can look like the gateway too, so publish the port on the loopback only,
`POSTERN_BIND=127.0.0.1` (see [The panel's port](#the-panels-port)). A Caddy in another
container uses the panel's address on the Docker network in the `ask` URL and in
`reverse_proxy`, and its network goes in `POSTERN_TRUSTED_PROXIES`.

In the settings of the public page, **Check** says where the host points and whether HTTPS
works with a valid certificate; when it does not, the certificate is the reverse proxy's
business, not the panel's.

Caddy sets both headers by itself.

### nginx

nginx has no on-demand TLS: every name needs a `server` block with its certificate, the
public page's host too, added by hand when you set it in the UI. Send the two headers:

```text
proxy_set_header Host              $host;
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Forwarded-Proto https;
```

### The panel's port

Only the proxy may be able to reach the panel's port: publish
it on the loopback with `POSTERN_BIND=127.0.0.1` (see
[Keeping the port off the network](#keeping-the-port-off-the-network)), or firewall it. Docker
publishes ports around host firewalls such as ufw, so a firewall rule for it goes in the
`DOCKER-USER` chain.

## The node kit

A node is installed from its bundle and a `postern-node` binary with the installer files of
`deploy/node` (see [its README](../node/README.md#without-a-registry)). The image carries all of that, so that
a node can be installed before any release exists and without reaching a release host, and runs
the version of the panel:

```text
/usr/local/share/postern/node-kit/install.sh             0755
/usr/local/share/postern/node-kit/launcher.sh            0755
/usr/local/share/postern/node-kit/compose.yaml           0644
/usr/local/share/postern/node-kit/amd64/postern-node     0755
/usr/local/share/postern/node-kit/arm64/postern-node     0755
```

Both binaries are built with the panel, with its `VERSION`, `COMMIT` and `DATE`, so
`postern-node version` says what `postern-panel version` says. In the
[image of a release](#the-image-of-a-release) they are the signed binaries of the release, each
with its signature next to it, `<arch>/postern-node.minisig` (0644); an image built from the source
has no signatures. The panel serves the kit of an architecture to admins at `/api/node-kit/amd64`
and `/api/node-kit/arm64`, as `postern-node-kit-linux-<arch>.tar` (a plain USTAR file with the four
files at its top level), and the page of a node shows the steps of the install with it.

The kit of an architecture is there when `<dir>/<arch>/postern-node` is an executable file and the
three scripts are files in `<dir>`; the panel looks at every request, and says at start, in one
line of its log, which architectures it has. When `<dir>` is there and the kit of an architecture
that is asked for is not, the request is logged as a warning with the reason. A download has 15
minutes to finish. A panel without a kit (one that runs with `go run`)
works the same otherwise: the page of a node then says which version of `postern-node` to install
with `install.sh --binary`.

## The image of a release

The images that the release workflow pushes are not built from the source. `scripts/release.sh`
builds the release, the UI in it, and signs it into `dist/` ([docs/releasing.md](../../docs/releasing.md)),
and the image is made of those files:

```sh
docker build --build-arg PREBUILT=dist -f deploy/panel/Dockerfile -t postern-panel:<version> .
```

`PREBUILT` is a directory of the build context. The image takes `postern-panel-linux-<arch>` (of
the architecture of the image) from it as its panel, and `postern-node-linux-amd64` and
`postern-node-linux-arm64` with their `.minisig` as its node kit, byte for byte; no UI and no Go is
built, and `VERSION`, `COMMIT` and `DATE` are those that the binaries of the release carry. The
binaries of an image and those of its release are the same files, so both have the same SHA-256 and
the same signatures. Of `dist/`, only those files get into the build context (`.dockerignore`).

## The country database

The countries of the clients in the statistics come from the free "IP to Country Lite" database
of [DB-IP](https://db-ip.com), a file of about 8 MB. It is public data and holds no address of a
client or of a node. Country data: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.

The panel downloads `dbip-country-lite-<YYYY-MM>.mmdb.gz` from `download.db-ip.com` when it
starts and looks again every day: for the current month, or for the month before while DB-IP has
not published the new file, and for nothing when it has that month already. The download has
30 seconds to connect and 5 minutes in all, at most 64 MiB of gzip and 256 MiB unpacked. The file
is checked as a country database before it replaces anything, so a bad download leaves the
database that the panel had in use; the failure is in the status of the database and, once for
each different error, in the events. The current file and the one before it are kept, in
`/data/geoip/` as `dbip-country-lite-<YYYY-MM>.mmdb` (mode 0644, since it is public data).

A panel that cannot reach DB-IP, or a network that must not, has two ways out. An admin can send
the file with `PUT /api/geoip` (the body is the database, gzipped as DB-IP publishes it or
unpacked, at most 256 MiB; the answer is its status as JSON), and `POSTERN_GEOIP_BASE_URL` can
point the panel at a mirror, a directory that has the files under the same names. Country lookups
can be turned off altogether, which stops the downloads. DB-IP and the network in front of its
download (a CDN) see the address of the panel when it downloads, and what the panel asks for is
the file of a month, nothing of its nodes or its clients.

## Updates and the launcher

The container starts `entrypoint.sh`, which does the ownership step, drops root and runs
`launcher.sh serve`; the launcher replaces itself with the panel, so the panel is the process
that gets Docker's signals. On `SIGTERM` the panel stops accepting connections, lets the requests
that are running finish (up to 8 seconds), stops the connections to the nodes and closes the
database. `docker compose stop` waits up to 30 seconds for that.

`entrypoint.sh` runs every command other than `serve` (for example `version`) without the
launcher: a one-off command through the launcher would count as a start.

To update the image: `docker compose pull && docker compose up -d` (or `up -d --build` from a
checkout). The database is copied to `/data/backups` before the panel migrates it.

Going back to an older image after an update that migrated the database needs that copy: an
older panel refuses a database that a newer one has migrated further (it logs that the database
"was migrated by a newer version" and does not start). Stop the panel, put the copy that was made
before the migration in the place of the database, and start the older image:

```sh
docker compose stop postern-panel
sudo ls -l ./data/backups        # postern.db.<unix time>.bak, one before each migration
sudo cp ./data/backups/postern.db.<unix time>.bak ./data/postern.db
sudo rm -f ./data/postern.db-wal ./data/postern.db-shm
POSTERN_IMAGE=<older image> docker compose up -d
```

The `-wal` and `-shm` files belong to the newer database and must go with it. What changed after
the copy was made is lost. The same goes for a newer binary in `/data/bin` (below) that migrated
the database: the binary that the launcher, or you, go back to refuses the database until the
copy is back.

The launcher is the one of the node (`deploy/node/launcher.sh`) with the paths of the panel:

- The binary of the image, `/usr/local/bin/postern-panel`, runs until something is put into
  the data volume. Newer binaries go to `/data/bin/postern-panel-<version>`, with `current`
  (a relative symlink) pointing at the one to run and `previous` at the one that ran before.
  **Remove `/data/bin/current` to go back to the binary of the image.**
- With no `bin/current` the launcher runs the binary of the image. It still keeps its books
  for that start (the start is recorded against the image binary's path, the marker below is
  asked for), so the panel knows it runs under its launcher and offers its first update; there
  is no rollback from the image binary, since there is nothing older to go back to.
- With one, it judges the start before: the panel writes a **healthy marker** (the path is in
  `POSTERN_HEALTHY_FILE`, `/data/run/launcher/healthy`) once the database is open, the key and
  the CA are loaded and the server is listening. A start without the marker is an unhealthy
  start; after 3 in a row, if `bin/previous` is an executable file, `bin/current` is pointed at
  it and `bin/previous` is removed. `bin/previous` may be an absolute link to the binary of the
  image, which is the way back when the first update fails. Details and the files of
  `/data/run/launcher` are in the header of `launcher.sh`.

### Self-update

The Versions page (`GetPanelVersion`, `UpdatePanel`) updates the panel to a newer signed release
without pulling an image. It is offered only when the launcher started the panel
(`POSTERN_HEALTHY_FILE` is set), `/data/bin` is writable and a file there runs (a volume mounted
`noexec` cannot take an update), and the binary has a release key compiled in. The panel never
updates to the version it runs or an older one, and refuses while a node's agent is older than
the minor before the target version (the panel supports nodes of the previous minor only): it
names those nodes, which are updated first. For a `vX.Y.0` with `Y > 0` the oldest agent allowed is
`vX.(Y-1).0`; for a `vX.0.0` it is `v(X-1).0.0` (lenient: the last minor of `X-1` is not known).
Nodes that have not reported a version yet are not counted.

An update:

1. fetches `postern-panel-linux-<arch>` and both `postern-node-linux-*` of the release (so that
   the node kit can follow) into `/data/artifacts/postern/<version>`, unless they are there from
   an uploaded bundle, and checks each against its signature, the static-ELF rule and the SHA-256
   that the release pins (the first time, the verified bytes are pinned; the panel binary has a pin
   of its own);
2. copies the panel binary into `/data/bin`, verifies the copy again (signature, ELF, pin) and runs
   `<binary> version`, which has to print `<version> (`; the pin is checked once more right before
   the file is moved in;
3. copies the database with `VACUUM INTO` (never a raw copy of the file) to
   `/data/backups/postern.db.pre-<version>.<unix time>.bak`;
4. writes the journal `/data/run/selfupdate.json` (`from`, `to`, `backup`, `at`);
5. installs `/data/bin/postern-panel-<version>`, points `previous` at what `current` pointed to
   (the binary of the image, by its absolute path, when there was no `current`) and `current` at
   the new file, and audits `panel_update_started`;
6. answers, stops as on `SIGTERM`, and exits with status **75**; `restart: unless-stopped` starts
   the launcher again, which runs the new `current`. An exit with 75 after the marker was written
   is no unhealthy start.

When the new version serves, it deletes the journal and records the event `panel_updated`.

**Automatic rollback and restore.** When the new version does not get healthy 3 times in a row,
the launcher points `current` back at `previous` and leaves `/data/run/launcher/rollback`. The old
version then finds the journal and the record (the record must not be older than the journal; an
older one is ignored) before it opens the database. If the failed version had migrated the
database, so that the old one would refuse it, `postern.db`, `postern.db-wal` and `postern.db-shm`
are moved to `/data/backups/failed-<version>-<unix time>/` and the snapshot of step 3 is put in
place as `postern.db`; what changed after the snapshot is in the kept files only. The files are
kept (hard links) before anything is removed, and the snapshot replaces `postern.db` in one rename,
so the data directory always has a database; a restore cut short is finished at the next start.
The snapshot, like every backup, has no client addresses (`ip_sightings` is emptied by design), so
the history of client addresses before the update is lost. The event `panel_update_rolled_back`
names the paths, and the journal and the record are deleted last.

If the failed version crashed and left a `postern.db-wal` without its `-shm`, the database may not
open read-only for the check: the panel then stops with an error (exit 1) and touches nothing.
Look at `/data/postern.db*` and the journal `/data/run/selfupdate.json`, restore the snapshot by
hand as above, and remove the journal and `/data/run/launcher/rollback`.

**Downgrade by hand.** The panel never downgrades itself. To go back to the binary of the image,
stop the panel, remove `/data/bin/current` and start it again (if the newer binary migrated the
database, restore the copy as above).

**A newer image wins.** After `docker compose pull && docker compose up -d` the launcher still
starts `/data/bin/current`, but that panel checks before it serves: when it runs from
`/data/bin` and the binary of the image reports a newer version (`<binary> version`, compared as
versions, prereleases included: `v1.0.0-rc7` is newer than `v1.0.0-rc6`, `v1.0.0` newer than
both), it logs a warning ("the image carries vX, newer than the self-updated vY: going back to the
image binary"), removes `current`, and `previous` when it points at the image binary (the
`postern-panel-<version>` files stay), and exits with 75; the launcher then runs the image. The
image panel records the event `panel_image_newer` and shows it as the last update. An image that
is older than or as new as the self-updated binary changes nothing; when the version of the
image binary cannot be read, the panel warns and runs on.

`kit_signed` on the Versions page says only that the node kit of the image came with signature
files (`<arch>/postern-node.minisig`); the node verifies the signature when it installs the
binary.

## Without Docker

```sh
cd web && npm ci && npm run build && cd ..
cp -r web/dist/. internal/panel/webui/dist/       # over the placeholder page
CGO_ENABLED=0 go build -trimpath -o postern-panel ./cmd/panel
POSTERN_DATA=./data POSTERN_KEYS=./keys POSTERN_LISTEN=127.0.0.1:8080 ./postern-panel serve
```

Without the `cp` the binary builds and works, and serves a placeholder page instead of the UI.
`git status` stays clean either way: only the placeholder page is tracked in
`internal/panel/webui/dist/`.

Such a panel has no [node kit](#the-node-kit). To give it one, lay it out as the image does and
point `POSTERN_NODE_KIT_DIR` at it (`bin/` is ignored by git):

```sh
mkdir -p bin/node-kit
cp deploy/node/install.sh deploy/node/launcher.sh deploy/node/compose.yaml bin/node-kit/
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o bin/node-kit/$arch/postern-node ./cmd/node
done
POSTERN_NODE_KIT_DIR=./bin/node-kit POSTERN_DATA=./data POSTERN_KEYS=./keys POSTERN_LISTEN=127.0.0.1:8080 ./postern-panel serve
```

## Tests

From the repository root. The tests run on Linux; from Windows use `bash scripts/wsl '<command>'`.

```sh
sh deploy/panel/launcher_test.sh        # the launcher, under the system's sh
sh deploy/panel/compose_test.sh         # how compose.yaml publishes the port (needs docker compose)
```

`compose_test.sh` runs `docker compose config` on `compose.yaml` with `POSTERN_BIND` unset, empty,
`127.0.0.1`, `[::1]` and an IPv6 address, and with `POSTERN_PORT`, and checks the address and the
port that the port is published on; without `docker compose` it says so and is skipped.

`entrypoint_test.sh` has to run as root, since it checks that root changes owners. Run both in the
runner image, which proves that the scripts work with busybox (and is the only place where the
test plants a link to `/etc`, to see that root does not follow it: outside a container, which it
tells by `/.dockerenv`, it skips that case, since a mistake would change the owner of the real
`/etc`):

```sh
for t in launcher_test entrypoint_test; do
  docker run --rm -v "$PWD":/src:ro \
    alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
    sh /src/deploy/panel/$t.sh
done
```

The Go side is tested with the rest of the repository (`go test ./internal/panel/... ./cmd/panel/...`).
