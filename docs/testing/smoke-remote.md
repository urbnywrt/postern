# Smoke test on a real server

A manual check of slices 0 to 2 with a real network and a real Telegram client: the panel runs
on your machine, a node on a test server, and a proxy of that node is probed and then used
(steps 1 to 9). It is the acceptance check of the design ("a proxy from the panel works on a
test VM, a restart of the agent does not break connections, the L1 probe is green"). Then
proxies of the node go out through a VLESS server with REALITY on a second test server, through
WARP and through Psiphon, also while the node cannot send DNS queries over UDP (step 10). The
automated counterpart is `scripts/e2e.sh` (`test/e2e`), which does the same on one machine with
Docker, with local servers for the egresses.

Use servers that you can throw away. Nothing here touches anything but `/opt/postern`, the
containers that Postern makes and the firewall rules that you add on the first, and
`/root/reality`, its container and a firewall rule on the second.

| Placeholder | What it is |
|---|---|
| `<SERVER_IP>` | the public IPv4 address of the test server |
| `<PANEL_IP>` | the public address of your machine as the server sees it, which the panel connects from: `ssh root@<SERVER_IP> 'echo $SSH_CLIENT'` prints it first |
| `<MGMT_PORT>` | the management port of the node: in the bundle, printed by `install.sh` |
| `<PORT>` | the port of the proxy's listener: 443 when it is free, 8443 otherwise |
| `<ARCH>` | the CPU architecture of the server: `amd64` or `arm64` (`uname -m`: `x86_64` or `aarch64`) |
| `<SERVER_B_IP>` | step 10: the public IPv4 address of the second test server, which runs the VLESS server |
| `<REALITY_PORT>` | step 10: the port of the VLESS server: 443 when it is free on the second server, 8443 otherwise |
| `<REALITY_SNI>` | step 10: the server name that REALITY borrows: use `dl.google.com` (it works with Xray 26.3.27; `www.microsoft.com` fails). To check another site, run `openssl s_client -connect <site>:443 -tls1_3 -alpn h2 </dev/null` from the second server: it must negotiate TLS 1.3 and h2, then try it in step 10.2 |
| `<CC>` | step 10: the exit country of Psiphon, two letters |

## What you need

- The test server: Linux on x86-64 or arm64, root over SSH, Docker Engine with the Compose v2
  plugin (on Debian and Ubuntu `apt-get install -y docker.io docker-compose-v2`), no
  `userns-remap`, and a firewall that you control (`ufw` below).
- For step 10, a second test server: Linux, root over SSH, Docker Engine, `unzip`, and a
  firewall that you control.
- For step 4b, Docker on your machine as well, to build the node image.
- Your machine: this repository and Go 1.27 (from Windows, run the Go commands in WSL:
  `bash scripts/wsl '<command>'`). The panel has to reach `<SERVER_IP>:<MGMT_PORT>` and GitHub,
  from which it downloads telemt.
- A Telegram client (Desktop, Android or iOS) on a network from which `<SERVER_IP>:<PORT>` can
  be reached.
- For held sessions and the statistics, a client address that is not the panel's. Once the
  node's edge has the capability `probe-sources`, a connection from the panel's own address
  (`<PANEL_IP>`) is taken for one of the panel's probes: it is cut 30 seconds after it was
  accepted, and it never shows in the statistics. Run the Telegram client, every session that
  has to stay open (through a restart, a switch, a roll of the edge) and every client whose
  traffic the statistics should show from another address; short `l1` and `l2` probes from
  `<PANEL_IP>` are fine.

## 1. Build

```sh
make build                                          # bin/postern-panel (and bin/postern-node) for this machine
CGO_ENABLED=0 GOOS=linux GOARCH=<ARCH> go build -trimpath -o bin/postern-node-<ARCH> ./cmd/node
```

## 2. Start the panel

```sh
mkdir -p smoke/data smoke/keys
POSTERN_DATA=$PWD/smoke/data POSTERN_KEYS=$PWD/smoke/keys POSTERN_LISTEN=127.0.0.1:8080 \
  ./bin/postern-panel serve
```

It prints the setup URL once (`http://127.0.0.1:8080/setup?token=...`). Open it, create the
admin (a password of at least 12 characters) and sign in. The image works as well:
`cd deploy/panel && docker compose up -d --build`, see `deploy/panel/README.md`.

`smoke/keys/master.key` and `smoke/data` hold the keys of the panel and of the node: keep them
out of the repository and delete them at the end.

## 3. Create the node

In the panel, add a node:

- name: `smoke`;
- management host: `<SERVER_IP>`; management port: empty (the panel picks a high port) or one
  of your choice;
- link host: `<SERVER_IP>`.

Download `postern-node-bundle.tar`. It holds the private key of the node: copy it only to the
server, and delete it once the node is online.

## 4. Install the node

One command line makes the directory and copies the files, and nothing else is pasted with it:
when `ssh` or `scp` stops to ask for a password, or whether to trust the key of the server, it
takes the next line that was pasted as the answer.

```sh
ssh root@<SERVER_IP> mkdir -p /root/postern && scp deploy/node/install.sh deploy/node/launcher.sh deploy/node/compose.yaml bin/postern-node-<ARCH> postern-node-bundle.tar root@<SERVER_IP>:/root/postern/
```

```sh
ssh root@<SERVER_IP>
```

On the server:

```sh
cd /root/postern
bash install.sh --bundle postern-node-bundle.tar --binary ./postern-node-<ARCH> --version smoke
ufw allow from <PANEL_IP> to any port <MGMT_PORT> proto tcp
rm postern-node-bundle.tar
```

Expected: `install.sh` ends with `Postern node installed.` and
`Management port: <MGMT_PORT>/tcp (mTLS)`; `docker ps` shows `postern-agent` up;
`docker logs postern-agent` has `agent: serving the panel` and `agent: healthy`.

## 4b. Or: install the node with the Docker command

This takes the place of step 4 and of the bundle of step 3: the one-command install of
`deploy/node/README.md`. The panel of step 2 has to know the node image: start it with
`POSTERN_NODE_IMAGE=postern-node:smoke` in its environment as well. Build the image from this
checkout and load it on the server (one command line, as in step 4):

```sh
docker build --platform linux/<ARCH> --build-arg VERSION=v0.0.1-smoke -f deploy/node/Dockerfile -t postern-node:smoke .
docker save postern-node:smoke | ssh root@<SERVER_IP> docker load
```

The panel of step 2 listens on `127.0.0.1` of your machine, which the server does not reach. For
the join, give the server that address through a tunnel, in a terminal of its own that stays open
until the node is online:

```sh
ssh -N -R 127.0.0.1:8080:127.0.0.1:8080 root@<SERVER_IP>
```

On the page of the node, under **Install with one command**, set **Panel address for nodes** to
`http://127.0.0.1:8080` (a loopback address of the server, so `http://` is accepted) and press
**Get the command**. Check that the `docker run` is the one of `deploy/node/README.md` with the
image `postern-node:smoke`, and that the `compose.yaml` tab says the same. On the server run the
command, then `ufw allow from <PANEL_IP> to any port <MGMT_PORT> proto tcp`.

Expected:

- `docker ps` shows `postern-agent` up on `postern-node:smoke`; `docker logs postern-agent` says
  that the node joined, then `agent: serving the panel` and `agent: healthy`, and holds no token;
- `readlink /opt/postern/bin/current` is `postern-node-v0.0.1-smoke`;
  `cat /proc/sys/net/ipv4/ip_local_reserved_ports` covers `20000-40999`;
  `/etc/sysctl.d/90-postern.conf` exists; `docker ps -a --filter name=postern-sysctl-` lists
  nothing (the helper removed itself);
- in the panel the bundle download of the node answers 409, and the journal (audit) has one
  `node.join` for the node.

Then, once the node is online (step 5):

- `docker restart postern-agent`: the node is online again, with no new `node.join`;
- **Get the command** again, and on the server `docker rm -f postern-agent` and the new command
  (the tunnel open again): a second `node.join`, the same node, online.

Stop the tunnel. Go on with step 5; in step 11, also `docker image rm postern-node:smoke` on the
server.

## 5. The node goes online

Within a minute the node is `online` in the panel, with the agent version, the OS and the
architecture of the server and its public address. It stays `provisioning` when the panel
cannot reach `<SERVER_IP>:<MGMT_PORT>` (check the firewall rule and `<PANEL_IP>`); `error`
means that the panel refuses the node, and the panel's log says why.

## 6. Create a listener and a proxy

On the server, see whether port 443 is free: `ss -ltnp | grep -E ':(443|8443) '`. Then, in the
panel:

- a listener on the node: kind `tls`, bind address `0.0.0.0`, port `<PORT>`;
- a proxy on that listener: domain and secret empty (a domain of the pool and a random secret).

On the server: `ufw allow <PORT>/tcp`.

Wait until the proxy is `serving`. The first time the panel downloads telemt from GitHub and
uploads it to the node, which takes up to a minute. On the server, `docker ps` now also shows
`postern-edge-g1` and `postern-eng-<proxy id in lower case>-g1`.

## 7. The L1 probe

Copy the proxy's `tg://` link from the panel and take the secret and the domain out of it (bash;
`xxd` comes with vim):

```sh
read -r LINK                                        # paste the link, so that it stays out of the history
S=${LINK##*secret=}
SECRET=${S:2:32}
DOMAIN=$(printf '%s' "${S:34}" | xxd -r -p)
```

From the repository, probe the proxy the way a client starts:

```sh
PROBE_SECRET=$SECRET go run ./internal/probe/testdata/probecheck -addr <SERVER_IP>:<PORT> -sni "$DOMAIN"
echo "exit $?"
```

Expected: `probe succeeded at attempt 1, after ...` and `exit 0`: the edge routed the connection
to the engine, and the engine proved that it knows the secret. With a wrong secret,
`PROBE_SECRET=00000000000000000000000000000000`, the probe has to fail (exit status 1 or 3).
Keep the shell open for step 9.

## 8. A real Telegram client

Open the `https://t.me/proxy?...` link of the proxy on the device, or scan the QR code in the
panel, and connect the proxy. Expected:

- Telegram shows the proxy as connected (Android and iOS: Settings, Data and Storage, Proxy;
  Desktop: Settings, Advanced, Connection type), with no "Connecting..." in the title;
- chats load and new messages arrive; a photo sent to Saved Messages goes through;
- within two minutes the live statistics of the proxy in the panel show a connection and traffic.

## 9. A restart of the agent keeps the connections

With the client connected, on the server:

```sh
docker ps --filter label=postern.role=edge --format '{{.ID}} {{.Names}}'
docker restart postern-agent
docker ps --filter label=postern.role=edge --format '{{.ID}} {{.Names}}'
```

Expected: the edge has the same container ID before and after; the client does not show
"Connecting..." and keeps working; the node is `online` again in the panel within a minute; the
L1 probe of step 7 still succeeds.

## 10. Egresses

What CI cannot check of slice 2: real servers on the way out. (`TestEgressChainFailover` covers
an egress chain and its failover with local servers, see `docs/testing/e2e.md`.) Each egress
gets a proxy of its own on the listener of step 6: a new proxy serves only once a datacenter of
Telegram has answered through its chain, while a new chain for a proxy that serves is not
checked that way.

In the shell of step 7, a function that probes a proxy from its link the way a client goes, all
the way to Telegram's DC2 (L2), and keeps the link out of the history:

```sh
l2() {  # paste the tg:// link of a proxy
  local LINK S
  read -r LINK
  S=${LINK##*secret=}
  PROBE_SECRET=${S:2:32} go run ./internal/probe/testdata/probecheck -addr <SERVER_IP>:<PORT> \
    -sni "$(printf '%s' "${S:34}" | xxd -r -p)" -l2 -dc 2 -wait 60s
}
```

Expected of every `l2` below: `L2 to DC2 succeeded at attempt N, ...` and exit status 0: the
resPQ of the datacenter came back through the edge, the engine and the egress.

### 10.1 A VLESS server with REALITY

On the second server, the Xray release that the panel pins, checked against the SHA-256 that
`internal/panel/proxies/catalog.go` pins for the file:

```sh
mkdir -p /root/reality && cd /root/reality
F=Xray-linux-64.zip            # on arm64: F=Xray-linux-arm64-v8a.zip
curl -fsSLO https://github.com/XTLS/Xray-core/releases/download/v26.3.27/$F
sha256sum $F                   # the SHA-256 that catalog.go pins for $F, or stop here
unzip -o $F xray && chmod 755 xray
./xray uuid                    # <UUID>
./xray x25519                  # PrivateKey: <PRIVATE_KEY>, Password (PublicKey): <PUBLIC_KEY>
openssl rand -hex 8            # <SHORT_ID>
```

`/root/reality/server.json`, with those values:

```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "0.0.0.0", "port": <REALITY_PORT>, "protocol": "vless",
    "settings": {"clients": [{"id": "<UUID>", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {
      "network": "raw", "security": "reality",
      "realitySettings": {"target": "<REALITY_SNI>:443", "serverNames": ["<REALITY_SNI>"],
        "privateKey": "<PRIVATE_KEY>", "shortIds": ["<SHORT_ID>"]}
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
```

It holds the private key. Check it, run the server on the host network, and let only the node
in:

```sh
chmod 600 server.json
./xray run -test -c server.json          # Configuration OK.
docker run -d --name reality --restart unless-stopped --network host \
  -v /root/reality/xray:/opt/xray/xray:ro -v /root/reality/server.json:/etc/xray/server.json:ro \
  alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 \
  /opt/xray/xray run -c /etc/xray/server.json
ufw allow from <SERVER_IP> to any port <REALITY_PORT> proto tcp
```

`docker logs reality` shows no error. The share link of the server holds the id of its user:
keep it out of shell histories and chats.

```text
vless://<UUID>@<SERVER_B_IP>:<REALITY_PORT>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<REALITY_SNI>&fp=chrome&pbk=<PUBLIC_KEY>&sid=<SHORT_ID>&type=tcp#reality
```

### 10.2 A proxy through the VLESS server

In the panel, Egress:

- Add an egress: kind Share link (Xray), node `smoke`, the share link of 10.1. Check says
  `vless, reality, tcp: vless://<SERVER_B_IP>:<REALITY_PORT>`. Create the egress.
- Add a chain `reality` of the node with that egress. The health check stays 0: the defaults of
  the node, a check every 30 seconds.
- Add a proxy `reality` on the listener of step 6, domain and secret empty, with Egress, Chain
  `reality`.

Expected: the proxy is `serving` within a few minutes (the panel uploads Xray to the node
first). On the node's page, Egress health has the member of chain `reality` up, with a latency,
and `<SERVER_B_IP>` as its exit IP. On the node, `docker ps` shows a container
`postern-egr-<egress id in lower case>-g1`; on the second server,
`ss -tn state established '( sport = :<REALITY_PORT> )'` lists connections from `<SERVER_IP>`.
`l2` with the link of the proxy passes, and a Telegram client works with it as in step 8.

### 10.3 A proxy through WARP

Add an egress of kind WARP (node `smoke`), a chain `warp` with it, and a proxy `warp` on the
listener with that chain.

Expected: the proxy serves; the member of chain `warp` is up, and its exit IP is one of
Cloudflare's, not `<SERVER_IP>`; `l2` with its link passes. The node has registered a WARP
device of its own: on the node, `ls /opt/postern/data/state/egress/` lists the egress.

### 10.4 A proxy through Psiphon

Add an egress of kind Psiphon (node `smoke`, exit country `<CC>`), which the panel marks
Experimental, a chain `psiphon` with it, and a proxy `psiphon` on the listener with that chain.
warp-plus opens its port only once its tunnel is up, which takes up to a minute and a half.

Expected: the proxy serves; the member is up, with an exit IP in `<CC>`; `l2` with its link
passes. Psiphon stays Experimental in the UI until it has passed this step on a real server:
say in the report whether it did. Taking the label away is a change of its own: the label is
`EXPERIMENTAL_KINDS` (`isExperimental`) in `web/src/app/egress.ts`, with its texts under the
keys `egress.experimental` and `egress.experimentalHint` of `web/src/i18n/en.json` and
`ru.json`, and the comment on the kind psiphon in `proto/postern/panel/v1/egress.proto` ("It is
experimental.") says it too.

### 10.5 No DNS over UDP

Production nodes cannot send DNS queries over UDP port 53. A node then resolves names through
the DNS forwarder of its edge, which asks DNS-over-HTTPS servers (the node's page, Egress, Name
resolution: DNS-over-HTTPS through the edge, the default). On the node, with the three proxies
serving:

```sh
iptables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP
ip6tables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP    # when the server has IPv6
```

The rule is inserted at the head of the chain, not appended: ufw accepts new UDP before a rule
at its end, which would then block nothing. It leaves the loopback alone: the forwarder listens
on `127.0.0.2:53`, and the containers of the node send it their queries over UDP. Without
`! -o lo` (`iptables -I OUTPUT -p udp --dport 53 -j DROP`) the rule drops those as well, which no
network does to a node, and then no new name resolves in a container: that is not a fault of
the node.

Expected, with the rule in place:

1. After `getent hosts postern-$RANDOM.example.com` on the host (a name that no cache holds),
   `iptables -L OUTPUT -v -n | grep 'dpt:53'` shows the counter of the rule grown: queries over
   UDP no longer leave the node.
2. `l2` with each of the three links passes, and the three members stay up in Egress health.
3. The forwarder answers:
   `docker run --rm --network host alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 nslookup example.com 127.0.0.2`
   prints the addresses of `example.com`.
4. The providers resolve the names of their servers when they start (the endpoint of WARP, the
   servers of Psiphon): restart them,
   `docker restart $(docker ps -q --filter label=postern.role=egress)`. Within two minutes the
   three members are up again, and `l2` passes with each of the three links.
5. A new engine resolves through the forwarder too: add a proxy `dns` on the listener with the
   chain `reality`. It serves once a datacenter has answered through the chain, and `l2` with
   its link passes. Delete it then.

The counter of the rule may also grow while Psiphon starts, with no query of a name: some of
Psiphon's own tunnel protocols run over UDP to port 53 of Psiphon's servers. Those datagrams are
not DNS; the rule drops them and Psiphon connects over another protocol, so the member comes up
all the same. Psiphon's names still resolve only through the forwarder
([third-party/psiphon-tunnel-core.md](../third-party/psiphon-tunnel-core.md#network)).

Then remove the rule, also when a check above failed:
`iptables -D OUTPUT ! -o lo -p udp --dport 53 -j DROP` (and the same with `ip6tables` when you
added it).

## 11. Clean up

First, on the node, the rule of 10.5, wherever step 10 stopped. This removes every copy of it,
and does nothing when there is none:

```sh
while iptables -D OUTPUT ! -o lo -p udp --dport 53 -j DROP 2> /dev/null; do :; done
while ip6tables -D OUTPUT ! -o lo -p udp --dport 53 -j DROP 2> /dev/null; do :; done
```

Before anything goes, see whether the node registered a WARP device: on the node,
`ls /opt/postern/data/state/egress/` lists the WARP egress (its id in lower case) when it did.
When it does not (10.3 was skipped, or failed before the registration), there is no device.

In the panel delete the proxies (those of step 10 too), the chains `reality`, `warp` and
`psiphon` and then their egresses, and remove the proxies from the Telegram client. Once no
proxy uses the WARP egress, the node deletes its device at Cloudflare as soon as the container
of the egress has drained, within three minutes, and its log says how that went:

```sh
docker logs postern-agent 2>&1 | grep 'WARP device'
```

- `deleted the WARP device of a deleted egress`, or `the WARP device of a deleted egress was gone
  at Cloudflare already`: the device is gone.
- `could not delete the WARP device of a deleted egress at Cloudflare`: the node keeps the account
  and tries again a minute later, then two minutes after that, then four. Wait for one of the
  lines above. When none comes within ten minutes, note it in the report with the error of that
  line (it holds no token): the device stays registered once the node goes.
- Neither line, while the node registered a device: wait, before the node goes; a node deleted
  first leaves its device registered.

Then delete the listener and the node. On the server:

```sh
docker rm -f $(docker ps -aq --filter label=postern.managed=true)
rm -rf /opt/postern /root/postern
ufw delete allow <PORT>/tcp
ufw delete allow from <PANEL_IP> to any port <MGMT_PORT> proto tcp
```

On the second server:

```sh
docker rm -f reality
rm -rf /root/reality
ufw delete allow from <SERVER_IP> to any port <REALITY_PORT> proto tcp
```

On your machine stop the panel (Ctrl-C), delete `smoke/`, and in the shell of step 7
`unset LINK S SECRET DOMAIN` and `unset -f l2`.

## Report

Note the date, the commit, the OS, architecture and Docker version of the server, and for each
step whether it passed. A step that failed goes with what the panel showed, the end of
`docker logs postern-agent` and, for a proxy, the end of
`docker logs postern-eng-<proxy id in lower case>-g1`. These logs hold no secrets, but they do
hold the addresses of the server and of the clients: share them with care.

For step 10, note for each egress the latency and the exit IP that Egress health shows for its
member and what `l2` printed, the same with the rule of 10.5 in place, and whether Psiphon
passed. An egress that failed goes with the end of the log of its container,
`docker logs postern-egr-<egress id in lower case>-g<N>`, and of the edge,
`docker logs postern-edge-g<N>`. For WARP, note what became of its device in step 11: deleted
(or gone already), or still not deleted when the node went, with the error of the line
`could not delete the WARP device`.
