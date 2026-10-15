# The end-to-end test in CI

`test/e2e` runs the panel, a node agent in Docker, the edge and telemt, and a fake-TLS client
through the edge; it restarts the agent, pauses and resumes the proxy, gives it a new secret (a
new generation of the engine, blue-green), and at the end checks that no log of the run holds
one of its secrets (see `TestPanelToNodeFakeTLS`, the package documentation and
`scripts/e2e.sh`). The containers of the
node run on the host network of the Docker daemon, and the test reaches them on `127.0.0.1` and
shares the node's directory with them at the same path. So the test needs a runner whose job
runs **directly on the Docker host**, with real host networking, not in a container of its own.

- **GitHub Actions**: the hosted runners are such hosts. The `e2e` job of
  `.github/workflows/ci.yml` runs there on every push and pull request.
- **Gitea Actions**: an `act_runner` in its default container mode runs the job in a container
  that has neither the host's network nor its paths. The test fails there by design, at once,
  in `checkSharedHost` ("a container on the host network does not reach this process at
  127.0.0.1"), rather than with a node that never comes online. The job is therefore skipped on
  Gitea unless the repository variable `POSTERN_E2E` is `1`. Set it only for a repository whose
  runner runs the job on the host: an `act_runner` with the label `ubuntu-latest:host` (host
  mode for the `runs-on` of the job), on a host with Docker that can reach GitHub (the panel
  downloads telemt from there, and the job sets up Go).

On a workstation, `bash scripts/e2e.sh` runs the test; on Docker Desktop it runs the test binary
in a container on the host network of Docker's VM, which is how it reaches the node there.

## The egress chain

`TestEgressChainFailover` (`test/e2e/egress_test.go`) gives a proxy an egress chain of two
Xray egresses and fails it over. The two "remote" VLESS servers run in containers of the run,
on the Xray release that the panel pins (downloaded from GitHub and checked against the pinned
SHA-256), on a Docker network of the run on `198.51.100.0/24`. An echo server of the test listens
on the gateway of that network, `198.51.100.1`, and answers every connection with the address
that it came from: a CONNECT through the SOCKS port of the proxy says which server the edge
went out through. The test stops the first server, and the edge has to take it down within
`fail_threshold × interval` and the time that one check takes, and go out through the second.
On top of the first test, the host of the job needs:

- the datacenters of Telegram, from the host network and through Docker's NAT: an engine
  generation serves only once a datacenter has answered through its chain, and the members of a
  chain are checked against them;
- the echo services that the edge asks for the exit address of every member that passed its
  check (`api.ipify.org`, `ifconfig.me` and `icanhazip.com`), through the same ways out: a round
  of the checks waits for them, and where they are slow the rounds stretch and the failover
  comes later than the test allows;
- `198.51.100.0/24` free for a Docker network (one run at a time per daemon), and connections from
  the containers of that network to the host itself not dropped by a firewall of the host.

With `POSTERN_E2E_ONLINE=1` (`scripts/e2e.sh` passes it on) the online subtests run as well: L2
through the proxy to Telegram's DC2 over each server, and WARP, for which the node registers a
WARP device with Cloudflare; the subtest deletes the device at its end, also when it fails. The
CI job does not set it. To leave WARP out on a network that drops WireGuard to Cloudflare, select
the other subtests: `bash scripts/e2e.sh -test.run 'TestEgressChainFailover/L2'`.

## Versions without downtime

`TestVersions` (`test/e2e/versions_test.go`) changes what one node runs, one action at a time,
while clients use it (R5-2): a version rollout of telemt, a failed one that cancels itself, a
switch of a proxy to mtg and back, and node rollouts of the agent and the edge, among them the
way back to the version that the node was installed with. The proof that no client notices:

- **held connections**: right before each change, a connection to every proxy that the change
  moves goes through the fake-TLS handshake, and it is still open once the change is through.
  telemt closes a client that has sent nothing for 60 s after its handshake, so the change has
  to be through within 50 s of it, or the test fails and says so. With `POSTERN_E2E_ONLINE=1`
  the held connections are L2 sessions that ask DC2 every 10 s instead (`probe.L2Session`);
- **the prober**: an L1 probe every 250 ms, the two proxies in turn, for the whole test; it may
  not fail once;
- **the accept queue**: during each edge roll 256 workers open short connections back to back
  (connect, the fake-TLS handshake, a reset), each from a loopback address of its own (the edge
  refuses more than 16 connections of one source before their ClientHello), `test/e2e/flood.go`:
  some 14 000 connections a second on a workstation. With `net.ipv4.tcp_migrate_req = 1` (what
  `install.sh` sets) none of them may fail. With `0` the connections still queued, or half open, at
  the old edge's listeners when they close are reset, and the flood has to see a failure, or it
  never reached the accept queue and its runs at 1 prove nothing. Only what is queued at that
  moment fails, so a roll at 0 fails the flood about one time in two (one or two connections of
  some 85 000; more workers made it rarer, not likelier): the test rolls the edge back and forth
  at 0 until the flood has failed, 8 rolls at the most. That run at 0 is a control, not a verdict:
  when all 8 rolls pass (about one run in 150), the test logs a warning that the run at 1 is not
  shown to be meaningful, and does not fail, so a good engine candidate of the stable job is
  never left out by chance. The run at 1 fails on any failed connection. The test reads and
  sets the sysctl of the host network with a privileged container of the run, and restores it at
  the end.

`scripts/e2e.sh` makes a throwaway release key in its work directory and builds postern-node
`v0.90.0-e2e` (installed), postern-node and postern-panel `v0.90.1-e2e` (the update and the
panel) and the stand-in engine (`test/e2e/testdata/badengine`), all trusting the key
(`-X …/internal/release.extraPublicKeys`). The test signs the update with the key and serves the
releases of the run from a GitHub of its own on `127.0.0.1` (`test/e2e/releasehost.go`, the
panel's `POSTERN_GITHUB_API`): telemt `3.5.90` (the real 3.5.13, repacked), telemt `3.5.91` (the
stand-in, which passes the trial run and exits as an engine) and postern-node `v0.90.1-e2e`. The
release lists of every other repository are empty, so mtg `v2.2.8` and telemt `3.5.13` come from
GitHub through the panel's built-in pins. On top of the first test the host of the job needs a
kernel with `net.ipv4.tcp_migrate_req` (Linux 5.14 or later), privileged containers,
`198.51.100.0/24` free for a Docker network, and sslip.io: mtg dials an address of its proxy's
domain itself (it fronts to an IP address), so the proxy that switches to mtg has the domain
`198-51-100-1.sslip.io`, the gateway of that network, where nothing listens on 443.

One thing the test works around, which a real node has as well: mtg ends a client that has sent
nothing 10 s after its handshake (its handshake timeout), so offline no held connection outlasts
the switch back from mtg (the prober watches it). An edge-only roll takes a binary only with a
kept signature; the test installs the node as `install.sh` does, with the release's signature
kept beside the binary, so the roll back to the version that the node was installed with is an
edge-only rollout.

The e2e job of CI runs `scripts/e2e.sh` with a limit of 30 minutes; the whole package has 28.

## Statistics, diagnostics and the public page

`TestInsights` (`test/e2e/insights_test.go`) runs slice 6 on the harness of the first test
(`setUpFakeTLS`): a fake-TLS proxy on a listener whose links lead to `127.0.0.1`, on a chain of a
direct egress. The panel reaches the node from `127.0.0.1`, which the node learns as the panel's
address and the edge exempts as a probe source; the test's own clients therefore dial from
`127.0.0.3`, every 10 s but in the last 18 s of a minute, so that each handshake is counted in
the minute it was made in. It checks:

- a country database of the test (`geoiptest`) uploaded through `PUT /api/geoip` (the panel's
  download base is a port that nothing listens on) and stored on the node; the series of the
  proxy and of the node, the countries and, under the IP policy `full`, the IP history;
- a probe from the panel (L2), and, when the node reports `probe-sources`, that the IP history
  never lists the panel's address;
- the proxy moved to a chain whose only member is a SOCKS5 server that does not exist: a
  before-run, an after-run with `egress.dc` and `e2e.l2` failing, a panel probe that says
  "no datacenter answered through the proxy (L1 ok)", and the `change_egress` fix that heals it;
- the panel stopped for 150 s or more (two whole minutes at least) while the clients go on:
  after its restart every minute of the
  gap is there once, with as many new connections as handshakes, one country row a minute and the
  minutes of the chain's member (the hours of members are rolled hourly, from whole hours only,
  so the test does not wait for them);
- the policies `countries` (no client address left in the database file, its WAL or its backups)
  and `off` (the country tables emptied, no new row);
- a node run of the diagnostics; the engine container paused with the Docker API, listed in the
  problem feed and gone once unpaused, and the `recreate_instance` fix while it is paused;
- the public page on `proxies.example.test`, its headers, its sanitized Markdown, no admin on
  that host, and a paused proxy marked or hidden at once;
- no secret in any log, nor a secret or the clients' address in a text of the diagnostics, the
  problem feed or the journal.

It needs Telegram's datacenters reachable, as the first test does (an engine serves only once a
datacenter has answered), and takes about 15 min; `scripts/e2e.sh` gives the run of all the
tests 60 min, and the CI job 75. Alone: `bash scripts/e2e.sh -test.run '^TestInsights$'`.

## The one-command install

`TestDockerJoin` (`test/e2e/docker_join_test.go`) installs a node with the Docker command of the
panel (`deploy/node/README.md`, "Install with one Docker command"). `scripts/e2e.sh` builds the
node image of the run, `postern-node:e2e-<run>`, from the node binary that it installs elsewhere
(`deploy/node/Dockerfile` with `PREBUILT`, so the image trusts the throwaway release key), passes
it to the test in `POSTERN_E2E_NODE_IMAGE` and to the panels in `POSTERN_NODE_IMAGE`, and removes
it at the end, with any `postern-sysctl-*` helper that a killed bootstrap left. Without
`POSTERN_E2E_NODE_IMAGE` (`go test` alone) the test is skipped.

The panel at `http://127.0.0.1:<port>` (loopback, so `http://` is accepted) renders the command
and the compose file, which the test checks word for word, and the test starts the container of
the command through the Docker API with the node's directory of the run in place of
`/opt/postern`, at the same path, and `POSTERN_HOME` saying so. It checks the join (one
`node.join`, the bundle a 409, the identity that the bootstrap wrote), the sysctl helper (the
reserved ports of the host cover 20000-40999), `bin/current` (the binary of the image, the agent's
version), a restart of the container (no new join), and a new token for the same node in a new
container (a second `node.join`, the same node id, a new certificate, and a listener applied
afterwards). It needs no datacenter of Telegram and downloads no telemt (like every test here it
is skipped when GitHub cannot be reached), and takes under a minute. The
sysctl helper changes the reserved ports of the Docker host and writes
`/etc/sysctl.d/90-postern.conf` there, as on a node. Alone:
`bash scripts/e2e.sh -test.run '^TestDockerJoin$'`.
