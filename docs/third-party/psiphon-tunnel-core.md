# psiphon-tunnel-core (Psiphon egresses)

Postern runs the egresses of kind `psiphon` on Psiphon's own client, the ConsoleClient of
[psiphon-tunnel-core](https://github.com/Psiphon-Labs/psiphon-tunnel-core), as a separate
program in a container of the node (`internal/providers/psiphoncore`). Postern does not link it
or include its code in its own programs: the agent writes a configuration file, starts the
binary, and uses the SOCKS5 port that the client opens on the loopback. Postern itself stays
under its own licence (AGPL-3.0).

## Licence

psiphon-tunnel-core is licensed under the **GNU General Public License v3.0** (GPL-3.0):
<https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/LICENSE>.

## The binary that Postern ships

Each release of Postern builds the client itself (Ruling S2-26) and ships it, signed by the
release key, as `psiphon-core-linux-amd64` and `psiphon-core-linux-arm64`
(`scripts/psiphon-core.sh`, run by `scripts/release.sh build`). Psiphon's own prebuilt binary
(`Psiphon-Labs/psiphon-tunnel-core-binaries`) is not used: it is UPX-packed and, unpacked, a
dynamically linked glibc program, which the runner image of the nodes cannot run, and there is
none for arm64.

| | |
|---|---|
| Upstream commit | `c4a09096ab401b57f52e092c8f2f829c8fac7628` (2026-10-05) |
| Source archive | `https://codeload.github.com/Psiphon-Labs/psiphon-tunnel-core/tar.gz/<commit>`, SHA-256 `35522b4b5e8b39acfaad6fcc5a98b5164cea9eb8ae5a6e5c691270b87f42dd0f` |
| Toolchain | `go1.26.8`, the toolchain of its go.mod (its psiphon-tls needs that Go exactly) |
| Build | `./ConsoleClient`, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-mod=vendor` after `go mod verify`, `-ldflags "-s -w -buildid=` and the build information of upstream's make.bash`"` |
| Version in Postern | `20261005-c4a09096ab` |
| SHA-256, linux/amd64 | `c1767915e1773bd812b64238377de262b135d9aafe097b24e09190ff6e4b0b33` |
| SHA-256, linux/arm64 | `eadefe0c157bd6645420e5d63b124e50de223a76206eda788165505555f6b1f8` |

The build is reproducible: the panel pins those SHA-256s (`internal/panel/releases/builtin.json`)
and the release tool refuses a build with other bytes (`check-build`). The panel takes the
files from the release of Postern that it is, on its release source, and checks the pin, the
signature, that each is a static program that is not packed, and the node tries it out before
it runs it. The pins are in `scripts/psiphon-core.env`; a new upstream commit is a new version
with new pins. A panel that is no published release (a dev build) or cannot reach its release
source (air-gapped) takes the two files with their `.minisig` as a release upload instead, with
the same checks ([releasing.md](../releasing.md#a-private-gitea)).

## Source offer

The corresponding source of the binaries is psiphon-tunnel-core at the commit above, with its
vendored modules: <https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/c4a09096ab401b57f52e092c8f2f829c8fac7628>
(the archive above, whose SHA-256 the build checks), and the build script
`scripts/psiphon-core.sh` of the Postern release that shipped them. Whoever distributes the
binaries (a release, an image, a mirror) passes on the GPL-3.0 and that source. On request, the
maintainers of Postern, and the operator of an installation that distributes the binaries, provide
that source on the same terms, for at least three years after the last release that shipped them.

## Network

A Psiphon egress resolves names only through the node's DNS: in DNS mode `doh` (the default)
that is the DNS-over-HTTPS forwarder of the edge, so no DNS query of Psiphon leaves the node over
UDP. Psiphon's tunnel, though, is its own: among the protocols that psiphon-tunnel-core tries are
some that run over UDP to port 53 of Psiphon's servers. Those datagrams are not DNS, but a
firewall that judges by the port sees UDP/53 to an address that is no resolver. A node that drops
UDP to port 53 (`iptables -I OUTPUT ! -o lo -p udp --dport 53 -j DROP`, as production nodes do)
loses nothing: the datagrams are dropped and Psiphon falls back to another protocol at once.

## Configuration

A client without a Psiphon partner agreement uses the ids `FFFFFFFFFFFFFFFF` and the public
remote server list with its signature key, as warp-plus (`psiphon/p.go`) and Oblivion do. No
statement from Psiphon allows this use, and Psiphon may withdraw it. An operator with partner ids
sets them on the egress (propagation channel id and sponsor id). Psiphon egresses stay marked
experimental.
