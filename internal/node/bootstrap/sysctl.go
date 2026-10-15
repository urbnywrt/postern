package bootstrap

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

// The sysctls of install.sh step 7.
const (
	reservedPortsKey = "net.ipv4.ip_local_reserved_ports"
	migrateReqKey    = "net.ipv4.tcp_migrate_req"
	// nodePorts are the loopback ports of the node (install.sh RESERVED_PORTS).
	nodePorts = "20000-40999"
	// sysctlFile is the file of install.sh in /etc/sysctl.d.
	sysctlFile = "90-postern.conf"
	// sysctlMarker, in data/run, is the SHA-256 of the file text that the
	// helper last wrote (or found), so that a restart of the container does
	// not need the helper when nothing changed.
	sysctlMarker = "sysctl-file.sha256"
)

// The helper container that sets the sysctls.
const (
	helperPrefix  = "postern-sysctl-"
	helperMount   = "/host/etc/sysctl.d"
	helperTimeout = 30 * time.Second
	helperPoll    = 250 * time.Millisecond
	pullTimeout   = 5 * time.Minute
	maxHelperLog  = 16 << 10
)

// The exit status of the helper script is a set of bits.
const (
	helperFileFailed   = 1 // the file could not be written
	helperSysctlFailed = 2 // a sysctl -w failed
)

// helperScript writes the file when its text differs (through a temporary
// file and mv) and sets each key with sysctl -w. The values come in the
// environment: CONF the file text (empty: no file), PORTS the reserved ports
// (empty: not set), MIGRATE 1 to set tcp_migrate_req.
const helperScript = `set -u
rc=0
f=` + helperMount + `/` + sysctlFile + `
if [ -n "$CONF" ]; then
  t=` + helperMount + `/.` + sysctlFile + `.new.$$
  if [ -d "$f" ]; then
    echo "/etc/sysctl.d/` + sysctlFile + ` is a directory" >&2
    rc=1
  elif [ -f "$f" ] && [ "$(cat "$f")" = "$CONF" ]; then
    :
  elif (umask 077 && printf '%s\n' "$CONF" > "$t") && chmod 0644 "$t" && mv -f "$t" "$f"; then
    echo "wrote /etc/sysctl.d/` + sysctlFile + `"
  else
    rm -f "$t"
    echo "cannot write /etc/sysctl.d/` + sysctlFile + `" >&2
    rc=1
  fi
fi
if [ -n "$PORTS" ]; then
  sysctl -w "` + reservedPortsKey + `=$PORTS" || rc=$((rc | 2))
fi
if [ "$MIGRATE" = 1 ]; then
  sysctl -w ` + migrateReqKey + `=1 || rc=$((rc | 2))
fi
exit "$rc"
`

// portRange is a range of ports, lo to hi.
type portRange struct{ lo, hi int }

// portListUnion is install.sh port_list_union: the union of lists of ports and
// ranges of ports as net.ipv4.ip_local_reserved_ports has them
// (8080,20000-40999), in order, with the ranges that overlap or touch joined.
// Blanks do not count and an empty list adds nothing; any item that is not a
// port or a range of ports from 0 to 65535 is an error.
func portListUnion(lists ...string) (string, error) {
	var items []portRange
	for _, list := range lists {
		list = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
				return -1
			}
			return r
		}, list)
		if list == "" {
			continue
		}
		for item := range strings.SplitSeq(list, ",") {
			lo, hi, isRange := strings.Cut(item, "-")
			if !isRange {
				hi = lo
			}
			l, okL := portNumber(lo)
			h, okH := portNumber(hi)
			if !okL || !okH || l > h || h > 65535 {
				return "", fmt.Errorf("%q is not a list of ports", list)
			}
			items = append(items, portRange{l, h})
		}
	}
	if len(items) == 0 {
		return "", nil
	}
	slices.SortStableFunc(items, func(a, b portRange) int { return cmp.Compare(a.lo, b.lo) })
	var out []string
	cur := items[0]
	flush := func() {
		if cur.lo == cur.hi {
			out = append(out, strconv.Itoa(cur.lo))
		} else {
			out = append(out, strconv.Itoa(cur.lo)+"-"+strconv.Itoa(cur.hi))
		}
	}
	for _, r := range items[1:] {
		if r.lo <= cur.hi+1 {
			cur.hi = max(cur.hi, r.hi)
			continue
		}
		flush()
		cur = r
	}
	flush()
	return strings.Join(out, ","), nil
}

// portNumber reads 1 to 5 decimal digits.
func portNumber(s string) (int, bool) {
	if len(s) < 1 || len(s) > 5 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// sysctlFileText is the text of /etc/sysctl.d/90-postern.conf without its final
// newline: install.sh reserved_ports_file, with a header that names the
// bootstrap too (ruling N-1).
func sysctlFileText(merged string, migrate bool) string {
	text := `# Written by the Postern node (bootstrap or install.sh), and again by each run of it.
# The loopback ports of the node, ` + nodePorts + `, are reserved: the kernel never
# picks one of them as the local port of an outgoing connection, so the engines and
# the edge always find their ports free. The ports that were reserved already when
# the installer ran are in the list too.
` + reservedPortsKey + ` = ` + merged
	if migrate {
		text += `
# The connections in the accept queue of an edge generation that drains move to
# the generation that takes over, instead of being aborted (Linux 5.14 or later).
` + migrateReqKey + ` = 1`
	}
	return text
}

// sysctlPlan is what the sysctls need.
type sysctlPlan struct {
	ports   string // the merged reserved ports; "" when they cannot be set
	migrate bool   // the kernel has tcp_migrate_req
	text    string // the file text; "" when there is no file to write
	running bool   // the running kernel has the values already
}

// planSysctls reads the running values from procfs; quiet leaves out the
// warnings, which were given already.
func (b *boot) planSysctls(quiet bool) sysctlPlan {
	log := b.log
	if quiet {
		log = slog.New(slog.DiscardHandler)
	}
	procSys := filepath.Join(b.opt.ProcDir, "sys")
	var p sysctlPlan
	portsOK := true
	cur, err := readSmall(filepath.Join(procSys, "net", "ipv4", "ip_local_reserved_ports"), 64<<10)
	if err != nil {
		log.Warn("bootstrap: cannot read "+reservedPortsKey+": the ports "+nodePorts+" are not reserved", "err", err)
	} else if p.ports, err = portListUnion(string(cur), nodePorts); err != nil {
		log.Warn("bootstrap: "+reservedPortsKey+" is not a list of ports: it is left alone, and the ports "+nodePorts+" are not reserved", "err", err)
	} else if now, _ := portListUnion(string(cur)); now != p.ports {
		portsOK = false
	}
	migrate, err := readSmall(filepath.Join(procSys, "net", "ipv4", "tcp_migrate_req"), 64)
	p.migrate = err == nil
	if !p.migrate {
		log.Warn("bootstrap: this kernel has no " + migrateReqKey + " (it came with Linux 5.14): an edge roll may abort the connections still waiting to be accepted")
	}
	p.running = portsOK && (!p.migrate || strings.TrimSpace(string(migrate)) == "1")
	if p.ports != "" {
		p.text = sysctlFileText(p.ports, p.migrate)
	}
	return p
}

func textHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// sysctls sets the sysctls of install.sh step 7 through a short-lived
// privileged helper, when the running kernel or the file need it. Nothing that
// goes wrong stops the node: each failure is a warning.
func (b *boot) sysctls(ctx context.Context) {
	p := b.planSysctls(false)
	marker := b.path("data", "run", sysctlMarker)
	fileKnown := p.text == ""
	if data, err := readSmall(marker, 256); err == nil && p.text != "" && strings.TrimSpace(string(data)) == textHash(p.text) {
		fileKnown = true
	}
	if p.ports == "" && !p.migrate {
		return
	}
	if p.running && fileKnown {
		b.log.Info("bootstrap: the sysctls of the node are set")
		return
	}
	code, out, err := b.runHelper(ctx, p)
	if out != "" {
		b.log.Info("bootstrap: the sysctl helper said: " + strings.ReplaceAll(strings.TrimSpace(out), "\n", "; "))
	}
	if err != nil {
		b.log.Warn("bootstrap: the sysctls of the node are not set (the node works without them; see README.md)", "err", err)
		return
	}
	if p.text != "" {
		if code&helperFileFailed == 0 {
			if err := writeFileAtomic(marker, []byte(textHash(p.text)+"\n"), 0o600); err != nil {
				b.log.Warn("bootstrap: cannot write data/run/"+sysctlMarker, "err", err)
			}
		} else {
			_ = os.Remove(marker)
			b.log.Warn("bootstrap: cannot write /etc/sysctl.d/" + sysctlFile + ": without it the reservation of the ports " + nodePorts + " may not survive a reboot")
		}
	}
	if code&helperSysctlFailed != 0 {
		b.log.Warn("bootstrap: sysctl -w failed in the helper: the ports " + nodePorts + " may not be reserved, or an edge roll may abort connections, until the next boot")
	} else if again := b.planSysctls(true); !again.running {
		b.log.Warn("bootstrap: the sysctls did not take in the running kernel")
	}
}

// runHelper runs the helper once and returns its exit code and output.
func (b *boot) runHelper(ctx context.Context, p sysctlPlan) (code int, out string, err error) {
	d := b.opt.Docker
	b.removeHelpers(ctx)
	if err := b.ensureImage(ctx); err != nil {
		return 0, "", err
	}
	migrate := ""
	if p.migrate {
		migrate = "1"
	}
	name := helperPrefix + randomHex(4)
	spec := dockerapi.ContainerSpec{
		Name:        name,
		Image:       b.opt.RunnerImage,
		User:        "0:0",
		NetworkMode: "host",
		Privileged:  true,
		Entrypoint:  []string{"/bin/sh", "-c", helperScript},
		Env:         []string{"PORTS=" + p.ports, "MIGRATE=" + migrate, "CONF=" + p.text},
		Binds:       []string{"/etc/sysctl.d:" + helperMount},
		Labels:      map[string]string{"postern.managed": "true", "postern.role": "helper"},
		ReadOnly:    true,
		PidsLimit:   64,
	}
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	_, err = d.Create(dctx, spec)
	cancel()
	if err != nil {
		return 0, "", fmt.Errorf("the sysctl helper: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerTimeout)
		defer cancel()
		if err := d.Remove(rctx, name, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			b.log.Warn("bootstrap: cannot remove the sysctl helper", "container", name, "err", err)
		}
	}()
	dctx, cancel = context.WithTimeout(ctx, dockerTimeout)
	err = d.Start(dctx, name)
	cancel()
	if err != nil {
		return 0, "", fmt.Errorf("the sysctl helper: %w", err)
	}
	deadline := b.opt.Now().Add(helperTimeout)
	for {
		dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
		det, err := d.Inspect(dctx, name)
		cancel()
		switch {
		case err != nil:
			return 0, "", fmt.Errorf("the sysctl helper: %w", err)
		case !det.Running && det.State != "created":
			return det.ExitCode, b.helperLog(ctx, name), nil
		case !b.opt.Now().Before(deadline):
			return 0, b.helperLog(ctx, name), fmt.Errorf("the sysctl helper did not end within %s", helperTimeout)
		}
		if err := b.opt.Sleep(ctx, helperPoll); err != nil {
			return 0, "", err
		}
	}
}

// helperLog is the output of the helper, at most maxHelperLog bytes.
func (b *boot) helperLog(ctx context.Context, name string) string {
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	r, err := b.opt.Docker.Logs(dctx, name, -1, false)
	if err != nil {
		return ""
	}
	defer func() { _ = r.Close() }()
	data, _ := io.ReadAll(io.LimitReader(r, maxHelperLog))
	return string(data)
}

// removeHelpers removes the helpers that an earlier bootstrap left behind.
func (b *boot) removeHelpers(ctx context.Context) {
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	list, err := b.opt.Docker.List(dctx, map[string]string{"postern.managed": "true", "postern.role": "helper"}, true)
	if err != nil {
		return
	}
	for _, c := range list {
		if strings.HasPrefix(c.Name, helperPrefix) {
			_ = b.opt.Docker.Remove(dctx, c.ID, true)
		}
	}
}

// ensureImage pulls the runner image when it is missing.
func (b *boot) ensureImage(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	ok, err := b.opt.Docker.ImageExists(dctx, b.opt.RunnerImage)
	cancel()
	if err != nil {
		return fmt.Errorf("the image %s: %w", b.opt.RunnerImage, err)
	}
	if ok {
		return nil
	}
	b.log.Info("bootstrap: pulling " + b.opt.RunnerImage)
	pctx, cancel := context.WithTimeout(ctx, pullTimeout)
	defer cancel()
	if err := b.opt.Docker.Pull(pctx, b.opt.RunnerImage); err != nil {
		return fmt.Errorf("pull %s: %w", b.opt.RunnerImage, err)
	}
	return nil
}
