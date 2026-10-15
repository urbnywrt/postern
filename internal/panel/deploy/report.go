package deploy

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// The severities of an Issue.
const (
	// SeverityBlocker is an issue that the install is refused for.
	SeverityBlocker = "blocker"
	// SeverityWarning is an issue that the admin should know of, and that
	// does not stop the install.
	SeverityWarning = "warning"
)

// The codes of the issues. The UI says each in its own words, with the
// parameters of the issue; the message is the English text for the log and
// for the API.
const (
	IssueNotRoot          = "not_root"
	IssueArchUnsupported  = "arch_unsupported"
	IssueKitMissing       = "kit_missing"
	IssueBashMissing      = "bash_missing"
	IssueDockerMissing    = "docker_missing"
	IssueDockerNotRunning = "docker_not_running"
	IssueComposeMissing   = "compose_missing"
	IssueUsernsRemap      = "userns_remap"
	IssueHTTPSPortTaken   = "https_port_taken"
	IssueMgmtPortTaken    = "mgmt_port_taken"
	IssuePortsUnknown     = "ports_unknown"
	IssueClockSkew        = "clock_skew"
	IssueLowDisk          = "low_disk"
)

// The methods of an install (Report.Method).
const (
	// MethodDocker starts the node with the Docker command of the node image.
	MethodDocker = "docker"
	// MethodKit copies the node kit and the bundle, and runs install.sh.
	MethodKit = "kit"
)

const (
	// httpsPort is the public port of the edge.
	httpsPort = 443

	// maxClockSkew is how far the clock of a server may be off that of the
	// panel before the report warns.
	maxClockSkew = time.Minute

	// minFreeDisk is the free space on /opt below which the report warns: the
	// binaries, the engines and the statistics of a node take a few hundred
	// MB.
	minFreeDisk = 1 << 30

	// installDir is the directory that the files of an install go to. Every
	// command runs as root, through sudo for another user, so it is the
	// directory of root, which only root can change.
	installDir = "/root/postern-install"

	// unknownOwner is the owner of a port when the server does not say who
	// holds it.
	unknownOwner = "an unknown process"
)

// An Issue is something that the preflight found, which blocks the install or
// which the admin should know of.
type Issue struct {
	Code     string
	Severity string // SeverityBlocker or SeverityWarning
	Message  string
	Params   map[string]string
	// FixedByDockerInstall says that installing Docker, when the admin asks
	// for it, mends the issue.
	FixedByDockerInstall bool
}

// A PortCheck says whether a port that the node needs is free.
type PortCheck struct {
	Port    uint16
	Free    bool
	Postern bool   // it is taken, by a container of Postern: a node is installed here already
	Owner   string // who holds it when it is taken and not by Postern
}

// A Report is what the preflight found, and what it means for the install.
type Report struct {
	Facts *Facts
	// Method is how the install goes: MethodDocker or MethodKit.
	Method string
	// InstallDir is the directory that the files of the install go to. It
	// is empty for MethodDocker, which copies no files.
	InstallDir string
	// DialedIP is the address that the panel connected to, when it is a public
	// one, which interfaces behind NAT do not show; it is not valid otherwise.
	DialedIP netip.Addr
	// ClockSkew is how far the clock of the server is ahead of that of the
	// panel (behind when it is negative); 0 when it is not known.
	ClockSkew time.Duration
	HTTPSPort PortCheck
	MgmtPort  PortCheck
	// KitAvailable says whether the panel has the node kit of the
	// architecture of the server.
	KitAvailable bool
	Issues       []Issue
}

// reportInput is what a report is made of.
type reportInput struct {
	facts    *Facts
	dialed   string // the host that the panel connected to
	mgmtPort uint32
	docker   bool                   // the install takes the Docker path (MethodDocker)
	kit      func(arch string) bool // whether the panel has the node kit of arch
	// before and after are the clock of the panel just before the preflight
	// and when it had printed everything.
	before, after time.Time
}

// newReport works out what the facts mean for the install.
func newReport(in reportInput) *Report {
	f := in.facts
	r := &Report{Facts: f, Method: MethodKit, InstallDir: installDir}
	if in.docker {
		// The node image carries the node, and the Docker command needs
		// neither bash nor Compose.
		r.Method, r.InstallDir = MethodDocker, ""
	}
	if a, err := netip.ParseAddr(in.dialed); err == nil && isPublic(a.Unmap()) {
		r.DialedIP = a.Unmap()
	}
	add := func(code, severity, message string, params map[string]string) *Issue {
		r.Issues = append(r.Issues, Issue{Code: code, Severity: severity, Message: message, Params: params})
		return &r.Issues[len(r.Issues)-1]
	}

	if f.UID != 0 {
		add(IssueNotRoot, SeverityBlocker, fmt.Sprintf("the commands of the panel do not run as root on the server (uid %d): "+
			"log in as root, or as a user with passwordless sudo", f.UID), map[string]string{"uid": strconv.Itoa(f.UID)})
	}
	switch {
	case f.Arch == "":
		add(IssueArchUnsupported, SeverityBlocker, fmt.Sprintf("the server is %s, and Postern nodes run on amd64 and arm64 only",
			orUnknown(f.Machine)), map[string]string{"machine": f.Machine})
	case in.kit != nil && in.kit(f.Arch):
		r.KitAvailable = true
	case !in.docker:
		add(IssueKitMissing, SeverityBlocker, fmt.Sprintf("the panel has no node kit for %s: run the panel from its Docker image, "+
			"which carries the kits", f.Arch), map[string]string{"arch": f.Arch})
	}
	if !in.docker && f.BashMajor < 4 {
		add(IssueBashMissing, SeverityBlocker, "bash 4 or newer is not installed, and install.sh needs it (on Alpine: apk add bash)", nil)
	}

	d := f.Docker
	switch {
	case !d.Installed:
		add(IssueDockerMissing, SeverityBlocker, "Docker is not installed", nil).FixedByDockerInstall = true
	case d.Version == "":
		params := map[string]string{"problem": d.Problem}
		if d.Stopped {
			params["stopped"] = "true"
		}
		add(IssueDockerNotRunning, SeverityBlocker, "Docker does not answer: "+d.Problem, params).FixedByDockerInstall = true
	case d.UsernsRemap:
		add(IssueUsernsRemap, SeverityBlocker, `Docker remaps user namespaces (userns-remap), which Postern does not support: `+
			`remove "userns-remap" from /etc/docker/daemon.json and restart Docker`, nil)
	}
	if !in.docker && d.Installed && d.ComposeVersion == "" {
		// The setup of Docker adds the plugin of the packages that the engine
		// comes from, with the package tool that it has for them, and has none
		// for docker.io of Debian or for an engine of no known packages.
		if composeAddable(f) {
			add(IssueComposeMissing, SeverityBlocker, "the Docker Compose v2 plugin is missing", map[string]string{"origin": d.Origin}).FixedByDockerInstall = true
		} else {
			add(IssueComposeMissing, SeverityBlocker, fmt.Sprintf("the Docker Compose v2 plugin is missing, and the panel adds none to this Docker "+
				"(%s): install Docker Compose v2 by hand", orUnknown(d.Origin)), map[string]string{"origin": d.Origin})
		}
	}

	if f.ListenTool == "" {
		add(IssuePortsUnknown, SeverityWarning, "the listening ports of the server could not be read: "+
			"whether 443 and the management port are free is not known", nil)
	}
	// A port that something else holds keeps the node from starting.
	r.HTTPSPort = checkPort(f, httpsPort)
	if !r.HTTPSPort.Free && !r.HTTPSPort.Postern {
		add(IssueHTTPSPortTaken, SeverityBlocker, fmt.Sprintf("port %d is taken by %s", httpsPort, r.HTTPSPort.Owner),
			map[string]string{"port": strconv.Itoa(httpsPort), "owner": r.HTTPSPort.Owner})
	}
	r.MgmtPort = checkPort(f, uint16(in.mgmtPort))
	if !r.MgmtPort.Free && !r.MgmtPort.Postern {
		add(IssueMgmtPortTaken, SeverityBlocker, fmt.Sprintf("the management port %d of the node is taken by %s", in.mgmtPort, r.MgmtPort.Owner),
			map[string]string{"port": strconv.FormatUint(uint64(in.mgmtPort), 10), "owner": r.MgmtPort.Owner})
	}

	if f.Disk != nil && f.Disk.FreeBytes < minFreeDisk {
		add(IssueLowDisk, SeverityWarning, fmt.Sprintf("only %s is free on %s", sizeText(f.Disk.FreeBytes), f.DiskPath),
			map[string]string{"free_bytes": strconv.FormatUint(f.Disk.FreeBytes, 10), "path": f.DiskPath})
	}

	if !f.RemoteTime.IsZero() && !in.before.IsZero() && !in.after.Before(in.before) {
		// The script read the clock at some moment between before and after,
		// and to the second.
		mid := in.before.Add(in.after.Sub(in.before) / 2)
		r.ClockSkew = f.RemoteTime.Sub(mid).Round(time.Second)
		lo := f.RemoteTime.Sub(in.after) - time.Second
		hi := f.RemoteTime.Sub(in.before) + time.Second
		var skew time.Duration
		switch {
		case lo > maxClockSkew:
			skew = lo
		case hi < -maxClockSkew:
			skew = hi
		}
		if skew != 0 {
			way := "ahead of"
			if skew < 0 {
				way = "behind"
			}
			add(IssueClockSkew, SeverityWarning, fmt.Sprintf("the clock of the server is at least %s %s the clock of the panel: "+
				"keep it in sync (NTP)", abs(skew).Round(time.Second), way),
				map[string]string{"seconds": strconv.FormatInt(int64(skew/time.Second), 10)})
		}
	}
	return r
}

// Blockers returns the issues that the install is refused for. With
// installDocker, those that installing Docker mends are left out.
func (r *Report) Blockers(installDocker bool) []Issue {
	var out []Issue
	for _, is := range r.Issues {
		if is.Severity == SeverityBlocker && (!installDocker || !is.FixedByDockerInstall) {
			out = append(out, is)
		}
	}
	return out
}

// NeedsDocker reports whether the server lacks Docker, a running daemon or
// Compose, which installing Docker mends.
func (r *Report) NeedsDocker() bool {
	return slices.ContainsFunc(r.Issues, func(is Issue) bool { return is.FixedByDockerInstall })
}

// composeAddable reports whether the setup of Docker (install_docker.sh) adds
// the Compose v2 plugin to the Docker of the server: one of the packages that
// it knows, with the package tool that it uses for them. docker-ce on a server
// with zypper or pacman only, or docker.io of Debian, gets none.
func composeAddable(f *Facts) bool {
	has := func(tools ...string) bool {
		return slices.ContainsFunc(tools, func(t string) bool { return slices.Contains(f.PackageTools, t) })
	}
	switch f.Docker.Origin {
	case "docker-ce":
		return has("apt-get", "dnf", "yum")
	case "docker.io":
		return f.OS.ID == "ubuntu" && has("apt-get")
	case "alpine":
		return has("apk")
	}
	return false
}

// checkPort says who holds port on the server: nobody, Postern, or someone
// else, and who.
func checkPort(f *Facts, port uint16) PortCheck {
	c := PortCheck{Port: port, Free: true, Postern: true}
	postern := map[string]bool{}
	names := map[string]string{}
	for _, ct := range f.Containers {
		postern[ct.ID] = ct.Postern
		names[ct.ID] = ct.Name
	}
	for _, l := range f.Listeners {
		if l.Port != port {
			continue
		}
		c.Free = false
		ours := len(l.Processes) > 0
		for _, p := range l.Processes {
			if !postern[f.ContainerOf[p.PID]] {
				ours = false
			}
		}
		if !ours {
			c.Postern = false
			if c.Owner == "" {
				c.Owner = describeOwner(l, f.ContainerOf, names)
			}
		}
	}
	if c.Free || c.Postern {
		c.Postern = !c.Free
	}
	return c
}

// isPublic reports whether the internet can reach a: a global unicast address
// that is not private and not carrier-grade NAT.
func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// describeOwner names who holds a listening socket: its first process, and
// its container when it runs in one.
func describeOwner(l Listener, containerOf map[int]string, names map[string]string) string {
	if len(l.Processes) == 0 {
		return unknownOwner
	}
	p := l.Processes[0]
	name := orUnknown(p.Name)
	if c := names[containerOf[p.PID]]; c != "" {
		return fmt.Sprintf("%s (pid %d, container %s)", name, p.PID, c)
	}
	return fmt.Sprintf("%s (pid %d)", name, p.PID)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// sizeText writes a number of bytes for people: "1.5 GiB", "512 MiB", "10 KiB".
func sizeText(n uint64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GiB"
	case n >= 1<<20:
		return strconv.FormatUint(n>>20, 10) + " MiB"
	case n >= 1<<10:
		return strconv.FormatUint(n>>10, 10) + " KiB"
	}
	return strconv.FormatUint(n, 10) + " bytes"
}
