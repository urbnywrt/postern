package deploy

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// hostFacts returns a copy of the facts of a fake server of the preflight
// tests, to change for a case.
func hostFacts(t *testing.T, host string) *Facts {
	t.Helper()
	for _, h := range preflightHosts {
		if h.host == host {
			f := h.want
			f.Listeners = slices.Clone(f.Listeners)
			return &f
		}
	}
	t.Fatalf("no fake server %s", host)
	return nil
}

func kits(arches ...string) func(string) bool {
	return func(arch string) bool { return slices.Contains(arches, arch) }
}

// issueList is the issues as "code/severity", with a + for those that
// installing Docker mends.
func issueList(r *Report) []string {
	var out []string
	for _, is := range r.Issues {
		s := is.Code + "/" + is.Severity
		if is.FixedByDockerInstall {
			s += "+"
		}
		out = append(out, s)
	}
	return out
}

func TestReport(t *testing.T) {
	remote := time.Unix(1791200000, 0)
	shopNginx := "nginx (pid 4120, container shop-nginx)"
	tests := []struct {
		name     string
		host     string
		change   func(*Facts)
		mgmtPort uint32
		kit      func(string) bool
		want     []string
		https    PortCheck
		mgmt     PortCheck
	}{
		{name: "a fresh server", host: "ubuntu-24.04", mgmtPort: 61001,
			https: PortCheck{Port: 443, Free: true}, mgmt: PortCheck{Port: 61001, Free: true}},
		{name: "a node that is installed again", host: "debian-12", mgmtPort: 61443,
			https: PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "busybox without bash and Docker, and no kit of its architecture", host: "alpine-3.22", mgmtPort: 61001,
			kit:   kits("amd64"),
			want:  []string{"kit_missing/blocker", "bash_missing/blocker", "docker_missing/blocker+"},
			https: PortCheck{Port: 443, Free: true}, mgmt: PortCheck{Port: 61001, Free: true}},
		{name: "nginx on 443 and Docker stopped", host: "alpine-3.22-ss", mgmtPort: 61001,
			want:  []string{"docker_not_running/blocker+", "https_port_taken/blocker", "low_disk/warning"},
			https: PortCheck{Port: 443, Owner: "nginx (pid 2101)"}, mgmt: PortCheck{Port: 61001, Free: true}},
		{name: "443 taken by the containers of another stack", host: "containers", mgmtPort: 61001,
			want:  []string{"https_port_taken/blocker"},
			https: PortCheck{Port: 443, Owner: shopNginx}, mgmt: PortCheck{Port: 61001, Free: true}},
		{name: "a management port taken by the containers of another stack", host: "containers", mgmtPort: 8088,
			want:  []string{"https_port_taken/blocker", "mgmt_port_taken/blocker"},
			https: PortCheck{Port: 443, Owner: shopNginx}, mgmt: PortCheck{Port: 8088, Owner: shopNginx}},
		{name: "a management port taken by a process of the host", host: "containers", mgmtPort: 8443,
			want:  []string{"https_port_taken/blocker", "mgmt_port_taken/blocker"},
			https: PortCheck{Port: 443, Owner: shopNginx}, mgmt: PortCheck{Port: 8443, Owner: "docker-proxy (pid 3900)"}},
		{name: "userns-remap, and ports whose owners the kernel does not name", host: "userns", mgmtPort: 61635,
			want:  []string{"userns_remap/blocker", "https_port_taken/blocker", "mgmt_port_taken/blocker"},
			https: PortCheck{Port: 443, Owner: unknownOwner}, mgmt: PortCheck{Port: 61635, Owner: unknownOwner}},
		{name: "a port taken by a container that is not Postern's", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) {
				f.Containers = slices.Clone(f.Containers)
				f.Containers[0].Postern = false
				f.Containers[0].Name = "caddy"
			},
			want:  []string{"https_port_taken/blocker"},
			https: PortCheck{Port: 443, Owner: "postern-node (pid 3311, container caddy)"}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "not root", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.UID = 1000 },
			want:   []string{"not_root/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "another architecture", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Machine, f.Arch = "riscv64", "" },
			want:   []string{"arch_unsupported/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker-ce", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion = "" },
			want:   []string{"compose_missing/blocker+"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker-ce of an RPM system with dnf", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.PackageTools = "", []string{"dnf"} },
			want:   []string{"compose_missing/blocker+"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker-ce of a system with zypper, which the panel does not mend", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.PackageTools = "", []string{"zypper"} },
			want:   []string{"compose_missing/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker-ce of a system with pacman, which the panel does not mend", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.PackageTools = "", []string{"pacman"} },
			want:   []string{"compose_missing/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker.io of Ubuntu without apt-get", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) {
				f.Docker.ComposeVersion, f.Docker.Origin, f.OS.ID, f.PackageTools = "", "docker.io", "ubuntu", nil
			},
			want:  []string{"compose_missing/blocker"},
			https: PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker.io of Ubuntu", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.Docker.Origin, f.OS.ID = "", "docker.io", "ubuntu" },
			want:   []string{"compose_missing/blocker+"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with docker.io of Debian, which the panel does not mend", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.Docker.Origin = "", "docker.io" },
			want:   []string{"compose_missing/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "no Compose with Docker of no known packages", host: "debian-12", mgmtPort: 61443,
			change: func(f *Facts) { f.Docker.ComposeVersion, f.Docker.Origin = "", "" },
			want:   []string{"compose_missing/blocker"},
			https:  PortCheck{Port: 443, Postern: true}, mgmt: PortCheck{Port: 61443, Postern: true}},
		{name: "ports that could not be read", host: "ubuntu-24.04", mgmtPort: 61001,
			change: func(f *Facts) { f.ListenTool, f.Listeners = "", nil },
			want:   []string{"ports_unknown/warning"},
			https:  PortCheck{Port: 443, Free: true}, mgmt: PortCheck{Port: 61001, Free: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := hostFacts(t, tt.host)
			if tt.change != nil {
				tt.change(f)
			}
			kit := tt.kit
			if kit == nil {
				kit = kits("amd64", "arm64")
			}
			r := newReport(reportInput{facts: f, mgmtPort: tt.mgmtPort, kit: kit,
				before: remote.Add(-time.Second), after: remote.Add(time.Second)})
			if got := issueList(r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("issues = %q, want %q", got, tt.want)
			}
			// Every command of an install runs as root, also through sudo.
			if r.InstallDir != "/root/postern-install" {
				t.Errorf("InstallDir = %q, want /root/postern-install", r.InstallDir)
			}
			if r.HTTPSPort != tt.https {
				t.Errorf("HTTPSPort = %+v, want %+v", r.HTTPSPort, tt.https)
			}
			if r.MgmtPort != tt.mgmt {
				t.Errorf("MgmtPort = %+v, want %+v", r.MgmtPort, tt.mgmt)
			}
			for _, is := range r.Issues {
				if is.Message == "" {
					t.Errorf("%s has no message", is.Code)
				}
			}
		})
	}
}

// The address that the panel connected to is a public address of the server,
// when it is one, also when no interface has it (1:1 NAT).
func TestReportDialedAddress(t *testing.T) {
	for _, tt := range []struct {
		dialed string
		want   string
	}{
		{"198.51.100.77", "198.51.100.77"},
		{"203.0.113.10", "203.0.113.10"},
		{"2001:db8::99", "2001:db8::99"},
		{"127.0.0.1", ""},
		{"10.0.0.5", ""},
		{"proxy.example.com", ""},
	} {
		r := newReport(reportInput{facts: hostFacts(t, "ubuntu-24.04"), mgmtPort: 61001, kit: kits("amd64"), dialed: tt.dialed})
		got := ""
		if r.DialedIP.IsValid() {
			got = r.DialedIP.String()
		}
		if got != tt.want {
			t.Errorf("dialed %q: DialedIP = %q, want %q", tt.dialed, got, tt.want)
		}
		p := reportProto(r)
		if p.GetDialedIp() != tt.want {
			t.Errorf("dialed %q: dialed_ip = %q, want %q", tt.dialed, p.GetDialedIp(), tt.want)
		}
		if tt.want != "" && !slices.Contains(p.GetPublicIps(), tt.want) {
			t.Errorf("dialed %q: public_ips %q do not have it", tt.dialed, p.GetPublicIps())
		}
		if n := len(p.GetPublicIps()); tt.want == "203.0.113.10" && n != 2 {
			t.Errorf("an address of an interface that the panel dialed shows %d times in %q", n, p.GetPublicIps())
		}
	}
}

// The issues name what the UI shows with them.
func TestReportParams(t *testing.T) {
	r := newReport(reportInput{facts: hostFacts(t, "containers"), mgmtPort: 61001, kit: kits("amd64")})
	byCode := map[string]Issue{}
	for _, is := range r.Issues {
		byCode[is.Code] = is
	}
	if got := byCode[IssueHTTPSPortTaken].Params; got["port"] != "443" || got["owner"] != "nginx (pid 4120, container shop-nginx)" {
		t.Errorf("https_port_taken params = %v", got)
	}
	low := newReport(reportInput{facts: hostFacts(t, "alpine-3.22-ss"), mgmtPort: 61001, kit: kits("amd64")})
	for _, is := range low.Issues {
		if is.Code == IssueLowDisk && (is.Params["free_bytes"] != "644520960" || is.Params["path"] != "/opt" || !strings.Contains(is.Message, "614 MiB")) {
			t.Errorf("low_disk = %+v", is)
		}
		// A daemon that does not run is named so, for the UI to say it in its
		// own words; one that does not answer, with what docker said.
		if is.Code == IssueDockerNotRunning && (is.Params["stopped"] != "true" || is.Message != "Docker does not answer: "+dockerStopped) {
			t.Errorf("docker_not_running of a stopped daemon = %+v", is)
		}
	}
	f := hostFacts(t, "debian-12")
	f.Docker.Version, f.Docker.Problem = "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
	for _, is := range newReport(reportInput{facts: f, mgmtPort: 61443, kit: kits("amd64")}).Issues {
		if is.Code == IssueDockerNotRunning && (is.Params["stopped"] != "" || is.Params["problem"] != f.Docker.Problem) {
			t.Errorf("docker_not_running of a daemon that does not answer = %+v", is)
		}
	}
}

func TestReportBlockers(t *testing.T) {
	r := newReport(reportInput{facts: hostFacts(t, "alpine-3.22-ss"), mgmtPort: 61001, kit: kits("amd64")})
	codes := func(list []Issue) []string {
		var out []string
		for _, is := range list {
			out = append(out, is.Code)
		}
		return out
	}
	if got := codes(r.Blockers(false)); !reflect.DeepEqual(got, []string{IssueDockerNotRunning, IssueHTTPSPortTaken}) {
		t.Errorf("Blockers(false) = %q", got)
	}
	if got := codes(r.Blockers(true)); !reflect.DeepEqual(got, []string{IssueHTTPSPortTaken}) {
		t.Errorf("Blockers(true) = %q", got)
	}
	if !r.NeedsDocker() {
		t.Error("NeedsDocker = false for a server whose Docker does not answer")
	}
	ok := newReport(reportInput{facts: hostFacts(t, "debian-12"), mgmtPort: 61443, kit: kits("amd64")})
	if ok.NeedsDocker() || len(ok.Blockers(false)) != 0 || !ok.KitAvailable {
		t.Errorf("a server ready for the install: NeedsDocker %v, blockers %v, kit %v", ok.NeedsDocker(), ok.Blockers(false), ok.KitAvailable)
	}
}

// The clock of the server is read at some moment of the preflight: it is only
// off when it is off whenever it was read.
func TestReportClockSkew(t *testing.T) {
	remote := time.Unix(1791200000, 0)
	tests := []struct {
		name          string
		before, after time.Time
		wantSkew      time.Duration
		wantWarning   string // the seconds of the warning, "" for none
	}{
		{"in sync", remote.Add(-2 * time.Second), remote.Add(2 * time.Second), 0, ""},
		{"ahead", remote.Add(-300 * time.Second), remote.Add(-298 * time.Second), 299 * time.Second, "297"},
		{"behind", remote.Add(119 * time.Second), remote.Add(121 * time.Second), -120 * time.Second, "-118"},
		{"a preflight too slow to tell", remote.Add(-100 * time.Second), remote.Add(50 * time.Second), 25 * time.Second, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReport(reportInput{facts: hostFacts(t, "debian-12"), mgmtPort: 61443, kit: kits("amd64"),
				before: tt.before, after: tt.after})
			if r.ClockSkew != tt.wantSkew {
				t.Errorf("ClockSkew = %v, want %v", r.ClockSkew, tt.wantSkew)
			}
			got := ""
			for _, is := range r.Issues {
				if is.Code == IssueClockSkew {
					got = is.Params["seconds"]
				}
			}
			if got != tt.wantWarning {
				t.Errorf("clock warning = %q, want %q (issues %q)", got, tt.wantWarning, issueList(r))
			}
		})
	}
	unknown := hostFacts(t, "debian-12")
	unknown.RemoteTime = time.Time{}
	if r := newReport(reportInput{facts: unknown, mgmtPort: 61443, kit: kits("amd64"), before: remote, after: remote}); r.ClockSkew != 0 {
		t.Errorf("ClockSkew of a server whose clock is not known = %v, want 0", r.ClockSkew)
	}
}

// The Docker path needs no node kit, no bash and no Compose: those are no
// issues there; an architecture without a node image still blocks it, and
// the rest is as on the kit path.
func TestReportOfTheDockerPath(t *testing.T) {
	for _, tt := range []struct {
		name   string
		host   string
		change func(*Facts)
		want   []string
	}{
		{name: "busybox without bash and Docker, and no kit of its architecture", host: "alpine-3.22",
			want: []string{"docker_missing/blocker+"}},
		{name: "no Compose with docker.io of Debian", host: "debian-12",
			change: func(f *Facts) { f.Docker.ComposeVersion, f.Docker.Origin = "", "docker.io" }},
		{name: "another architecture", host: "debian-12",
			change: func(f *Facts) { f.Machine, f.Arch = "riscv64", "" },
			want:   []string{"arch_unsupported/blocker"}},
		{name: "nginx on 443 and Docker stopped", host: "alpine-3.22-ss",
			want: []string{"docker_not_running/blocker+", "https_port_taken/blocker", "low_disk/warning"}},
		{name: "userns-remap", host: "userns",
			want: []string{"userns_remap/blocker", "https_port_taken/blocker"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := hostFacts(t, tt.host)
			if tt.change != nil {
				tt.change(f)
			}
			r := newReport(reportInput{facts: f, mgmtPort: 61001, kit: kits(), docker: true})
			if got := issueList(r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("issues = %q, want %q", got, tt.want)
			}
			if r.Method != MethodDocker || r.InstallDir != "" {
				t.Errorf("Method %q, InstallDir %q; want docker and none", r.Method, r.InstallDir)
			}
		})
	}
	if r := newReport(reportInput{facts: hostFacts(t, "debian-12"), mgmtPort: 61443, kit: kits("amd64")}); r.Method != MethodKit {
		t.Errorf("Method = %q, want kit", r.Method)
	}
}
