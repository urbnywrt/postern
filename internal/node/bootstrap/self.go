package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

// dockerTimeout bounds one short call to the daemon.
const dockerTimeout = 15 * time.Second

// dockerSocket is where the agent finds the daemon (dockerapi.DefaultSocket).
const dockerSocket = dockerapi.DefaultSocket

// errUserns is the refusal for a daemon that remaps user namespaces: the agent
// writes root-owned files that the edge and the engines must read as root.
var errUserns = errors.New("bootstrap: Docker remaps user namespaces; the node needs a daemon without userns-remap")

// checkEnvironment checks what the node needs of its container (facts §2.4,
// §3 step 1, Risks 2, 3, 15).
func (b *boot) checkEnvironment(ctx context.Context) error {
	if b.opt.Getuid() != 0 {
		return errors.New("bootstrap: the node runs as root (the edge and the node's files need it); start the container without --user")
	}
	home := b.opt.Home
	if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return fmt.Errorf("bootstrap: %s must be a clean absolute path", EnvHome)
	}
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	_, err := b.opt.Docker.Ping(dctx)
	cancel()
	if err != nil {
		return fmt.Errorf("bootstrap: Docker does not answer at %s (start the container with -v %s:%s): %w", dockerSocket, dockerSocket, dockerSocket, err)
	}
	dctx, cancel = context.WithTimeout(ctx, dockerTimeout)
	info, err := b.opt.Docker.Info(dctx)
	cancel()
	if err != nil {
		return fmt.Errorf("bootstrap: Docker's system information: %w", err)
	}
	for _, o := range info.SecurityOptions {
		if strings.Contains(o, "name=userns") {
			return errUserns
		}
	}
	return b.checkOwnContainer(ctx)
}

// containerIDRe finds the container's ID in the paths of its own mounts
// (/var/lib/docker/containers/<id>/hostname, resolv.conf, hosts).
var containerIDRe = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// ownContainerID is the ID of the container the process runs in, from
// /proc/self/mountinfo; "" when it cannot be told.
func (b *boot) ownContainerID() string {
	data, err := os.ReadFile(filepath.Join(b.opt.ProcDir, "self", "mountinfo"))
	if err != nil {
		return ""
	}
	if m := containerIDRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// checkOwnContainer inspects the container the bootstrap runs in. POSTERN_HOME
// must come from the same path on the host, because the agent hands host paths
// to Docker for the edge; the Docker socket must be there; and self-update
// needs a restart policy, as it restarts the agent by exiting. A container
// that cannot be found is a warning: the checks are left out.
func (b *boot) checkOwnContainer(ctx context.Context) error {
	id := b.ownContainerID()
	if id == "" {
		b.log.Warn("bootstrap: cannot find the own container in /proc/self/mountinfo; its mounts are not checked")
		return nil
	}
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	d, err := b.opt.Docker.Inspect(dctx, id)
	cancel()
	if err != nil {
		b.log.Warn("bootstrap: cannot inspect the own container; its mounts are not checked", "container", id[:12], "err", err)
		return nil
	}
	home := b.opt.Home
	same := fmt.Sprintf("-v %s:%s", home, home)
	var homeMount *dockerapi.MountPoint
	socket := false
	for i, m := range d.Mounts {
		switch dst := path.Clean(m.Destination); dst {
		case home:
			homeMount = &d.Mounts[i]
		case dockerSocket, "/run/docker.sock", "/var/run", "/run":
			socket = true
		}
	}
	switch {
	case homeMount == nil:
		return fmt.Errorf("bootstrap: %s is not mounted from the host: start the container with %s", home, same)
	case path.Clean(homeMount.Source) != home:
		return fmt.Errorf("bootstrap: %s comes from %s on the host; the agent hands host paths to Docker for the edge, so the path must be the same: start the container with %s",
			home, homeMount.Source, same)
	case !homeMount.RW:
		return fmt.Errorf("bootstrap: %s is mounted read-only: start the container with %s", home, same)
	}
	if !socket {
		b.log.Warn("bootstrap: the Docker socket is not mounted at " + dockerSocket + "; the agent looks for it there (-v " + dockerSocket + ":" + dockerSocket + ")")
	}
	if p := d.RestartPolicy; p != "unless-stopped" && p != "always" {
		b.log.Warn("bootstrap: the container has no restart policy; self-update restarts the agent by exiting, so start it with --restart unless-stopped", "policy", p)
	}
	return nil
}
