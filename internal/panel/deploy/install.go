package deploy

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/sshx"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// dockerScript sets up Docker: it starts an installed Docker, adds the Compose
// v2 plugin to it, or installs Docker where there is none, and never replaces
// an engine; see the comment at its top.
//
//go:embed install_docker.sh
var dockerScript string

const (
	// bundleFileName is the name of the bundle in the directory of the
	// install, which install.sh is given.
	bundleFileName = "postern-node-bundle.tar"
	// binaryName is the name of the node binary in the kit and in the
	// directory of the install.
	binaryName = "postern-node"
)

// wrapped is a command that runs child, a command line, in the background and
// waits for it, passing TERM and HUP on to it: sshx stops a command with TERM
// to the shell that runs it, which would end at once and leave the child
// running unaware. The wrapper exits with the status of the child. prelude
// runs first; cleanup, shell without single quotes, runs when the wrapper
// exits, also after a signal. The first line, "# postern: <marker>", names
// the command.
//
// A child that dash or the ash of busybox has just forked starts with the
// traps of the wrapper, and a signal that reaches it before it has put them
// back is noted and then forgotten: the child would run on, and the wrapper
// wait for it for ever. So the wrapper sends a signal again, a tenth of a
// second apart, for as long as the child is there, at most 20 times. Its
// children, install.sh and the setup of Docker, do not trap TERM or HUP, and
// end on the first one that they get.
func wrapped(marker, prelude, child, cleanup string) string {
	var b strings.Builder
	b.WriteString("# postern: " + marker + "\n")
	b.WriteString(prelude)
	if cleanup != "" {
		b.WriteString("trap '" + cleanup + "' EXIT\n")
	}
	b.WriteString(`child=
stopping=
signals=0
forward() {
  stopping=$1
  signals=$((signals + 1))
  if [ -z "$child" ]; then
    return 0
  fi
  f_sent=0
  while [ "$f_sent" -lt 20 ] && kill -s "$1" "$child" 2> /dev/null; do
    f_sent=$((f_sent + 1))
    sleep 0.1 2> /dev/null || sleep 1
  done
}
trap 'forward TERM' TERM
trap 'forward HUP' HUP
case $stopping in
  TERM) rc=143 ;;
  HUP) rc=129 ;;
  *)
    ` + child + ` &
    child=$!
    if [ -n "$stopping" ]; then
      forward "$stopping"
    fi
    # wait returns early, above 128, when a signal comes: the child is waited
    # for again, until wait gives its status. One whose status came already,
    # as a signal came, is not known to wait any more (127).
    rc=
    while :; do
      seen=$signals
      wait "$child"
      st=$?
      if [ -n "$rc" ] && [ "$st" = 127 ]; then
        break
      fi
      rc=$st
      if [ "$st" -le 128 ] || [ "$signals" = "$seen" ]; then
        break
      fi
    done
    ;;
esac
exit "$rc"
`)
	return b.String()
}

// installCommand runs install.sh in the directory of the install, under a
// wrapper that removes the bundle when install.sh ends, also when it is
// stopped, and says so when it cannot.
func installCommand(dir string) string {
	return wrapped("install",
		"cd "+dir+" || exit 1\nb="+dir+"/"+bundleFileName+"\n",
		"bash install.sh --bundle "+bundleFileName+" --binary ./"+binaryName,
		`rm -f -- "$b"; if [ -e "$b" ]; then echo "postern: $b could not be removed" >&2; fi`)
}

// dockerCommand sets up Docker (dockerSetupCommand) under the wrapper, with
// the Compose v2 plugin when needCompose says so.
func dockerCommand(needCompose bool) string {
	return wrapped("docker", "s="+shellQuote(dockerSetupCommand("", needCompose))+"\n", `sh -c "$s"`, "")
}

// agentContainer is the name of the container of the agent.
const agentContainer = "postern-agent"

// removeAgentCommand removes the container of the agent of an earlier install,
// when there is one, so that the Docker command can start a new one under its
// name. What else an earlier install left in /opt/postern stays, the compose
// file of a kit install and the certificate of the node too: the new join
// token makes the node join again.
const removeAgentCommand = "# postern: remove-agent\n" +
	"if docker container inspect " + agentContainer + " > /dev/null 2>&1; then\n" +
	"  docker rm -f " + agentContainer + "\n" +
	"else\n" +
	"  echo 'there is no container " + agentContainer + "'\n" +
	"fi"

// pullCommand pulls the node image under the wrapper: a pull takes time, and
// a cancelled job stops it.
func pullCommand(image string) string {
	return wrapped("pull", "", "docker pull "+shellQuote(image), "")
}

// imageThereCommand succeeds when the node image is on the server already.
func imageThereCommand(image string) string {
	return "docker image inspect " + shellQuote(image) + " > /dev/null"
}

// startCommand runs the Docker command that starts the node, as
// nodes.RenderDockerCommand renders it, under the wrapper: the pull of the
// image takes time, and a cancelled job stops it.
func startCommand(dockerRun string) string {
	return wrapped("start", "", dockerRun, "")
}

// removeBundleCommand removes the bundle from the server, as the wrapper of
// install.sh does, and fails when it is still there.
func removeBundleCommand(path string) string {
	return "rm -f -- " + path + "; [ ! -e " + path + " ]"
}

// mkdirCommand makes the directory of the install, which only uid u can read
// (0, root, but for the tests), and removes what an earlier install may have
// left there of a bundle, which holds the private key of a node: the
// temporary files of an upload that was cut off, and a bundle that could not
// be removed. It refuses a path that is a link or a file, and a directory that
// another user owns: the files that go there run as root.
func mkdirCommand(dir string, uid int) string {
	return "# postern: mkdir\nd=" + dir + "\nu=" + strconv.Itoa(uid) + "\n" + `if [ -L "$d" ] || { [ -e "$d" ] && [ ! -d "$d" ]; }; then
  echo "$d is there and is not a directory" >&2
  exit 1
fi
if [ -d "$d" ]; then
  owner=$(ls -nd "$d" | awk '{ print $3 }')
  if [ "$owner" != "$u" ]; then
    echo "$d belongs to uid $owner, not to $u: remove it, and install again" >&2
    exit 1
  fi
fi
mkdir -p "$d" && chmod 0700 "$d" && rm -f -- "$d"/.` + bundleFileName + `.tmp-* "$d"/` + bundleFileName
}

// install is one install of a node: the function of its job.
type install struct {
	s       *Service
	adminID string // the admin who started it
	node    *store.Node
	target  sshx.Target      // with the host key to check the server against
	auth    sshx.Auth        // the credentials
	stored  *store.SSHTarget // the target that the panel kept before; nil for none
	bundle  []byte           // the tar of the bundle, which holds the private key of the node; nil on the Docker path

	// panelURL, checked, is the address that the node joins the panel at
	// on the Docker path, with image, the node image; both are empty on the
	// kit path.
	panelURL, image string

	installDocker, remember bool
}

// docker reports whether the install takes the Docker path.
func (in *install) docker() bool { return in.panelURL != "" }

// progress writes the lines of the log of a job that say what the job does.
type progress struct{ w io.Writer }

func (p progress) step(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "==> "+format+"\n", args...)
}

func (p progress) note(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "    "+format+"\n", args...)
}

// run is the function of the job. The bundle is not cleared when it is done:
// the SSH client copies the input of a command in a goroutine of its own, which
// can read it after a failed upload has returned.
func (in *install) run(ctx context.Context, w io.Writer) (err error) {
	log := progress{w}
	t := in.target
	log.step("Connecting to %s@%s", t.User, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
	client, hk, err := sshx.Dial(ctx, t, in.auth)
	if err != nil {
		return fmt.Errorf("could not log in to the server: %w", err)
	}
	defer func() { _ = client.Close() }()
	log.note("the host key is %s (%s), as confirmed", hk.Fingerprint, hk.KeyType)
	t.HostKeyType = hk.KeyType
	if err := in.s.saveTarget(ctx, in.node.ID, t, in.stored, &keepCredentials{auth: in.auth, remember: in.remember}); err != nil {
		return fmt.Errorf("could not store how the panel reaches the server: %w", err)
	}
	in.s.keyConfirmed(ctx, in.adminID, in.node.ID, in.stored, t)
	if in.remember {
		log.note("the panel keeps the credentials, sealed")
	}

	log.step("Checking the server")
	report, err := in.s.preflight(ctx, client, in.node, t.Host, in.docker())
	if err != nil {
		return err
	}
	describeReport(log, report)
	switch {
	case in.installDocker && !report.NeedsDocker():
		log.note("Docker is installed and runs: it is not installed again")
	case !in.installDocker && report.NeedsDocker():
		log.note("the panel sets up Docker when the install asks for it (install_docker)")
	}
	if in.installDocker && report.NeedsDocker() {
		// Docker is not installed on a server that is refused anyway.
		if blockers := report.Blockers(true); len(blockers) > 0 {
			return refuse(log, blockers)
		}
		log.step("Setting up Docker, as asked")
		code, err := in.runLong(ctx, client, dockerCommand(!in.docker()), w)
		switch {
		case err != nil:
			return fmt.Errorf("setting up Docker: %w", err)
		case code != 0:
			engine := "Docker Engine with the Compose v2 plugin"
			if in.docker() {
				engine = "Docker Engine"
			}
			return fmt.Errorf("setting up Docker failed with exit code %d, and the log says why: "+
				"set up %s by hand, then install the node again", code, engine)
		}
		log.step("Checking the server again")
		if report, err = in.s.preflight(ctx, client, in.node, t.Host, in.docker()); err != nil {
			return err
		}
		describeReport(log, report)
	}
	if blockers := report.Blockers(false); len(blockers) > 0 {
		return refuse(log, blockers)
	}
	if in.docker() {
		return in.runDocker(ctx, client, log)
	}

	kit, err := in.s.nodes.OpenKitFor(ctx, report.Facts.Arch)
	if err != nil {
		return fmt.Errorf("the install is refused: %w", err)
	}
	defer kit.Close()
	dir := report.InstallDir
	log.step("Copying the node kit (%s) and the bundle to %s", kit.Arch, dir)
	if code, err := in.runShort(ctx, client, mkdirCommand(dir, 0), w); err != nil || code != 0 {
		return commandFailed("the directory of the install could not be made", code, err)
	}
	for _, f := range kit.Files {
		mode := os.FileMode(0o600)
		if f.Name == binaryName {
			mode = 0o700
		}
		if err := in.upload(ctx, client, dir+"/"+f.Name, mode, f); err != nil {
			return err
		}
		log.note("%s, %s", f.Name, sizeText(uint64(f.Size)))
	}

	bundlePath := dir + "/" + bundleFileName
	removed := false
	defer func() {
		if !removed {
			if rmErr := in.removeBundle(ctx, client, bundlePath, log); rmErr != nil {
				err = withRemoval(err, rmErr)
			}
		}
	}()
	if err := in.upload(ctx, client, bundlePath, 0o600, bytes.NewReader(in.bundle)); err != nil {
		return err
	}
	log.note("%s, the certificate and the key of the node", bundleFileName)

	log.step("Running install.sh")
	code, err := in.runLong(ctx, client, installCommand(dir), w)
	installed := in.s.now()
	// The wrapper of install.sh has removed the bundle; this is the second
	// line, which also finds out that it is gone.
	removed = true
	rmErr := in.removeBundle(ctx, client, bundlePath, log)
	switch {
	case err != nil:
		return withRemoval(fmt.Errorf("install.sh: %w", err), rmErr)
	case code != 0:
		return withRemoval(fmt.Errorf("install.sh failed with exit code %d: its output is in the log", code), rmErr)
	}

	log.step("Waiting for the node to come online (at most %s)", in.s.onlineTimeout)
	n, err := in.s.waitOnline(ctx, in.node, installed)
	if err != nil {
		return withRemoval(err, rmErr)
	}
	log.note("The node is online, agent %s", orUnknown(n.AgentVersion))
	if rmErr != nil {
		return fmt.Errorf("the node is online, but %w", rmErr)
	}
	log.step("Done")
	return nil
}

// runDocker is the rest of an install on the Docker path, on a server that
// the preflight let through: it makes a join token, pulls the node image,
// removes the container of an earlier agent, starts the node with the Docker
// command, and waits for it to come online. The token, and the value of
// POSTERN_JOIN that holds it, are secrets of the job from the moment that it
// is made. The token and the image come first: when either cannot be had, the
// agent that runs is left as it is.
func (in *install) runDocker(ctx context.Context, client *sshx.Client, log progress) error {
	w := log.w
	log.step("Making a join token")
	token, expires, err := in.s.nodes.MintJoinTokenBy(ctx, in.node.ID, in.adminID)
	if err != nil {
		return fmt.Errorf("could not make a join token: %w", err)
	}
	jobs.AddSecrets(w, token, in.panelURL+"#"+token)
	log.note("the node joins %s with it, until %s at the latest", in.panelURL, expires.UTC().Format(time.RFC3339))

	// The image is pulled while the old agent still runs: a registry that
	// cannot be reached must not leave the server without a node.
	log.step("Pulling the node image (%s)", in.image)
	if code, err := in.runLong(ctx, client, pullCommand(in.image), w); err != nil || code != 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c, ierr := in.runShort(ctx, client, imageThereCommand(in.image), w); ierr != nil || c != 0 {
			return commandFailed("could not pull the node image, and the server has no copy of it", code, err)
		}
		log.note("warning: the pull failed; the copy of %s on the server is used", in.image)
	}

	log.step("Removing an old agent container")
	if code, err := in.runShort(ctx, client, removeAgentCommand, w); err != nil || code != 0 {
		return commandFailed("the old agent container could not be removed", code, err)
	}

	log.step("Starting the node (%s)", in.image)
	code, err := in.runLong(ctx, client, startCommand(nodes.RenderDockerCommand(in.image, in.panelURL, token)), w)
	started := in.s.now()
	switch {
	case err != nil:
		return fmt.Errorf("docker run: %w", err)
	case code != 0:
		return fmt.Errorf("docker run failed with exit code %d: its output is in the log", code)
	}

	log.step("Waiting for the node to come online (at most %s)", in.s.onlineTimeout)
	n, err := in.s.waitOnline(ctx, in.node, started)
	if err != nil {
		return err
	}
	log.note("The node is online, agent %s", orUnknown(n.AgentVersion))
	log.step("Done")
	return nil
}

// withRemoval adds to the error of a job that the bundle could not be removed,
// when it could not.
func withRemoval(err, rmErr error) error {
	switch {
	case rmErr == nil:
		return err
	case err == nil:
		return rmErr
	}
	return fmt.Errorf("%w; and %w", err, rmErr)
}

// runShort runs a short command, bounded by stepTimeout.
func (in *install) runShort(ctx context.Context, client *sshx.Client, cmd string, out io.Writer) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	return client.Run(ctx, cmd, nil, out)
}

// runLong runs a long command, bounded by longTimeout.
func (in *install) runLong(ctx context.Context, client *sshx.Client, cmd string, out io.Writer) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	return client.Run(ctx, cmd, nil, out)
}

// upload copies a file to the server, bounded by longTimeout: a binary of
// some 20 MB over a slow link takes minutes.
func (in *install) upload(ctx context.Context, client *sshx.Client, path string, mode os.FileMode, r io.Reader) error {
	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	if err := client.Upload(ctx, path, mode, r); err != nil {
		return fmt.Errorf("could not copy %s: %w", path, err)
	}
	return nil
}

// removeBundle makes sure that the bundle, which holds the private key of the
// node, is gone from the server, also when the job has been cancelled. The
// error says what to do when it is not; it is a notice of the job, which the
// error of a cancelled job keeps too.
func (in *install) removeBundle(ctx context.Context, client *sshx.Client, path string, log progress) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	log.step("Removing the bundle, which holds the private key of the node")
	code, err := client.Run(ctx, removeBundleCommand(path), nil, log.w)
	if err != nil || code != 0 {
		log.note("%s may still be on the server: remove it by hand", path)
		return jobs.Notice(fmt.Errorf("the bundle %s, which holds the private key of the node, may still be on the server: remove it by hand (%v)",
			path, commandFailed("rm", code, err)))
	}
	return nil
}

// waitOnline waits until the panel has connected to the agent of the node
// since since, for at most the online timeout. It tells the connection
// manager to look at the node now and then, so that it connects at once
// instead of after its back-off.
func (s *Service) waitOnline(ctx context.Context, node *store.Node, since time.Time) (*store.Node, error) {
	ctx, cancel := context.WithTimeout(ctx, s.onlineTimeout)
	defer cancel()
	since = since.Truncate(time.Second) // the store keeps whole seconds
	tick := time.NewTicker(s.onlinePoll)
	defer tick.Stop()
	for i := 0; ; i++ {
		if i%notifyEvery == 0 && s.notifier != nil {
			s.notifier.Notify(node.ID)
		}
		n, err := s.db.NodeByID(ctx, node.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, errors.New("the node was deleted while it was being installed")
		case err == nil && n.Status == store.NodeStatusOnline && n.LastSeenAt != nil && !n.LastSeenAt.Before(since):
			return n, nil
		}
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("the node did not come online within %s: the panel has to reach the management port of the node, %s, "+
				"so check the firewall, and the log of the agent on the server: docker logs postern-agent",
				s.onlineTimeout, net.JoinHostPort(node.MgmtHost, strconv.FormatUint(uint64(node.MgmtPort), 10)))
		case <-tick.C:
		}
	}
}

// describeReport writes what the preflight found to the log.
func describeReport(log progress, r *Report) {
	f := r.Facts
	log.note("%s, %s (%s)", orUnknown(f.OS.PrettyName), orUnknown(f.Machine), orUnknown(f.Arch))
	d := f.Docker
	switch {
	case !d.Installed:
		log.note("Docker is not installed")
	case d.Version == "":
		log.note("Docker does not answer: %s", d.Problem)
	case d.ComposeVersion == "":
		log.note("Docker %s, without Compose v2", d.Version)
	default:
		log.note("Docker %s, Compose %s", d.Version, d.ComposeVersion)
	}
	if r.Method == MethodDocker {
		log.note("the node starts from its Docker image, with the Docker command")
	} else {
		log.note("the node kit is copied to the server, and install.sh runs")
	}
	log.note("port %d: %s", r.HTTPSPort.Port, portText(r.HTTPSPort))
	log.note("management port %d: %s", r.MgmtPort.Port, portText(r.MgmtPort))
	for _, is := range r.Issues {
		if is.Severity == SeverityWarning {
			log.note("warning: %s", is.Message)
		}
	}
}

func portText(c PortCheck) string {
	switch {
	case c.Free:
		return "free"
	case c.Postern:
		return "held by Postern, which is installed here already"
	}
	return "taken by " + c.Owner
}

// refuse says why the install is refused, in the log and in the error.
func refuse(log progress, blockers []Issue) error {
	messages := make([]string, 0, len(blockers))
	for _, b := range blockers {
		log.note("blocker: %s", b.Message)
		messages = append(messages, b.Message)
	}
	return fmt.Errorf("the install is refused: %s", strings.Join(messages, "; "))
}

// commandFailed is the error of a command that failed to run or exited with
// code.
func commandFailed(what string, code int, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: exit code %d", what, code)
}

// dockerSetupCommand is the script that sets up Docker, with root (the
// directory of /etc and /run, "" but for the tests) and the functions that it
// shares with the preflight, and need_compose, which says whether the install
// needs the Compose v2 plugin.
func dockerSetupCommand(root string, needCompose bool) string {
	nc := "0"
	if needCompose {
		nc = "1"
	}
	return "root=" + shellQuote(root) + "\nneed_compose=" + nc + "\n" + sharedFunctions + dockerScript
}
