//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/dockerapi"
)

// ---- cleanup ------------------------------------------------------------------

// cleanup removes what the run made, also after a failure, and prints the
// logs of the panel and the node's containers when the test failed. The agent
// goes first, so that it starts nothing that is removed after it, and the
// networks of the run last, once no container is on them.
func (e *env) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if e.t.Failed() || os.Getenv("POSTERN_E2E_LOGS") != "" {
		e.dumpLogs(ctx)
	}
	if e.agent != "" {
		if err := e.docker.Remove(ctx, e.agent, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			e.errorf("removing the agent container: %v", err)
		}
	}
	list, err := e.containersOfThisRun(ctx)
	if err != nil {
		e.errorf("listing the containers of the run: %v", err)
	}
	for _, c := range list {
		if err := e.docker.Remove(ctx, c.ID, true); err != nil && !errors.Is(err, dockerapi.ErrNotFound) {
			e.errorf("removing container %s: %v", c.name(), err)
		}
	}
	e.removeNetworks(ctx)
	if e.panel != nil {
		if err := e.panel.stop(15 * time.Second); err != nil && !e.t.Failed() {
			e.logf("the panel: %v", err)
		}
	}
	e.removeWork(ctx)
	if left, err := e.containersOfThisRun(ctx); err == nil && len(left) > 0 {
		var names []string
		for _, c := range left {
			names = append(names, c.name())
		}
		e.errorf("containers of the run are left: %s", strings.Join(names, ", "))
	}
}

// removeNetworks removes the networks of the run (the label of the run); their
// containers, which are the run's, are gone by now.
func (e *env) removeNetworks(ctx context.Context) {
	nets, err := e.raw.networks(ctx, labelRun+"="+e.run)
	if err != nil {
		e.errorf("listing the networks of the run: %v", err)
		return
	}
	for _, n := range nets {
		err := e.raw.do(ctx, http.MethodDelete, "/networks/"+url.PathEscape(n.ID), nil, nil)
		if err != nil && !errors.Is(err, errNoSuchNetwork) {
			e.errorf("removing the network %s: %v", n.Name, err)
		}
	}
}

// removeWork removes the node's directory. The agent, the edge and the
// engines leave files of root and of 65534 in it, which only root can remove:
// a container of the run does that first.
func (e *env) removeWork(ctx context.Context) {
	if e.work == "" {
		return
	}
	if err := os.RemoveAll(e.work); err == nil {
		return
	}
	if code, out := e.runHelperCtx(ctx, "rm", "none", []string{"rm", "-rf", e.home}); code != 0 {
		e.errorf("removing %s: exit %d: %s", e.home, code, out)
		return
	}
	if err := os.RemoveAll(e.work); err != nil {
		e.errorf("removing %s: %v", e.work, err)
	}
}

// containersOfThisRun are the containers that the test made (the label of the
// run) and those that the agent made for the node (postern.managed=true, with
// a mount from the node's directory). The container that the test itself runs
// in (POSTERN_E2E_CONTAINER, see scripts/e2e.sh) is not one of them, although
// it has the label of the run.
func (e *env) containersOfThisRun(ctx context.Context) ([]rawContainer, error) {
	own, err := e.raw.containers(ctx, labelRun+"="+e.run)
	if err != nil {
		return nil, err
	}
	managed, err := e.raw.containers(ctx, "postern.managed=true")
	if err != nil {
		return nil, err
	}
	self := os.Getenv("POSTERN_E2E_CONTAINER")
	var out []rawContainer
	for _, c := range own {
		if self == "" || c.name() != self {
			out = append(out, c)
		}
	}
	for _, c := range managed {
		if c.Labels[labelRun] == e.run || e.work == "" {
			continue // listed already, or nothing of the node exists yet
		}
		for _, m := range c.Mounts {
			if m.Source == e.work || strings.HasPrefix(m.Source, e.work+"/") {
				out = append(out, c)
				break
			}
		}
	}
	return out, nil
}

// dumpLogs prints the end of the logs of the panel and of the node's
// containers, scrubbed as everything that the test prints.
func (e *env) dumpLogs(ctx context.Context) {
	if e.panel != nil {
		e.logf("---- panel log (end) ----\n%s", lastLines(e.panel.log.String(), 150))
	}
	list, err := e.containersOfThisRun(ctx)
	if err != nil {
		e.logf("listing the containers of the run: %v", err)
		return
	}
	for _, c := range list {
		rc, err := e.docker.Logs(ctx, c.ID, 150, false)
		if err != nil {
			e.logf("logs of %s: %v", c.name(), err)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		_ = rc.Close()
		e.logf("---- %s (%s) log (end) ----\n%s", c.name(), c.State, data)
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ---- Docker -------------------------------------------------------------------

// runHelper runs a short command as root in a container of the run on the
// network (none, or host), with the node's directory mounted at the same path,
// and returns its exit code and output.
func (e *env) runHelper(tag, network string, cmd []string) (int, string) {
	return e.runHelperCtx(e.ctx, tag, network, cmd)
}

func (e *env) runHelperCtx(ctx context.Context, tag, network string, cmd []string) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	spec := dockerapi.ContainerSpec{
		Name:          "postern-e2e-" + e.run + "-" + tag + "-" + strings.ToLower(rand.Text())[:6],
		Image:         runnerImage,
		User:          "0:0",
		NetworkMode:   network,
		RestartPolicy: "no",
		Entrypoint:    cmd,
		Binds:         []string{e.work + ":" + e.work},
		Labels:        map[string]string{labelRun: e.run},
	}
	id, err := e.docker.Create(ctx, spec)
	if err != nil {
		return -1, err.Error()
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rcancel()
		_ = e.docker.Remove(rctx, id, true)
	}()
	if err := e.docker.Start(ctx, id); err != nil {
		return -1, err.Error()
	}
	return e.waitExit(ctx, id)
}

// rawDocker is what dockerapi does not offer: the daemon's info, and lists of
// containers with their mounts.
type rawDocker struct{ hc *http.Client }

func newRawDocker(socket string) *rawDocker {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &rawDocker{hc: &http.Client{Transport: tr, Timeout: time.Minute}}
}

// errNoSuchContainer and errNoSuchNetwork are the 404 of the daemon for a
// container and for a network.
var (
	errNoSuchContainer = errors.New("no such container")
	errNoSuchNetwork   = errors.New("no such network")
)

func (r *rawDocker) get(ctx context.Context, path string, v any) error {
	return r.do(ctx, http.MethodGet, path, nil, v)
}

// do sends a request to the daemon, with body as JSON when it is not nil, and
// decodes the answer into v when v is not nil. An answer other than 2xx is an
// error that quotes the daemon.
func (r *rawDocker) do(ctx context.Context, method, path string, body, v any) error {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, payload)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("docker %s %s: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/containers/"):
		return fmt.Errorf("docker %s %s: %w: %s", method, path, errNoSuchContainer, bytes.TrimSpace(data))
	case resp.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/networks/") && method != http.MethodPost:
		return fmt.Errorf("docker %s %s: %w: %s", method, path, errNoSuchNetwork, bytes.TrimSpace(data))
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return fmt.Errorf("docker %s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(data))
	}
	if v == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// rawNetwork is a network as GET /networks describes it.
type rawNetwork struct {
	ID   string `json:"Id"`
	Name string
}

// networks are the networks with the label (key=value).
func (r *rawDocker) networks(ctx context.Context, label string) ([]rawNetwork, error) {
	filters, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		return nil, err
	}
	var list []rawNetwork
	if err := r.get(ctx, "/networks?filters="+url.QueryEscape(string(filters)), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// containerIP is the IPv4 address of a container on a network.
func (r *rawDocker) containerIP(ctx context.Context, id, network string) (string, error) {
	var d struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := r.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &d); err != nil {
		return "", err
	}
	n, ok := d.NetworkSettings.Networks[network]
	if !ok || n.IPAddress == "" {
		return "", fmt.Errorf("container %.12s has no address on the network %s", id, network)
	}
	return n.IPAddress, nil
}

// rawContainer is a container as GET /containers/{id}/json describes it.
type rawContainer struct {
	ID     string
	Name   string
	State  string
	Labels map[string]string
	Mounts []struct{ Source string }
}

func (c rawContainer) name() string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID[:12]
}

// containers describes every container, running or not, with the label
// (key=value). Each one is inspected: the list of the daemon says where the
// bind mounts come from in its own terms, and Docker Desktop's are not the
// paths that were asked for, which inspecting gives back.
func (r *rawDocker) containers(ctx context.Context, label string) ([]rawContainer, error) {
	filters, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		return nil, err
	}
	var list []struct {
		ID string `json:"Id"`
	}
	if err := r.get(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &list); err != nil {
		return nil, err
	}
	out := make([]rawContainer, 0, len(list))
	for _, l := range list {
		var d struct {
			ID     string `json:"Id"`
			Name   string
			State  struct{ Status string }
			Config struct{ Labels map[string]string }
			Mounts []struct{ Source string }
		}
		switch err := r.get(ctx, "/containers/"+url.PathEscape(l.ID)+"/json", &d); {
		case errors.Is(err, errNoSuchContainer):
			continue // removed in the meantime
		case err != nil:
			return nil, err
		}
		out = append(out, rawContainer{
			ID: d.ID, Name: strings.TrimPrefix(d.Name, "/"), State: d.State.Status, Labels: d.Config.Labels, Mounts: d.Mounts,
		})
	}
	return out, nil
}
