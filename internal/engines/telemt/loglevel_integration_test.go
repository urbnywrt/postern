//go:build integration

package telemt

import (
	"context"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/state"
)

// clientAddr is the client address of the handshakes: the source of their
// PROXY v2 headers, as the edge would send it.
const clientAddr = "198.51.100.77"

// TestLogLevel is the proof behind logFilter (R6-2): telemt 3.5.13 in the
// container the driver describes, RUST_LOG and all, through its start-up with
// the middle proxies on and no way out (the SOCKS port of the edge is not
// there: every datacenter is dead and getProxySecret cannot be fetched), a
// good and a bad fake-TLS handshake from clientAddr, writes no secret in any
// of its forms, no API token and no client address to its log; and the filter
// is in effect: the log has info lines although the config says silent.
//
// It runs its clients in helper containers on the host network, as the other
// cases do, so that it works with Docker Desktop as with a Linux daemon:
// go test -tags integration -run TestLogLevel ./internal/engines/telemt/
func TestLogLevel(t *testing.T) {
	env := newITestEnv(t)
	drv := New()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	secret, token := randomHex(t, 16), strings.ToLower(rand.Text())
	proxy := &nodev1.Proxy{
		Id: strings.ToUpper("itest" + env.run + "loglevel"), Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
		Secret: secret, Domain: "www.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: itestVersion,
		UseMiddleProxy: true, AdTag: randomHex(t, 16), NatIp: "203.0.113.10",
		// The middle proxies cannot start here: with the fallback telemt
		// comes up in direct mode and keeps trying them.
		EngineOverridesJson: `{"me2dc_fallback": true}`,
	}
	dir, err := os.MkdirTemp(env.base, "loglevel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.removeTree(t, dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	in := engines.Instance{
		Proxy: proxy, InstanceID: proxy.Id + "-g1", Generation: 1,
		ListenPort: pickPort(t, 20000, 25000), APIPort: pickPort(t, 25000, 30000), SocksPort: pickPort(t, 30000, 35000),
		APIToken: token, InstanceDir: dir, BinaryPath: env.store.BinaryPath(env.ref), RunnerImage: runnerImage,
	}
	files, err := drv.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	spec := drv.Container(in)
	if !strings.HasPrefix(strings.Join(spec.Env, " "), "RUST_LOG=") {
		t.Fatalf("the container spec sets no RUST_LOG: %v", spec.Env)
	}
	spec.Name = "postern-test-" + env.run + "-loglevel"
	spec.RestartPolicy = "no"
	spec.Labels = itestLabels(env.run)
	id, err := env.docker.Create(ctx, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { env.removeContainer(t, id, spec.Name) })
	if err := env.docker.Start(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}

	helper := func(tag string, args []string, extra ...string) (int, string) {
		return env.runHelper(t, ctx, tag, dockerapi.ContainerSpec{
			Image: runnerImage, User: "65534:65534", NetworkMode: "host",
			Entrypoint: []string{"/opt/readycheck"}, Cmd: args,
			Env: append([]string{"TELEMT_API_PORT=" + strconv.Itoa(int(in.APIPort)), "TELEMT_API_TOKEN=" + token,
				"TELEMT_LISTEN_PORT=" + strconv.Itoa(int(in.ListenPort)), "TELEMT_SNI=www.example.com"}, extra...),
			Binds: []string{env.ready + ":/opt/readycheck:ro"},
		}, 2*time.Minute, func(ctx context.Context) error { return env.stillRunning(ctx, id) })
	}
	if exit, out := helper("ready", []string{"-wait", "90s"}); exit != 0 {
		t.Fatalf("not ready (exit %d): %s", exit, strings.TrimSpace(out))
	}
	for i, s := range []string{secret, randomHex(t, 16), secret, randomHex(t, 16)} {
		src := clientAddr + ":" + strconv.Itoa(40000+i)
		_, out := helper("hs", []string{"-handshake"}, "TELEMT_SECRET="+s, "TELEMT_SRC="+src)
		t.Logf("handshake %d (good %t): %s", i, s == secret, strings.TrimSpace(out))
	}
	// The middle proxies keep failing meanwhile.
	time.Sleep(20 * time.Second)
	if _, out := helper("dcs", []string{"-dcs"}); out != "" {
		t.Logf("GET /v1/stats/dcs: %s", strings.TrimSpace(out))
	}
	if err := env.stillRunning(ctx, id); err != nil {
		t.Fatal(err)
	}

	log := env.logs(t, id)
	st := &nodev1.NodeState{Proxies: []*nodev1.Proxy{proxy}}
	rt := state.NewRuntime()
	rt.Instances[proxy.Id] = state.InstanceRecord{APIToken: token}
	scrubbed := diag.NewScrubber(st, rt, []netip.Addr{netip.MustParseAddr("203.0.113.10")}).Clean(log)
	if n := strings.Count(scrubbed, diag.Redacted) - strings.Count(log, diag.Redacted); n > 0 {
		t.Errorf("the log has %d secrets in one form or another (proxy secret, ad tag, API token); log withheld", n)
		return
	}
	for _, bad := range []string{clientAddr, "tg://", strings.ToLower(token)} {
		if strings.Contains(strings.ToLower(log), bad) {
			t.Errorf("the log contains %q; log withheld", bad)
			return
		}
	}
	plain := stripANSI(log)
	if !strings.Contains(plain, " INFO ") {
		t.Errorf("no info line in the log: RUST_LOG is not in effect")
	}
	t.Logf("telemt log at %s (%d bytes):\n%s", logFilter, len(log), strings.TrimSpace(scrubbed))
}
