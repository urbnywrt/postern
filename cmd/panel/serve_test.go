package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/server"
	"github.com/urbnywrt/postern/internal/version"
)

// envOf is the environment of a test: getenv over a map.
func envOf(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// defaultKit is where the panel image keeps the node kit.
const defaultKit = "/usr/local/share/postern/node-kit"

func TestConfigFromEnv(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want server.Config
	}{
		{
			name: "nothing is set",
			env:  nil,
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: ":8080", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			name: "everything is set",
			env: map[string]string{
				"POSTERN_DATA": "/srv/postern/data", "POSTERN_KEYS": "/srv/postern/keys",
				"POSTERN_LISTEN":          "127.0.0.1:9090",
				"POSTERN_TRUSTED_PROXIES": "192.0.2.7, 198.51.100.0/24",
				"POSTERN_HEALTHY_FILE":    "/data/run/launcher/healthy",
				"POSTERN_NODE_KIT_DIR":    "/srv/postern/node-kit",
				"POSTERN_GEOIP_BASE_URL":  "https://mirror.example/free",
				"POSTERN_PUBLIC_PAGE":     " OFF ",
				"POSTERN_GITHUB_API":      "https://github.example/api",
				"POSTERN_NODE_IMAGE":      " ghcr.io/owner/postern-node:v9 ",
			},
			want: server.Config{
				DataDir: "/srv/postern/data", KeysDir: "/srv/postern/keys", Listen: "127.0.0.1:9090",
				TrustedProxies: prefixes(t, "192.0.2.7/32", "198.51.100.0/24"),
				HealthyFile:    "/data/run/launcher/healthy",
				NodeKitDir:     "/srv/postern/node-kit",
				GeoIPBaseURL:   "https://mirror.example/free",
				PublicPageOff:  true,
				ReleasesAPI:    "https://github.example/api",
				NodeImage:      "ghcr.io/owner/postern-node:v9",
			},
		},
		{
			name: "the public page on, said so",
			env:  map[string]string{"POSTERN_PUBLIC_PAGE": "on"},
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: ":8080", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			// docker compose passes a variable that was not set as an empty one.
			name: "empty and blank values mean the default",
			env: map[string]string{
				"POSTERN_DATA": "", "POSTERN_KEYS": "  ", "POSTERN_LISTEN": "\t",
				"POSTERN_TRUSTED_PROXIES": "", "POSTERN_HEALTHY_FILE": " ", "POSTERN_NODE_KIT_DIR": " ", "POSTERN_GEOIP_BASE_URL": "  ",
				"POSTERN_PUBLIC_PAGE": " ", "POSTERN_NODE_IMAGE": " ",
			},
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: ":8080", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			name: "values are trimmed",
			env:  map[string]string{"POSTERN_DATA": "  /d  ", "POSTERN_LISTEN": " :80 "},
			want: server.Config{
				DataDir: "/d", KeysDir: "/keys", Listen: ":80", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			name: "a list of only blanks is the default, not an empty list",
			env:  map[string]string{"POSTERN_TRUSTED_PROXIES": " , ,"},
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: ":8080", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			name: "ipv6 listen address",
			env:  map[string]string{"POSTERN_LISTEN": "[::1]:8080"},
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: "[::1]:8080", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
		{
			name: "a random port",
			env:  map[string]string{"POSTERN_LISTEN": "127.0.0.1:0"},
			want: server.Config{
				DataDir: "/data", KeysDir: "/keys", Listen: "127.0.0.1:0", NodeKitDir: defaultKit,
				TrustedProxies: prefixes(t, "127.0.0.1/32", "::1/128"),
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := configFromEnv(envOf(c.env))
			if err != nil {
				t.Fatalf("configFromEnv: %v", err)
			}
			if got.DataDir != c.want.DataDir || got.KeysDir != c.want.KeysDir || got.Listen != c.want.Listen ||
				got.HealthyFile != c.want.HealthyFile || got.NodeKitDir != c.want.NodeKitDir ||
				got.GeoIPBaseURL != c.want.GeoIPBaseURL || got.PublicPageOff != c.want.PublicPageOff ||
				got.ReleasesAPI != c.want.ReleasesAPI || got.NodeImage != c.want.NodeImage {
				t.Errorf("config = %+v, want %+v", got, c.want)
			}
			if !slices.Equal(got.TrustedProxies, c.want.TrustedProxies) {
				t.Errorf("trusted proxies = %v, want %v", got.TrustedProxies, c.want.TrustedProxies)
			}
		})
	}
}

func TestConfigFromEnvRefuses(t *testing.T) {
	for _, c := range []struct {
		name    string
		env     map[string]string
		mention []string
	}{
		{"a proxy that is not an address", map[string]string{"POSTERN_TRUSTED_PROXIES": "192.0.2.1,proxy.example"}, []string{"POSTERN_TRUSTED_PROXIES", "proxy.example"}},
		{"a proxy with a bad length", map[string]string{"POSTERN_TRUSTED_PROXIES": "192.0.2.0/40"}, []string{"POSTERN_TRUSTED_PROXIES", "192.0.2.0/40"}},
		{"a port alone", map[string]string{"POSTERN_LISTEN": "8080"}, []string{"POSTERN_LISTEN", "8080"}},
		{"a host without a port", map[string]string{"POSTERN_LISTEN": "localhost"}, []string{"POSTERN_LISTEN", "localhost"}},
		{"a port that is not a number", map[string]string{"POSTERN_LISTEN": ":web"}, []string{"POSTERN_LISTEN", ":web"}},
		{"a port that is too large", map[string]string{"POSTERN_LISTEN": ":70000"}, []string{"POSTERN_LISTEN", ":70000"}},
		{"a negative port", map[string]string{"POSTERN_LISTEN": ":-1"}, []string{"POSTERN_LISTEN", ":-1"}},
		{"an unbracketed ipv6 address", map[string]string{"POSTERN_LISTEN": "::1:8080"}, []string{"POSTERN_LISTEN"}},
		{"a download base that is no address", map[string]string{"POSTERN_GEOIP_BASE_URL": "not an address"}, []string{"POSTERN_GEOIP_BASE_URL", "not an address"}},
		{"a download base that is not http", map[string]string{"POSTERN_GEOIP_BASE_URL": "ftp://mirror.example/free"}, []string{"POSTERN_GEOIP_BASE_URL", "ftp://mirror.example/free"}},
		{"a download base with no host", map[string]string{"POSTERN_GEOIP_BASE_URL": "https:///free"}, []string{"POSTERN_GEOIP_BASE_URL"}},
		{"a download base with a query", map[string]string{"POSTERN_GEOIP_BASE_URL": "https://mirror.example/free?key=1"}, []string{"POSTERN_GEOIP_BASE_URL", "no query"}},
		{"a download base with a fragment", map[string]string{"POSTERN_GEOIP_BASE_URL": "https://mirror.example/free#a"}, []string{"POSTERN_GEOIP_BASE_URL", "no fragment"}},
		{"a download base with a user name and a password", map[string]string{"POSTERN_GEOIP_BASE_URL": "https://alice:s3cret@mirror.example/free"}, []string{"POSTERN_GEOIP_BASE_URL", "user name or password"}},
		{"a public page switch that is neither on nor off", map[string]string{"POSTERN_PUBLIC_PAGE": "maybe"}, []string{"POSTERN_PUBLIC_PAGE", "maybe", "on or off"}},
		{"a node image that is no reference", map[string]string{"POSTERN_NODE_IMAGE": "ghcr.io/Owner/node"}, []string{"POSTERN_NODE_IMAGE", "ghcr.io/Owner/node", "not a Docker image reference"}},
		{"a node image with a bad tag", map[string]string{"POSTERN_NODE_IMAGE": "ghcr.io/owner/node:-x"}, []string{"POSTERN_NODE_IMAGE"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if cfg, err := configFromEnv(envOf(c.env)); err == nil {
				t.Fatalf("configFromEnv = %+v, want an error", cfg)
			} else {
				for _, want := range c.mention {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the error does not mention %q: %v", want, err)
					}
				}
			}
		})
	}
}

// lockedBuffer is a bytes.Buffer that two goroutines may use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var setupURLPattern = regexp.MustCompile(`http://(\S+)/setup\?token=([A-Za-z0-9_-]+)`)

// started is a serve command that runs in the background.
type started struct {
	stdout, stderr *lockedBuffer
	stop           func() int
}

func start(t *testing.T, env map[string]string) *started {
	t.Helper()
	s := &started{stdout: &lockedBuffer{}, stderr: &lockedBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- runServe(ctx, nil, envOf(env), s.stdout, s.stderr) }()
	var code int
	var once sync.Once
	s.stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(30 * time.Second):
				t.Error("the serve command did not return after its context was done")
				code = -1
			}
		})
		return code
	}
	t.Cleanup(func() { s.stop() })
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func serveEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"POSTERN_DATA":   filepath.Join(dir, "data"),
		"POSTERN_KEYS":   filepath.Join(dir, "keys"),
		"POSTERN_LISTEN": "127.0.0.1:0",
		// A panel that serves looks for its country database: not at DB-IP.
		"POSTERN_GEOIP_BASE_URL": closedBase(t),
		// The release tracker polls at start: a served panel must not reach
		// GitHub from a test. A stub answers 404 to everything.
		"POSTERN_GITHUB_API": releasesStub(t),
	}
}

// closedBase is the address of a directory on a loopback port that nothing
// listens on.
func closedBase(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}

// releasesStub serves an empty release API: 404 to everything.
func releasesStub(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// The command opens the store, makes the key, serves, prints the setup URL on
// stdout (and only that), logs on stderr (without the token), and stops with the
// exit status 0 when it is told to.
func TestServe(t *testing.T) {
	env := serveEnv(t)
	s := start(t, env)

	waitFor(t, "the setup URL", func() bool { return setupURLPattern.MatchString(s.stdout.String()) })
	m := setupURLPattern.FindStringSubmatch(s.stdout.String())
	host, token := m[1], m[2]

	resp, err := http.Post("http://"+host+"/api/postern.panel.v1.HealthService/Check", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check: status %d", resp.StatusCode)
	}
	resp, err = http.Get("http://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("the UI is served without the security headers")
	}

	for _, path := range []string{filepath.Join(env["POSTERN_DATA"], "postern.db"), filepath.Join(env["POSTERN_KEYS"], "master.key")} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%v", err)
		}
	}

	if code := s.stop(); code != 0 {
		t.Errorf("exit status %d, want 0 after a stop that was asked for; stderr:\n%s", code, s.stderr.String())
	}
	if n := strings.Count(s.stdout.String(), "/setup?token="); n != 1 {
		t.Errorf("stdout has the setup URL %d times, want once:\n%s", n, s.stdout.String())
	}
	stderr := s.stderr.String()
	if strings.Contains(stderr, token) || strings.Contains(s.stdout.String(), "level=") {
		t.Errorf("the token is in the log, or the log is on stdout")
	}
	for _, want := range []string{"level=INFO", "version=", "the panel is serving", "the panel has stopped", "node kit"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr has no %q:\n%s", want, stderr)
		}
	}
}

// The usage text documents every variable that the serve command reads.
func TestUsageNamesEveryVariable(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, name := range []string{envData, envKeys, envListen, envProxies, envHealthy, envNodeKit, envGeoIP, envPublic, envNodeImage} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("the usage text does not name %s", name)
		}
	}
	if !strings.Contains(out.String(), defaultKit) {
		t.Errorf("the usage text does not give the default of %s", envNodeKit)
	}
}

// The store logs through the default logger of slog, which the command sets to
// its own, so that every line has the same form.
func TestServeLogsTheStoreInTheSameForm(t *testing.T) {
	s := start(t, serveEnv(t))
	waitFor(t, "the setup URL", func() bool { return setupURLPattern.MatchString(s.stdout.String()) })
	s.stop()
	for _, line := range strings.Split(strings.TrimSpace(s.stderr.String()), "\n") {
		if !strings.HasPrefix(line, "time=") {
			t.Errorf("a line of the log is not in the form of the panel: %q", line)
		}
	}
	if !strings.Contains(s.stderr.String(), "applied migration") {
		t.Error("the log has nothing from the store")
	}
}

// The key is lost and the database is not: the panel stops, saying why, and
// makes no key.
func TestServeStopsWithoutTheKeyOverSealedData(t *testing.T) {
	env := serveEnv(t)
	first := start(t, env)
	waitFor(t, "the first start", func() bool { return setupURLPattern.MatchString(first.stdout.String()) })
	if code := first.stop(); code != 0 {
		t.Fatalf("first run: exit %d", code)
	}
	key := filepath.Join(env["POSTERN_KEYS"], "master.key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr lockedBuffer
	code := runServe(context.Background(), nil, envOf(env), &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit status %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), key) || !strings.Contains(stderr.String(), "will not make a new key") {
		t.Errorf("stderr does not say why, and where the key is expected:\n%s", stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("stdout: %q", stdout.String())
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("a key was made")
	}
}

// The address of POSTERN_GEOIP_BASE_URL reaches the panel: it looks for its
// country database there as soon as it serves, and not at DB-IP.
func TestServeLooksForTheCountryDatabaseWhereTheEnvironmentSays(t *testing.T) {
	asked := make(chan string, 8)
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case asked <- r.URL.Path:
		default:
		}
		http.NotFound(w, r)
	}))
	defer src.Close()
	env := serveEnv(t)
	env["POSTERN_GEOIP_BASE_URL"] = src.URL + "/free/"
	s := start(t, env)

	select {
	case path := <-asked:
		if !strings.HasPrefix(path, "/free/dbip-country-lite-") || !strings.HasSuffix(path, ".mmdb.gz") {
			t.Errorf("the panel asked for %q, want a file of the country database under /free/", path)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the panel did not look for its country database at the address of the environment")
	}
	if code := s.stop(); code != 0 {
		t.Errorf("exit status %d, want 0; stderr:\n%s", code, s.stderr.String())
	}
}

// An address with a user name and a password, or one that cannot be read, is
// refused without being said back: the message goes to a terminal and a log.
func TestConfigFromEnvDoesNotEchoCredentials(t *testing.T) {
	for _, base := range []string{
		"https://alice:s3cret@mirror.example/free",
		"http://alice:s3cret@mirror.example:80/free?k=v",
		"http://alice:s3cret@mirror.example:badport/free",
		"http://alice:s3cret@mirror.example/%zz",
		"alice:s3cret@mirror.example",
	} {
		_, err := configFromEnv(envOf(map[string]string{"POSTERN_GEOIP_BASE_URL": base}))
		if err == nil {
			t.Errorf("%q was taken", base)
			continue
		}
		for _, secret := range []string{"alice", "s3cret"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the refusal of %q says %q: %v", base, secret, err)
			}
		}
		if !strings.Contains(err.Error(), "POSTERN_GEOIP_BASE_URL") {
			t.Errorf("the refusal of %q does not name the variable: %v", base, err)
		}
	}
	// What has no secret in it is said back, so that the mistake can be found.
	_, err := configFromEnv(envOf(map[string]string{"POSTERN_GEOIP_BASE_URL": "ftp://mirror.example/free"}))
	if err == nil || !strings.Contains(err.Error(), "ftp://mirror.example/free") {
		t.Errorf("err = %v, want the address that is wrong", err)
	}
}

func TestServeStopsWhenTheAddressIsTaken(t *testing.T) {
	env := serveEnv(t)
	first := start(t, env)
	waitFor(t, "the first start", func() bool { return setupURLPattern.MatchString(first.stdout.String()) })
	taken := setupURLPattern.FindStringSubmatch(first.stdout.String())[1]

	other := serveEnv(t)
	other["POSTERN_LISTEN"] = taken
	var stdout, stderr lockedBuffer
	if code := runServe(context.Background(), nil, envOf(other), &stdout, &stderr); code != 1 {
		t.Errorf("exit status %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), taken) {
		t.Errorf("stderr does not name the address: %s", stderr.String())
	}
}

func TestServeRefusesBadConfiguration(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"proxies": {"POSTERN_TRUSTED_PROXIES": "oops"},
		"listen":  {"POSTERN_LISTEN": "8080"},
	} {
		t.Run(name, func(t *testing.T) {
			env["POSTERN_DATA"] = t.TempDir()
			env["POSTERN_KEYS"] = t.TempDir()
			var stdout, stderr lockedBuffer
			if code := runServe(context.Background(), nil, envOf(env), &stdout, &stderr); code != 2 {
				t.Errorf("exit status %d, want 2", code)
			}
			if !strings.HasPrefix(stderr.String(), "postern-panel: POSTERN_") {
				t.Errorf("stderr: %q", stderr.String())
			}
			// Nothing was opened or made.
			if entries, _ := os.ReadDir(env["POSTERN_DATA"]); len(entries) != 0 {
				t.Errorf("the data directory has %d entries", len(entries))
			}
		})
	}
}

func TestServeTakesNoArguments(t *testing.T) {
	var stdout, stderr lockedBuffer
	code := runServe(context.Background(), []string{"--listen", ":1"}, envOf(serveEnv(t)), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "serve takes no arguments") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

// The trusted proxies of the environment reach the server: with one that is not
// the loopback, the loopback is not trusted, so a header from it counts for
// nothing in the limits on sign-in.
func TestServeUsesTheTrustedProxiesOfTheEnvironment(t *testing.T) {
	login := func(host, xff, user string) string {
		req, err := http.NewRequest(http.MethodPost, "http://"+host+"/api/postern.panel.v1.AuthService/Login",
			strings.NewReader(`{"username":"`+user+`","password":"not the password"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return buf.String()
	}
	for _, c := range []struct {
		name    string
		proxies string // "" is the default
		want    string
	}{
		{"loopback by default", "", `"unauthenticated"`},
		{"another proxy", "198.51.100.0/24", `"resource_exhausted"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := serveEnv(t)
			if c.proxies != "" {
				env["POSTERN_TRUSTED_PROXIES"] = c.proxies
			}
			s := start(t, env)
			waitFor(t, "the setup URL", func() bool { return setupURLPattern.MatchString(s.stdout.String()) })
			host := setupURLPattern.FindStringSubmatch(s.stdout.String())[1]
			var last string
			for i := range 6 {
				last = login(host, "192.0.2."+string(rune('1'+i)), "nobody"+string(rune('a'+i)))
			}
			if !strings.Contains(last, c.want) {
				t.Errorf("the sixth failure from six addresses: %s, want a Connect error %s", last, c.want)
			}
		})
	}
}

func TestUsageNamesTheEnvironment(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	for _, want := range []string{"serve", "POSTERN_DATA", "POSTERN_KEYS", "POSTERN_LISTEN", "POSTERN_TRUSTED_PROXIES", "127.0.0.1/32,::1/128", "/data", "/keys", ":8080"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the usage does not mention %q:\n%s", want, buf.String())
		}
	}
}

// The node image is POSTERN_NODE_IMAGE, or else the default of the build,
// with the version of the panel as its tag when it has none; a dev build has
// no tag to give, and so no image.
func TestConfigFromEnvNodeImage(t *testing.T) {
	defer func(v, img string) { version.Version, version.NodeImage = v, img }(version.Version, version.NodeImage)
	for _, c := range []struct {
		name, version, builtin, env, want string
	}{
		{"none", "v1.2.3", "", "", ""},
		{"the default of the build", "v1.2.3", "ghcr.io/owner/postern-node", "", "ghcr.io/owner/postern-node:v1.2.3"},
		{"the environment over the default", "v1.2.3", "ghcr.io/owner/postern-node", "registry.example/postern-node", "registry.example/postern-node:v1.2.3"},
		{"a tag is kept", "v1.2.3", "", "ghcr.io/owner/postern-node:v1.0.0", "ghcr.io/owner/postern-node:v1.0.0"},
		{"a dev build without a tag", "dev", "ghcr.io/owner/postern-node", "", ""},
		{"a dev build with a tag", "dev", "", "ghcr.io/owner/postern-node:edge", "ghcr.io/owner/postern-node:edge"},
		{"a version that cannot be a tag", "1.2.3+build", "ghcr.io/owner/postern-node", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			version.Version, version.NodeImage = c.version, c.builtin
			got, err := configFromEnv(envOf(map[string]string{"POSTERN_NODE_IMAGE": c.env}))
			if err != nil || got.NodeImage != c.want {
				t.Errorf("NodeImage = %q, %v; want %q", got.NodeImage, err, c.want)
			}
		})
	}

	version.Version, version.NodeImage = "v1.2.3", "ghcr.io/Owner/postern-node"
	_, err := configFromEnv(envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "POSTERN_NODE_IMAGE") || !strings.Contains(err.Error(), "ghcr.io/Owner/postern-node") {
		t.Errorf("a bad default of the build: %v, want an error that names it and POSTERN_NODE_IMAGE", err)
	}
	// A good value in the environment stands in for a bad default.
	if got, err := configFromEnv(envOf(map[string]string{"POSTERN_NODE_IMAGE": "ghcr.io/owner/postern-node"})); err != nil || got.NodeImage != "ghcr.io/owner/postern-node:v1.2.3" {
		t.Errorf("NodeImage = %q, %v", got.NodeImage, err)
	}
}

// An image without a tag in a build whose version cannot be a tag gives no
// one-command install, and the panel says so once as it starts, but starts.
func TestServeWarnsOfANodeImageWithoutATag(t *testing.T) {
	defer func(v string) { version.Version = v }(version.Version)
	version.Version = "1.2.3+build"
	env := serveEnv(t)
	env["POSTERN_NODE_IMAGE"] = "ghcr.io/owner/postern-node"
	s := start(t, env)
	waitFor(t, "the panel to serve", func() bool { return strings.Contains(s.stderr.String(), "the panel is serving") })
	if code := s.stop(); code != 0 {
		t.Fatalf("exit status %d; stderr:\n%s", code, s.stderr.String())
	}
	var warnings int
	for _, line := range strings.Split(s.stderr.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "POSTERN_NODE_IMAGE") {
			warnings++
			if !strings.Contains(line, "tag") || !strings.Contains(line, "ghcr.io/owner/postern-node") {
				t.Errorf("the warning does not suggest a tag or name the image: %s", line)
			}
		}
	}
	if warnings != 1 {
		t.Errorf("%d warnings that name POSTERN_NODE_IMAGE, want 1:\n%s", warnings, s.stderr.String())
	}
}
