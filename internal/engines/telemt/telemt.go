// Package telemt is the engines.Driver for telemt, the Rust MTProxy
// implementation (https://github.com/telemt/telemt).
//
// The official musl release binary runs in a stock Alpine container on the host
// network. It listens on 127.0.0.1 only, behind the node's own edge router,
// which hands it every connection with a PROXY protocol v2 header, and
// everything it connects to goes out through the edge's SOCKS5 port. The
// container is unprivileged: user 65534, read-only root file system, no
// capabilities, a small tmpfs, and the instance directory as the one writable
// place.
package telemt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
)

// Driver runs telemt. It holds no state: one value serves every instance.
type Driver struct{}

// New returns the telemt driver.
func New() *Driver { return &Driver{} }

var _ engines.Driver = Driver{}

// Engine is ENGINE_TELEMT.
func (Driver) Engine() nodev1.Engine { return nodev1.Engine_ENGINE_TELEMT }

// Supports reports fake-TLS and WEB proxies.
func (Driver) Supports(t nodev1.ProxyType) bool {
	return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS || t == nodev1.ProxyType_PROXY_TYPE_WEB
}

// ArtifactFile is the release file for a CPU architecture ("amd64" or "arm64"):
// a .tar.gz with the telemt binary in it, statically linked against musl.
func (Driver) ArtifactFile(arch string) (string, error) {
	switch arch {
	case "amd64":
		return "telemt-x86_64-linux-musl.tar.gz", nil
	case "arm64":
		return "telemt-aarch64-linux-musl.tar.gz", nil
	}
	return "", fmt.Errorf("telemt: no release for architecture %q (want amd64 or arm64)", arch)
}

// BinaryName is "telemt".
func (Driver) BinaryName() string { return "telemt" }

var _ engines.Trialer = Driver{}

// trialOutput is what telemt's healthcheck prints for a config it cannot load
// (src/healthcheck.rs of 3.5.12 and 3.5.13, finding F1).
var trialOutput = regexp.MustCompile(`(?m)^\[telemt\] healthcheck failed: config load failed`)

// Trial is `telemt healthcheck --mode liveness /nonexistent/config.toml`: exit
// code 1 and the healthcheck's "config load failed" line. telemt has no version
// flag (`telemt --version` would start the proxy with ./config.toml, finding
// F1), so the trial proves that the binary runs in the runner image and is a
// telemt, not which version it is. The version is ignored.
func (Driver) Trial(string) engines.Trial {
	return engines.Trial{
		Args:     []string{"healthcheck", "--mode", "liveness", "/nonexistent/config.toml"},
		ExitCode: 1,
		Output:   trialOutput,
	}
}

// Render returns the config of the instance: config.toml, which contains the
// proxy secret and the API token, so it must be written private; and, for a
// WEB proxy, the files of its decoy site under public/ (web.go). The engine
// overrides of the proxy are written into config.toml as well, when they are
// on the whitelist of package overrides. A proxy it cannot render (wrong type,
// malformed fields, engine overrides that are not on the whitelist or not
// valid) is an error; the error never holds a secret.
func (Driver) Render(in engines.Instance) (map[string][]byte, error) {
	if in.Proxy == nil {
		return nil, errors.New("telemt: no proxy to render")
	}
	if in.Proxy.GetType() == nodev1.ProxyType_PROXY_TYPE_WEB {
		cfg, err := renderWeb(in)
		if err != nil {
			return nil, err
		}
		files := decoyFiles(in.Proxy)
		files[configFile] = cfg
		return files, nil
	}
	cfg, err := renderFakeTLS(in)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{configFile: cfg}, nil
}

// Container describes the container the instance runs in:
//
//	postern-eng-<proxy id, lower case>-g<generation>
//
// from the runner image, as user 65534 on the host network, with a read-only
// root file system, no capabilities, no new privileges, a 16 MiB /tmp, 256 MiB of
// memory and 256 processes. The binary is mounted read-only and the instance
// directory read-write: telemt keeps its caches there. Check the two host paths
// with Instance.CheckHostPaths before creating it.
func (Driver) Container(in engines.Instance) dockerapi.ContainerSpec {
	id := cmp.Or(in.Proxy.GetId(), in.InstanceID)
	return dockerapi.ContainerSpec{
		Name:          "postern-eng-" + strings.ToLower(id) + "-g" + strconv.FormatUint(in.Generation, 10),
		Image:         in.RunnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    []string{binaryMount, configMount},
		// The log level (LogEnv): not part of the instance hash.
		Env: Driver{}.LogEnv(),
		Binds: []string{
			in.BinaryPath + ":" + binaryMount + ":ro",
			in.InstanceDir + ":" + instanceMount,
		},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "engine",
			"postern.id":         id,
			"postern.generation": strconv.FormatUint(in.Generation, 10),
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 256 << 20,
		PidsLimit:   256,
		LogMaxSize:  "5m",
		LogMaxFile:  2,
	}
}

// ---- readiness ----------------------------------------------------------------

const (
	readyPath = "/v1/health/ready"
	// maxReadyBody bounds what Ready reads of an answer. The real one is a couple
	// of hundred bytes.
	maxReadyBody = 64 << 10
)

// readyRequestTimeout bounds one readiness request, so that an engine that
// accepts the connection and then says nothing cannot hold a polling loop for
// longer than its own deadline allows. A variable for the tests.
var readyRequestTimeout = 5 * time.Second

// apiClient talks to the engine's API on loopback: no proxy from the
// environment, no redirects (the API never sends one), no connection reuse.
var apiClient = &http.Client{
	Transport: &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Ready asks the engine's API, GET http://127.0.0.1:<APIPort>/v1/health/ready with
// the token as the Authorization header (as it is: no "Bearer"), and returns nil
// when it answers that it is ready: admission is open and at least one upstream
// is healthy. Anything else is an error that says why, without the token. It
// makes a single request, with its own timeout, and does not wait: callers poll.
func (Driver) Ready(ctx context.Context, in engines.Instance) error {
	if in.APIPort == 0 {
		return errors.New("telemt: no API port")
	}
	if in.APIToken == "" {
		return errors.New("telemt: no API token")
	}
	ctx, cancel := context.WithTimeout(ctx, readyRequestTimeout)
	defer cancel()

	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.APIPort))) + readyPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("telemt: %w", err)
	}
	req.Header.Set("Authorization", in.APIToken)

	resp, err := apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("telemt: health check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReadyBody))
	if err != nil {
		return fmt.Errorf("telemt: health check: reading the answer: %w", err)
	}

	var answer struct {
		OK   bool `json:"ok"`
		Data struct {
			Ready     bool   `json:"ready"`
			Status    string `json:"status"`
			Reason    string `json:"reason"`
			Healthy   int    `json:"healthy_upstreams"`
			Upstreams int    `json:"total_upstreams"`
		} `json:"data"`
	}
	decodeErr := json.Unmarshal(body, &answer)

	switch {
	case resp.StatusCode == http.StatusOK && decodeErr != nil:
		return fmt.Errorf("telemt: unexpected answer from %s (HTTP 200, but not telemt's JSON): is something else on the API port?", readyPath)
	case resp.StatusCode == http.StatusOK && answer.OK && answer.Data.Ready:
		return nil
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusServiceUnavailable:
		// Not ready. Say why, as far as the answer says.
		msg := fmt.Sprintf("telemt is not ready (HTTP %d", resp.StatusCode)
		if decodeErr == nil {
			if why := cmp.Or(answer.Data.Reason, answer.Data.Status); why != "" {
				msg += fmt.Sprintf(": %.64q", why)
			}
			if answer.Data.Upstreams > 0 {
				msg += fmt.Sprintf("; %d of %d upstreams healthy", answer.Data.Healthy, answer.Data.Upstreams)
			}
		}
		return errors.New(msg + ")")
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("telemt: the API refused the request (HTTP %d): the token or the source address was not accepted", resp.StatusCode)
	}
	return fmt.Errorf("telemt: health check answered HTTP %d", resp.StatusCode)
}
