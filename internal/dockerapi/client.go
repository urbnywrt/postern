package dockerapi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// client speaks the Engine API to a daemon over a unix socket.
//
// Every request opens its own connection (keep-alive is off). A unix connect
// costs microseconds, and it means a daemon restart can never leave a dead
// pooled connection behind to fail the next call.
type client struct {
	socket  string
	http    *http.Client
	version atomic.Pointer[string] // API version in use; nil until negotiated
}

var _ Client = (*client)(nil)

// New returns a Client for the Docker daemon listening on socketPath (default
// DefaultSocket; a unix:// prefix is accepted). It does not connect yet: the
// first call negotiates the API version, min(the daemon's ApiVersion,
// MaxAPIVersion), with GET /version, and Ping renegotiates it.
func New(socketPath string) Client {
	socketPath = strings.TrimPrefix(socketPath, "unix://")
	if socketPath == "" {
		socketPath = DefaultSocket
	}
	return &client{
		socket: socketPath,
		http: &http.Client{
			// No Proxy: the socket must never be reached through HTTP_PROXY.
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
				DisableKeepAlives:  true,
				DisableCompression: true,
			},
			// The Engine API never redirects; whatever sends one is not the API.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			// No Timeout: it would cut log and pull streams. Contexts bound calls.
		},
	}
}

// ---- API version --------------------------------------------------------------

// parseAPIVersion splits "1.47" into 1 and 47.
func parseAPIVersion(v string) (major, minor int, err error) {
	majorPart, minorPart, ok := strings.Cut(v, ".")
	a, errA := strconv.ParseUint(majorPart, 10, 16)
	b, errB := strconv.ParseUint(minorPart, 10, 16)
	if !ok || errA != nil || errB != nil {
		return 0, 0, fmt.Errorf("dockerapi: unexpected API version %q", v)
	}
	return int(a), int(b), nil
}

// lowerAPIVersion returns the older of two API versions. They are compared as
// numbers, major then minor: 1.9 is older than 1.47.
func lowerAPIVersion(a, b string) (string, error) {
	aMajor, aMinor, err := parseAPIVersion(a)
	if err != nil {
		return "", err
	}
	bMajor, bMinor, err := parseAPIVersion(b)
	if err != nil {
		return "", err
	}
	if aMajor > bMajor || (aMajor == bMajor && aMinor > bMinor) {
		aMajor, aMinor = bMajor, bMinor
	}
	return fmt.Sprintf("%d.%d", aMajor, aMinor), nil
}

func (c *client) negotiate(ctx context.Context) (string, error) {
	const op = "negotiate API version"
	resp, err := c.send(ctx, http.MethodGet, "/version", nil, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", readAPIError(op, resp)
	}
	var body struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := decodeBody(op, resp, &body); err != nil {
		return "", err
	}
	return lowerAPIVersion(body.APIVersion, MaxAPIVersion)
}

// apiVersion returns the API version in use, negotiating it on first use. A
// failed negotiation is not remembered.
func (c *client) apiVersion(ctx context.Context) (string, error) {
	if v := c.version.Load(); v != nil {
		return *v, nil
	}
	v, err := c.negotiate(ctx)
	if err != nil {
		return "", err
	}
	c.version.Store(&v)
	return v, nil
}

// ---- requests -----------------------------------------------------------------

// send performs one request. endpoint is an escaped path; a non-nil body is
// sent as JSON. The caller must close the response body.
func (c *client) send(ctx context.Context, method, endpoint string, query url.Values, body any) (*http.Response, error) {
	target := "http://docker" + endpoint // the host is ignored: every dial goes to the socket
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("dockerapi: encode request: %w", err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, fmt.Errorf("dockerapi: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dockerapi: %w", err)
	}
	return resp, nil
}

// call is send for an endpoint of the versioned API.
func (c *client) call(ctx context.Context, method, endpoint string, query url.Values, body any) (*http.Response, error) {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, method, "/v"+v+endpoint, query, body)
}

// do runs a request whose answer carries nothing of interest: success is one of
// the ok statuses, anything else an *APIError.
func (c *client) do(ctx context.Context, op, method, endpoint string, query url.Values, body any, ok ...int) error {
	resp, err := c.call(ctx, method, endpoint, query, body)
	if err != nil {
		return err
	}
	if !slices.Contains(ok, resp.StatusCode) {
		return readAPIError(op, resp)
	}
	_ = resp.Body.Close()
	return nil
}

// readAPIError turns an error answer into an *APIError and closes the body.
func readAPIError(op string, resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	message := strings.TrimSpace(string(data))
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &body) == nil && strings.TrimSpace(body.Message) != "" {
		message = strings.TrimSpace(body.Message)
	}
	return newAPIError(op, resp.StatusCode, message)
}

// decodeBody decodes a JSON answer and closes the body.
func decodeBody(op string, resp *http.Response, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("dockerapi: %s: decode response: %w", op, err)
	}
	return nil
}

func containerPath(idOrName, suffix string) string {
	return "/containers/" + url.PathEscape(idOrName) + suffix
}

// imageJSONPath is the path of GET /images/{name}/json. The reference keeps its
// slashes (the route takes them) but is escaped otherwise.
func imageJSONPath(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/images/" + strings.Join(parts, "/") + "/json"
}

// ---- Client -------------------------------------------------------------------

func (c *client) Ping(ctx context.Context) (string, error) {
	resp, err := c.send(ctx, http.MethodGet, "/_ping", nil, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", readAPIError("ping", resp)
	}
	_ = resp.Body.Close()
	v, err := c.negotiate(ctx)
	if err != nil {
		return "", err
	}
	c.version.Store(&v)
	return v, nil
}

func (c *client) Info(ctx context.Context) (*Info, error) {
	const op = "system info"
	resp, err := c.call(ctx, http.MethodGet, "/info", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(op, resp)
	}
	var raw struct {
		SecurityOptions []string
	}
	if err := decodeBody(op, resp, &raw); err != nil {
		return nil, err
	}
	return &Info{SecurityOptions: raw.SecurityOptions}, nil
}

func (c *client) List(ctx context.Context, labels map[string]string, all bool) ([]Container, error) {
	const op = "list containers"
	query := url.Values{}
	if all {
		query.Set("all", "1")
	}
	if len(labels) > 0 {
		filters, err := json.Marshal(map[string][]string{"label": labelFilters(labels)})
		if err != nil {
			return nil, fmt.Errorf("dockerapi: encode filters: %w", err)
		}
		query.Set("filters", string(filters))
	}
	resp, err := c.call(ctx, http.MethodGet, "/containers/json", query, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(op, resp)
	}
	var raw []struct {
		ID      string `json:"Id"`
		Names   []string
		Image   string
		Created int64
		State   string
		Status  string
		Labels  map[string]string
	}
	if err := decodeBody(op, resp, &raw); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		out = append(out, Container{
			ID:      r.ID,
			Name:    primaryName(r.Names),
			Image:   r.Image,
			State:   r.State,
			Status:  r.Status,
			Labels:  r.Labels,
			Created: time.Unix(r.Created, 0).UTC(),
		})
	}
	return out, nil
}

// labelFilters renders labels as the daemon's "key=value" label filters, in a
// fixed order; an empty value becomes a bare "key", which matches any value.
func labelFilters(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		if v == "" {
			out = append(out, k)
		} else {
			out = append(out, k+"="+v)
		}
	}
	slices.Sort(out)
	return out
}

// primaryName picks the container's own name out of the daemon's Names list:
// the one without a second slash (the others are legacy link aliases like
// "/web/db"), without its leading slash.
func primaryName(names []string) string {
	for _, n := range names {
		if strings.Count(n, "/") == 1 {
			return strings.TrimPrefix(n, "/")
		}
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}

// inspectResponse is the part of GET /containers/{id}/json that is used.
type inspectResponse struct {
	ID           string `json:"Id"`
	Name         string
	RestartCount int
	Created      string
	State        struct {
		Status     string
		Running    bool
		ExitCode   int
		StartedAt  string
		FinishedAt string
	}
	Config struct {
		Image  string
		Labels map[string]string
		Tty    bool
		Env    []string
	}
	HostConfig struct {
		RestartPolicy struct{ Name string }
		Binds         []string
		NetworkMode   string
		PortBindings  map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
	}
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
}

func (c *client) inspect(ctx context.Context, idOrName string) (*inspectResponse, error) {
	if err := checkID(idOrName); err != nil {
		return nil, err
	}
	op := fmt.Sprintf("inspect container %q", idOrName)
	resp, err := c.call(ctx, http.MethodGet, containerPath(idOrName, "/json"), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(op, resp)
	}
	var out inspectResponse
	if err := decodeBody(op, resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *client) Inspect(ctx context.Context, idOrName string) (*ContainerDetails, error) {
	r, err := c.inspect(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	op := fmt.Sprintf("inspect container %q", idOrName)
	created, err := parseTimestamp(op, "Created", r.Created)
	if err != nil {
		return nil, err
	}
	started, err := parseTimestamp(op, "StartedAt", r.State.StartedAt)
	if err != nil {
		return nil, err
	}
	finished, err := parseTimestamp(op, "FinishedAt", r.State.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &ContainerDetails{
		Container: Container{
			ID:      r.ID,
			Name:    strings.TrimPrefix(r.Name, "/"),
			Image:   r.Config.Image,
			State:   r.State.Status,
			Status:  r.State.Status,
			Labels:  r.Config.Labels,
			Created: created,
		},
		RestartPolicy: cmp.Or(r.HostConfig.RestartPolicy.Name, "no"),
		Binds:         r.HostConfig.Binds,
		Running:       r.State.Running,
		ExitCode:      r.State.ExitCode,
		RestartCount:  r.RestartCount,
		Env:           r.Config.Env,
		StartedAt:     started,
		FinishedAt:    finished,
		NetworkMode:   r.HostConfig.NetworkMode,
		PortBindings:  portBindings(r),
		Mounts:        mountPoints(r),
	}, nil
}

// mountPoints copies the top-level Mounts of an inspection.
func mountPoints(r *inspectResponse) []MountPoint {
	var out []MountPoint
	for _, m := range r.Mounts {
		out = append(out, MountPoint{Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	return out
}

// portBindings flattens HostConfig.PortBindings, sorted.
func portBindings(r *inspectResponse) []PortBinding {
	var out []PortBinding
	for port, bs := range r.HostConfig.PortBindings {
		for _, b := range bs {
			out = append(out, PortBinding{ContainerPort: port, HostIP: b.HostIP, HostPort: b.HostPort})
		}
	}
	sortPortBindings(out)
	return out
}

func sortPortBindings(bs []PortBinding) {
	slices.SortFunc(bs, func(a, b PortBinding) int {
		return cmp.Or(strings.Compare(a.ContainerPort, b.ContainerPort), strings.Compare(a.HostIP, b.HostIP), strings.Compare(a.HostPort, b.HostPort))
	})
}

// parseTimestamp reads one of the daemon's RFC 3339 timestamps. The daemon
// reports "never" as 0001-01-01T00:00:00Z, which is the zero time.
func parseTimestamp(op, field, s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("dockerapi: %s: bad %s %q: %w", op, field, s, err)
	}
	return t, nil
}

// The request bodies of POST /containers/create and POST /containers/{id}/update.
// Zero values are omitted so that the image's and the daemon's defaults apply.
// StopTimeout is the exception: it is a pointer so that an explicit 0 is sent
// (and nil is omitted), and it belongs to the container config, not HostConfig.
type (
	createRequest struct {
		Image       string            `json:"Image"`
		User        string            `json:"User,omitempty"`
		Entrypoint  []string          `json:"Entrypoint,omitempty"`
		Cmd         []string          `json:"Cmd,omitempty"`
		Env         []string          `json:"Env,omitempty"`
		Labels      map[string]string `json:"Labels,omitempty"`
		StopTimeout *int              `json:"StopTimeout,omitempty"`
		HostConfig  hostConfig        `json:"HostConfig"`
	}
	hostConfig struct {
		Binds          []string          `json:"Binds,omitempty"`
		NetworkMode    string            `json:"NetworkMode,omitempty"`
		RestartPolicy  *restartPolicy    `json:"RestartPolicy,omitempty"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs,omitempty"`
		CapAdd         []string          `json:"CapAdd,omitempty"`
		CapDrop        []string          `json:"CapDrop,omitempty"`
		SecurityOpt    []string          `json:"SecurityOpt,omitempty"`
		Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
		Memory         int64             `json:"Memory,omitempty"`
		MemorySwap     int64             `json:"MemorySwap,omitempty"`
		PidsLimit      int64             `json:"PidsLimit,omitempty"`
		Ulimits        []ulimit          `json:"Ulimits,omitempty"`
		LogConfig      *logConfig        `json:"LogConfig,omitempty"`
		PidMode        string            `json:"PidMode,omitempty"`
		Privileged     bool              `json:"Privileged,omitempty"`
		Mounts         []mount           `json:"Mounts,omitempty"`
	}
	mount struct {
		Type     string `json:"Type"`
		Source   string `json:"Source"`
		Target   string `json:"Target"`
		ReadOnly bool   `json:"ReadOnly,omitempty"`
	}
	restartPolicy struct {
		Name string `json:"Name"`
	}
	ulimit struct {
		Name string `json:"Name"`
		Soft int64  `json:"Soft"`
		Hard int64  `json:"Hard"`
	}
	logConfig struct {
		Type   string            `json:"Type"`
		Config map[string]string `json:"Config,omitempty"`
	}
	updateRequest struct {
		RestartPolicy restartPolicy `json:"RestartPolicy"`
	}
)

func newCreateRequest(spec ContainerSpec) createRequest {
	req := createRequest{
		Image:       spec.Image,
		User:        spec.User,
		Entrypoint:  spec.Entrypoint,
		Cmd:         spec.Cmd,
		Env:         spec.Env,
		Labels:      spec.Labels,
		StopTimeout: spec.StopTimeout,
		HostConfig: hostConfig{
			Binds:          spec.Binds,
			NetworkMode:    spec.NetworkMode,
			ReadonlyRootfs: spec.ReadOnly,
			CapAdd:         spec.CapAdd,
			CapDrop:        spec.CapDrop,
			SecurityOpt:    spec.SecurityOpt,
			Tmpfs:          spec.Tmpfs,
			Memory:         spec.MemoryBytes,
			MemorySwap:     spec.MemorySwap,
			PidsLimit:      spec.PidsLimit,
			PidMode:        spec.PidMode,
			Privileged:     spec.Privileged,
		},
	}
	if spec.RestartPolicy != "" {
		req.HostConfig.RestartPolicy = &restartPolicy{Name: spec.RestartPolicy}
	}
	for _, u := range spec.Ulimits {
		req.HostConfig.Ulimits = append(req.HostConfig.Ulimits, ulimit(u))
	}
	for _, m := range spec.Mounts {
		req.HostConfig.Mounts = append(req.HostConfig.Mounts, mount{Type: "bind", Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	if spec.LogMaxSize != "" || spec.LogMaxFile > 0 {
		lc := &logConfig{Type: "json-file", Config: map[string]string{}}
		if spec.LogMaxSize != "" {
			lc.Config["max-size"] = spec.LogMaxSize
		}
		if spec.LogMaxFile > 0 {
			lc.Config["max-file"] = strconv.Itoa(spec.LogMaxFile)
		}
		req.HostConfig.LogConfig = lc
	}
	return req
}

func (c *client) Create(ctx context.Context, spec ContainerSpec) (string, error) {
	if err := validateSpec(spec); err != nil {
		return "", err
	}
	op := fmt.Sprintf("create container %q", spec.Name)
	query := url.Values{}
	if spec.Name != "" {
		query.Set("name", spec.Name)
	}
	resp, err := c.call(ctx, http.MethodPost, "/containers/create", query, newCreateRequest(spec))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", readAPIError(op, resp)
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := decodeBody(op, resp, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("dockerapi: %s: the daemon returned no container ID", op)
	}
	return out.ID, nil
}

func (c *client) Start(ctx context.Context, id string) error {
	if err := checkID(id); err != nil {
		return err
	}
	// 204 started it, 304 says it was running already.
	return c.do(ctx, fmt.Sprintf("start container %q", id), http.MethodPost, containerPath(id, "/start"), nil, nil,
		http.StatusNoContent, http.StatusNotModified)
}

func (c *client) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if err := checkID(id); err != nil {
		return err
	}
	query := url.Values{}
	if timeout >= 0 {
		query.Set("t", strconv.FormatInt(int64((timeout+time.Second-1)/time.Second), 10))
	}
	// 204 stopped it, 304 says it was not running.
	return c.do(ctx, fmt.Sprintf("stop container %q", id), http.MethodPost, containerPath(id, "/stop"), query, nil,
		http.StatusNoContent, http.StatusNotModified)
}

func (c *client) Remove(ctx context.Context, id string, force bool) error {
	if err := checkID(id); err != nil {
		return err
	}
	query := url.Values{"v": {"1"}}
	if force {
		query.Set("force", "1")
	}
	return c.do(ctx, fmt.Sprintf("remove container %q", id), http.MethodDelete, containerPath(id, ""), query, nil,
		http.StatusNoContent)
}

func (c *client) SetRestartPolicy(ctx context.Context, id, policy string) error {
	if err := checkID(id); err != nil {
		return err
	}
	if err := checkRestartPolicy(policy); err != nil {
		return err
	}
	if policy == "" {
		policy = "no"
	}
	return c.do(ctx, fmt.Sprintf("update container %q", id), http.MethodPost, containerPath(id, "/update"), nil,
		updateRequest{RestartPolicy: restartPolicy{Name: policy}}, http.StatusOK)
}

func (c *client) Logs(ctx context.Context, id string, tail int, follow bool) (io.ReadCloser, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	// Whether the stream is framed depends on the container having a TTY, which
	// only inspect tells.
	info, err := c.inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	query := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"all"}}
	if tail >= 0 {
		query.Set("tail", strconv.Itoa(tail))
	}
	if follow {
		query.Set("follow", "1")
	}
	return c.logs(ctx, id, info, query)
}

func (c *client) LogsSince(ctx context.Context, id string, since time.Time) (io.ReadCloser, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	info, err := c.inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	query := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"all"}, "timestamps": {"1"}}
	if !since.IsZero() {
		// Seconds and nanoseconds, the daemon's own form of a precise time.
		query.Set("since", fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()))
	}
	return c.logs(ctx, id, info, query)
}

func (c *client) logs(ctx context.Context, id string, info *inspectResponse, query url.Values) (io.ReadCloser, error) {
	resp, err := c.call(ctx, http.MethodGet, containerPath(id, "/logs"), query, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(fmt.Sprintf("read logs of container %q", id), resp)
	}
	if info.Config.Tty {
		return resp.Body, nil
	}
	return &demuxReader{r: resp.Body}, nil
}

func (c *client) ImageExists(ctx context.Context, ref string) (bool, error) {
	if ref == "" {
		return false, errEmptyRef
	}
	resp, err := c.call(ctx, http.MethodGet, imageJSONPath(ref), nil, nil)
	if err != nil {
		return false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		_ = resp.Body.Close()
		return true, nil
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return false, nil
	}
	return false, readAPIError(fmt.Sprintf("inspect image %q", ref), resp)
}

func (c *client) Pull(ctx context.Context, ref string) error {
	if ref == "" {
		return errEmptyRef
	}
	op := fmt.Sprintf("pull image %q", ref)
	from, tag := splitImageRef(ref)
	resp, err := c.call(ctx, http.MethodPost, "/images/create", url.Values{"fromImage": {from}, "tag": {tag}}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return readAPIError(op, resp)
	}
	// The daemon answers 200 and then streams progress as JSON messages. A pull
	// that fails after the first byte is reported by a message with an error.
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("dockerapi: %s: reading progress: %w", op, err)
		}
		if m := cmp.Or(msg.ErrorDetail.Message, msg.Error); m != "" {
			return fmt.Errorf("dockerapi: %s: %s", op, m)
		}
	}
}

// splitImageRef splits an image reference into the fromImage and tag parameters
// of POST /images/create, as the Docker CLI does: a digest wins over a tag, and
// no tag at all means "latest".
func splitImageRef(ref string) (from, tag string) {
	name, digest, hasDigest := strings.Cut(ref, "@")
	// A colon starts a tag only after the last slash; before it, it is the port
	// of a registry address.
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name, tag = name[:colon], name[colon+1:]
	}
	switch {
	case hasDigest:
		tag = digest
	case tag == "":
		tag = "latest"
	}
	return name, tag
}

// ---- log stream ---------------------------------------------------------------

// demuxReader strips the framing of Docker's multiplexed stream, which a
// container without a TTY uses for stdout and stderr: every frame is an 8-byte
// header (stream type, three zero bytes, payload size as a big-endian uint32)
// followed by the payload. The result is the payloads, in order.
type demuxReader struct {
	r    io.ReadCloser
	left uint32 // bytes of the current frame's payload not read yet
	err  error  // why reading stopped; sticky
}

func (d *demuxReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	for d.left == 0 { // at a frame boundary (and past empty frames)
		var hdr [8]byte
		if _, err := io.ReadFull(d.r, hdr[:]); err != nil {
			// io.EOF: the stream ended between frames, which is how it ends.
			// io.ErrUnexpectedEOF: it ended inside a header.
			d.err = err
			return 0, err
		}
		if hdr[1]|hdr[2]|hdr[3] != 0 {
			d.err = errors.New("dockerapi: log stream is not a multiplexed stream (bad frame header)")
			return 0, d.err
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		switch hdr[0] {
		case 0, 1, 2: // stdin (never sent for logs), stdout, stderr
			d.left = size
		case 3: // the daemon reporting a problem
			msg, _ := io.ReadAll(io.LimitReader(d.r, min(int64(size), 4096)))
			d.err = fmt.Errorf("dockerapi: daemon error in log stream: %s", msg)
			return 0, d.err
		default:
			d.err = fmt.Errorf("dockerapi: unexpected stream type %d in log stream", hdr[0])
			return 0, d.err
		}
	}
	if uint64(len(p)) > uint64(d.left) {
		p = p[:d.left]
	}
	n, err := d.r.Read(p)
	d.left -= uint32(n)
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF) && d.left == 0:
		d.err = io.EOF // the stream ended exactly at the end of a frame
	case errors.Is(err, io.EOF):
		d.err = io.ErrUnexpectedEOF // it ended inside a frame
	default:
		d.err = err
	}
	return n, d.err
}

func (d *demuxReader) Close() error { return d.r.Close() }
