// Package geodb keeps the country database of the panel current: the DB-IP "IP
// to Country Lite" database, a MaxMind DB file of about 8 MB that gives the
// country of an IP address (internal/geoip reads it). The statistics of client
// countries rest on it, and it is public data.
//
//   - [Manager] downloads the file of the current month, looks again every day,
//     takes an upload, keeps the file and what is known about it, and gives the
//     country of an address while it is enabled. It is what the node manager of
//     the panel and its ingest hold on to.
//   - [Service] is the GeoIPService of the panel API: the status, a refresh now,
//     and the switch.
//   - [Manager.UploadHandler] is PUT /api/geoip, the upload for a panel that
//     cannot reach DB-IP.
//
// # What is kept
//
// The file is /data/geoip/dbip-country-lite-<YYYY-MM>.mmdb, mode 0644 since it
// is public data. The current file and the one before it are kept, and no
// older one. What the panel knows about it is in two settings of the database:
// geoip, {"enabled": true} (absent: enabled), and geoip_state, which names the
// current file, its checksum and size, when it was built, got and last looked
// for, and the error of the last look. The state is a memory across restarts:
// what the panel uses is the file that it loads when it starts, and the
// checksum that it sends the nodes is that of the file that it loaded.
//
// # How it is got
//
// A refresh that is due asks DB-IP for the file of the current UTC month and,
// when there is none yet (a 404), for the one of the month before. It asks for
// nothing when a database of the month that it would ask for is installed
// already. The file is written to a temporary file in its directory while it is
// unpacked (gzip, by its first bytes) and its SHA-256 is taken, opened and
// verified as a country database, and only then renamed, so that a file that
// cannot be used never replaces one that can: the old database stays in use
// and the failure is noted in the state and, once for each distinct error, as
// the event geoip.failed. A database that is installed is the event
// geoip.updated. The database is read into memory and the reader is swapped in
// one atomic step; the old one is let go of.
//
// DB-IP's download is limited to 64 MiB of gzip and 256 MiB unpacked, to 30
// seconds to connect and 5 minutes in all.
package geodb

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/version"
)

// DefaultBaseURL is the directory that DB-IP publishes the database in:
// <DefaultBaseURL>/dbip-country-lite-<YYYY-MM>.mmdb.gz.
const DefaultBaseURL = "https://download.db-ip.com/free"

// The settings of the database that the manager keeps, and the events it makes.
const (
	settingEnabled = "geoip"
	settingState   = "geoip_state"

	eventUpdated = "geoip.updated"
	eventFailed  = "geoip.failed"
)

// How files are named, and how a download is asked for.
const (
	filePrefix   = "dbip-country-lite-"
	fileSuffix   = ".mmdb"
	remoteSuffix = ".mmdb.gz"
	monthLayout  = "2006-01"
	// tempPrefix starts the name of a file while it is being received. No
	// database has such a name, so a file with it is the leftover of a crash.
	tempPrefix = ".incoming-"

	sourceDownload = "download"
	sourceUpload   = "upload"
)

// The limits, as they are for the panel; fields of the Manager, so that tests
// can make them small.
const (
	defaultMaxDownload = 64 << 20 // gzip, from DB-IP
	defaultMaxUnpacked = geoip.MaxFileSize
	defaultMaxUpload   = 256 << 20 // what an admin sends, gzip or not

	connectTimeout  = 30 * time.Second
	downloadTimeout = 5 * time.Minute
	refreshEvery    = 24 * time.Hour
	// retryEvery is the wait after a look that failed, and while there is no
	// database: a day is long for a panel that has none.
	retryEvery = time.Hour
	// maxRedirects is how many redirects a download follows.
	maxRedirects = 3
	// earliestMonth is the first month that a database of DB-IP can be of.
	earliestMonth = "2000-01"

	// maxErrorLen bounds an error that is kept in the state and in an event.
	maxErrorLen = 500
)

// fileNamePattern is the name of a file that the manager makes.
var fileNamePattern = regexp.MustCompile(`^` + filePrefix + `(\d{4}-\d{2})` + regexp.QuoteMeta(fileSuffix) + `$`)

// fileName is the name of the file of a month ("2026-10").
func fileName(month string) string { return filePrefix + month + fileSuffix }

// parseFileName returns the month of a file name that the manager makes, and
// whether it is one.
func parseFileName(name string) (string, bool) {
	m := fileNamePattern.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	if _, err := time.Parse(monthLayout, m[1]); err != nil {
		return "", false
	}
	return m[1], true
}

// candidates are the months that a refresh asks for at now, in the order that it
// does: the current UTC month, then the one before.
func candidates(now time.Time) [2]string {
	u := now.UTC()
	first := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
	return [2]string{first.Format(monthLayout), first.AddDate(0, -1, 0).Format(monthLayout)}
}

// enabledSetting is the setting "geoip". Without it, or without the field, the
// database is enabled.
type enabledSetting struct {
	Enabled bool `json:"enabled"`
}

// state is the setting "geoip_state".
type state struct {
	Month       string `json:"month"`        // of the file: "2026-10"
	File        string `json:"file"`         // its name in the directory
	SHA256      string `json:"sha256"`       // of the unpacked file, lower-case hex
	Size        int64  `json:"size"`         // in bytes
	BuiltUnix   int64  `json:"built_unix"`   // from the metadata of the database
	FetchedUnix int64  `json:"fetched_unix"` // when the panel got the file
	CheckedUnix int64  `json:"checked_unix"` // when the panel last looked for a newer one
	Error       string `json:"error"`        // why the last look failed
}

// Status is what is known about the database.
type Status struct {
	// Enabled is whether country lookups are on.
	Enabled bool
	// Present is whether a database is loaded: it is, while Enabled is false.
	Present bool
	// Month is the month of the database ("2026-10"): the one that it was
	// downloaded for, or the one that it was built in when it was uploaded.
	Month string
	// Built is when the database was built. The zero time without a database.
	Built time.Time
	// Size is the size of the file, unpacked, and SHA256 its lower-case hex
	// SHA-256.
	Size   int64
	SHA256 string
	// Fetched is when the panel got this database; Checked is when it last looked
	// for a newer one, whatever came of it.
	Fetched time.Time
	Checked time.Time
	// Error is why the last look failed, or why the file that was installed
	// could not be used; empty after a look that went well.
	Error string
}

// Current is the database that the panel uses, for what sends it to the nodes.
type Current struct {
	Month  string // "2026-10"
	SHA256 string // of the file, lower-case hex
	Path   string // of the file
	Size   int64  // of the file
}

// loaded is a database in memory, and what is known of the file it came from.
type loaded struct {
	db    *geoip.DB
	month string
	file  string // its name in the directory
	sha   string
	size  int64
	built time.Time
}

// An Option changes how a Manager gets its database.
type Option func(*Manager)

// WithHTTPClient makes the manager download with c. Without it, it uses a
// client that waits 30 seconds to connect and 5 minutes for a download, and
// honours the proxy of the environment (HTTPS_PROXY).
func WithHTTPClient(c *http.Client) Option {
	return func(m *Manager) {
		if c != nil {
			m.client = c
		}
	}
}

// WithBaseURL makes the manager download from this directory instead of
// [DefaultBaseURL]: a file is <base>/dbip-country-lite-<YYYY-MM>.mmdb.gz. The
// end-to-end test points it at a closed port, and a panel behind a mirror at the
// mirror. An empty base is the default.
func WithBaseURL(base string) Option {
	return func(m *Manager) {
		if base = strings.TrimRight(strings.TrimSpace(base), "/"); base != "" {
			m.base = base
		}
	}
}

// WithNow makes the manager take the time from now: the month that it asks for,
// and the times that it keeps.
func WithNow(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

// A Manager keeps the country database of the panel; see the package comment.
// Its methods may be called from any goroutine.
type Manager struct {
	db  *store.DB
	dir string
	log *slog.Logger

	client *http.Client
	base   string
	now    func() time.Time

	// The limits and the timings; tests change them.
	maxDownload, maxUnpacked, maxUpload int64
	timeout                             time.Duration // for a download in all
	every                               time.Duration // between two refreshes
	retry                               time.Duration // between two, while there is no database or the last failed

	// enabled is the setting "geoip", kept here so that a lookup costs no read of
	// the database. cur is the database in use, nil when there is none.
	enabled atomic.Bool
	cur     atomic.Pointer[loaded]

	// op is the turn to change what is installed, one at a time: a channel and
	// not a mutex, so that a caller waits no longer than its context.
	op chan struct{}
	// kick makes the loop look now: turning the lookups on does.
	kick chan struct{}
	// setMu keeps two changes of enabled from writing the setting in one order
	// and the memory in the other.
	setMu sync.Mutex

	mu       sync.Mutex // guards onChange and started
	onChange []func()
	started  bool
	wg       sync.WaitGroup
}

// NewManager returns a manager that keeps the database in dir (made when the
// first database arrives), with its settings in db. A nil log discards the log.
// It reads nothing and starts nothing: see [Manager.Start]. Until then no
// database is loaded, and lookups find nothing.
func NewManager(db *store.DB, dir string, log *slog.Logger, opts ...Option) *Manager {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := &Manager{
		db:          db,
		dir:         dir,
		log:         log,
		client:      defaultClient(),
		base:        DefaultBaseURL,
		now:         time.Now,
		maxDownload: defaultMaxDownload,
		maxUnpacked: defaultMaxUnpacked,
		maxUpload:   defaultMaxUpload,
		timeout:     downloadTimeout,
		every:       refreshEvery,
		retry:       retryEvery,
		op:          make(chan struct{}, 1),
		kick:        make(chan struct{}, 1),
	}
	m.enabled.Store(true)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// checkRedirect is the redirect policy of the client that a manager makes: three
// hops at most, and none from https to http, since TLS is all that vouches for
// the file that comes.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if n := len(via); n > 0 && via[n-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refused a redirect from https to http")
	}
	return nil
}

// defaultClient is the client of a manager that is not given one: a download is
// bounded by 5 minutes in all (the manager bounds it by its own context as
// well), and the connection by 30 seconds.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout:       downloadTimeout,
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: connectTimeout,
			// One download a day: a connection that is kept is no use.
			IdleConnTimeout: 30 * time.Second,
			MaxIdleConns:    1,
		},
	}
}

// Start loads the database that is installed, which is done when it returns, and
// then refreshes it in the background at once and every 24 hours, until ctx is
// done; [Manager.Wait] waits for that end. Call it before anything that asks for
// a country is started. A second call does nothing.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	m.loadEnabled(ctx)
	m.loadInstalled(ctx)
	m.wg.Add(1)
	go m.loop(ctx)
}

// Wait waits until the background work that Start began is over, which it is
// once the context of Start is done. The panel waits for it before it closes the
// database.
func (m *Manager) Wait() { m.wg.Wait() }

// loop is the background refresh: at once, and then after m.every, or after
// m.retry while there is no database or the last look failed, or when the
// lookups are turned on.
func (m *Manager) loop(ctx context.Context) {
	defer m.wg.Done()
	for {
		// A refresh that fails has said so already: in the log, in the state and
		// in an event.
		st, err := m.Refresh(ctx)
		if err == nil && ctx.Err() == nil {
			m.log.Debug("looked for the country database", "month", st.Month, "enabled", st.Enabled)
		}
		wait := m.every
		if err != nil || (st.Enabled && (!st.Present || st.Error != "")) {
			wait = m.retry
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.kick:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// loadEnabled reads the setting that turns the database on and off.
func (m *Manager) loadEnabled(ctx context.Context) {
	s := enabledSetting{Enabled: true}
	if _, err := m.db.GetSetting(ctx, settingEnabled, &s); err != nil {
		m.log.Error("could not read whether the country database is enabled; taking it as enabled", "err", err)
		s.Enabled = true
	}
	m.enabled.Store(s.Enabled)
}

// loadInstalled loads the file that the state names, and the leftovers of a
// crash are cleared away first. A file that cannot be used is no database: the
// reason is kept in the state, and the next refresh makes the month again.
func (m *Manager) loadInstalled(ctx context.Context) {
	_ = m.withTurn(ctx, func() error {
		m.removeTemps()
		return nil
	})
	st, err := m.readState(ctx)
	if err != nil {
		m.log.Error("could not read what is known of the country database", "err", err)
		return
	}
	if st.File == "" {
		return
	}
	now := m.now().UTC()
	month, ok := parseFileName(st.File)
	if !ok {
		m.fail(ctx, now, fmt.Errorf("the country database that was installed cannot be used: %q is not a name that the panel gives a file", clip(st.File, 80)), false)
		return
	}
	path := filepath.Join(m.dir, st.File)
	sum, size, err := hashFile(path)
	var db *geoip.DB
	if err == nil {
		db, err = geoip.Open(path)
	}
	if err != nil {
		m.fail(ctx, now, fmt.Errorf("the country database that was installed cannot be used: %w", err), false)
		return
	}
	cur := &loaded{db: db, month: month, file: st.File, sha: sum, size: size, built: db.Info().Built}
	m.cur.Store(cur)
	m.log.Info("country database loaded", "month", month, "bytes", size)

	// The file is what is used. What the state says of it follows the file.
	if sum != st.SHA256 || size != st.Size || st.Month != month || st.BuiltUnix != cur.built.Unix() {
		m.log.Warn("the file of the country database is not the one that was noted; using the file", "file", st.File)
		st.Month, st.SHA256, st.Size, st.BuiltUnix = month, sum, size, cur.built.Unix()
		if err := m.writeState(ctx, st); err != nil {
			m.log.Error("could not note the country database that was loaded", "err", err)
		}
	}
}

// hashFile returns the SHA-256 of the file at path, in lower-case hex, and its
// size. It reads no more than a database may be.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, geoip.MaxFileSize+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Country returns the code of the country of ip, "DE", or "" when the database
// is disabled, when there is none, when it does not have the address, and for
// the zero address. It is cheap and safe to call from any goroutine.
func (m *Manager) Country(ip netip.Addr) string {
	if !m.enabled.Load() {
		return ""
	}
	cur := m.cur.Load()
	if cur == nil {
		return ""
	}
	return cur.db.Country(ip)
}

// Current returns the database that is in use: false while lookups are disabled
// and when there is no database. It is what is sent to the nodes.
func (m *Manager) Current() (Current, bool) {
	if !m.enabled.Load() {
		return Current{}, false
	}
	cur := m.cur.Load()
	if cur == nil {
		return Current{}, false
	}
	return Current{Month: cur.month, SHA256: cur.sha, Path: filepath.Join(m.dir, cur.file), Size: cur.size}, true
}

// OnChange registers fn to be called after a database is installed and after
// lookups are turned on or off, which is when [Manager.Current] may have
// changed. It is called on the goroutine that made the change, once that change
// is complete and nothing is held, so fn may call the manager. A nil fn is
// ignored.
func (m *Manager) OnChange(fn func()) {
	if fn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, fn)
}

// fire calls what OnChange registered.
func (m *Manager) fire() {
	m.mu.Lock()
	fns := slices.Clone(m.onChange)
	m.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// SetEnabled turns country lookups on or off, and keeps it. Off, the manager
// asks DB-IP for nothing and finds no country; the file stays, and is in use
// again when they are turned on, and the loop looks for a newer one at once.
// OnChange is told when the setting changed.
func (m *Manager) SetEnabled(ctx context.Context, on bool) (Status, error) {
	m.setMu.Lock()
	changed := m.enabled.Load() != on
	err := m.db.PutSetting(ctx, settingEnabled, enabledSetting{Enabled: on})
	if err == nil {
		m.enabled.Store(on)
	}
	m.setMu.Unlock()
	if err != nil {
		return Status{}, err
	}
	if changed {
		if on {
			// Look now, and not at the next turn of the loop, which may be a
			// day away. A kick that is waiting already is enough.
			select {
			case m.kick <- struct{}{}:
			default:
			}
		}
		m.fire()
	}
	return m.Status(ctx)
}

// Status says what is known about the database now: the database in use, and
// when the panel got it and last looked for a newer one.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	st, err := m.readState(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{Enabled: m.enabled.Load(), Checked: unixTime(st.CheckedUnix), Error: st.Error}
	if cur := m.cur.Load(); cur != nil {
		out.Present = true
		out.Month, out.Built, out.Size, out.SHA256 = cur.month, cur.built, cur.size, cur.sha
		out.Fetched = unixTime(st.FetchedUnix)
	}
	return out, nil
}

// unixTime is the time of a Unix time that is kept; 0 is no time.
func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// acquire waits for the turn to change what is installed, no longer than ctx.
func (m *Manager) acquire(ctx context.Context) error {
	select {
	case m.op <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) release() { <-m.op }

// withTurn runs fn with the turn to change what is installed, and gives the turn
// back however fn ends, a panic included: a turn that is kept would leave every
// refresh and upload after it waiting for ever.
func (m *Manager) withTurn(ctx context.Context, fn func() error) error {
	if err := m.acquire(ctx); err != nil {
		return err
	}
	defer m.release()
	return fn()
}

// Refresh looks for a newer database now, as the background loop does every
// day, and returns the status after it. It does nothing, and returns the
// status, while lookups are disabled.
//
// A refresh that cannot get a database returns the error, and the status that
// has it in Error; the database that was there stays in use. A refresh that is
// ended by its context is not a verdict on DB-IP: it returns the error of the
// context and notes nothing. Refreshes and uploads are one at a time, so several
// refreshes that come together make one download.
func (m *Manager) Refresh(ctx context.Context) (Status, error) {
	var changed bool
	var err error
	if turn := m.withTurn(ctx, func() error {
		changed, err = m.refresh(ctx)
		return nil
	}); turn != nil {
		return Status{}, turn
	}
	if changed {
		m.fire()
	}
	if err != nil && ctx.Err() != nil {
		return Status{}, err
	}
	st, serr := m.Status(ctx)
	if serr != nil {
		return Status{}, serr // the database of the panel failed: that is the error
	}
	return st, err
}

// refresh is Refresh with the turn taken. It reports whether it installed a
// database.
func (m *Manager) refresh(ctx context.Context) (bool, error) {
	if !m.enabled.Load() {
		return false, nil
	}
	now := m.now().UTC()
	f, err := m.look(ctx, now)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		m.fail(ctx, now, err, true)
		return false, &failure{err}
	}
	if f == nil {
		// What DB-IP has is here already: the look is the news.
		return false, m.checked(ctx, now)
	}
	defer f.discard()
	if err := m.install(ctx, f, sourceDownload, now); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		m.fail(ctx, now, err, true)
		return false, &failure{err}
	}
	return true, nil
}

// failure is the error of a refresh that did not get a database and has noted
// that: in the state, in the log and, when it was a new one, in an event. It is
// told from the error of a refresh that could not do its work at all, because
// the database of the panel failed, which has noted nothing: the first is in
// the status that the refresh returns, the second is the panel's own fault.
type failure struct{ err error }

func (f *failure) Error() string { return cleanText(f.err) }

func (f *failure) Unwrap() error { return f.err }

// look finds out whether DB-IP has a newer database than the one installed, and
// downloads it if it has: the file of the current month, or of the month before
// when DB-IP answers 404 for the current one. It returns nil, and no error, when
// the month that it would ask for is installed.
func (m *Manager) look(ctx context.Context, now time.Time) (*fetched, error) {
	months := candidates(now)
	for _, month := range months {
		// A database of this month or of a later one is what this month would
		// bring.
		if cur := m.cur.Load(); cur != nil && cur.month >= month {
			return nil, nil
		}
		f, err := m.download(ctx, month)
		if errors.Is(err, errNotPublished) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	return nil, fmt.Errorf("no country database for %s or %s at %s", months[0], months[1], hostOf(m.base))
}

// errNotPublished is the answer of DB-IP that the file of a month is not there.
var errNotPublished = errors.New("geodb: the file is not published")

// fetched is a database that has been received and opened, and is waiting to be
// installed.
type fetched struct {
	rc    received
	db    *geoip.DB
	month string
}

// discard removes what is left of the received file, if it was not installed.
func (f *fetched) discard() {
	if f.rc.path != "" {
		_ = os.Remove(f.rc.path)
		f.rc.path = ""
	}
}

// download gets the file of a month from DB-IP: 404 is errNotPublished.
func (m *Manager) download(ctx context.Context, month string) (*fetched, error) {
	target := m.base + "/" + filePrefix + month + remoteSuffix
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("could not ask for the country database: %w", err)
	}
	req.Header.Set("User-Agent", "postern/"+version.Version)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not download the country database from %s: %w", hostOf(target), err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNotPublished
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s answered %s", hostOf(target), resp.Status)
	case resp.ContentLength > m.maxDownload:
		return nil, &sizeError{what: "download", limit: m.maxDownload}
	}
	f, err := m.accept(&capReader{r: resp.Body, left: m.maxDownload, what: "download", limit: m.maxDownload})
	if err != nil {
		return nil, err
	}
	f.month = month
	return f, nil
}

// Install installs the database that r holds as the current one: the file as it
// is, or gzipped as DB-IP publishes it, told by its first bytes. Its month is
// the month that it was built in. It reads at most 256 MiB, and the database
// may be no larger than that unpacked.
//
// A file that is not a usable country database is an error that is
// geoip.ErrInvalid, and nothing changes: the database that was there stays in
// use, and nothing is noted of it, since the caller is told. An upload does not
// wait for a refresh that is under way for longer than ctx.
func (m *Manager) Install(ctx context.Context, r io.Reader) (Status, error) {
	if err := m.withTurn(ctx, func() error { return m.upload(ctx, r) }); err != nil {
		return Status{}, err
	}
	m.fire()
	return m.Status(ctx)
}

// upload is Install with the turn taken.
func (m *Manager) upload(ctx context.Context, r io.Reader) error {
	f, err := m.accept(&capReader{r: r, left: m.maxUpload, what: "upload", limit: m.maxUpload})
	if err != nil {
		return err
	}
	defer f.discard()
	now := m.now().UTC()
	f.month = f.db.Info().Built.UTC().Format(monthLayout)
	if err := plausibleMonth(f.month, now); err != nil {
		return err
	}
	return m.install(ctx, f, sourceUpload, now)
}

// accept receives a file from src, which may be gzip, and opens it as a country
// database, which verifies it. The file that it made is removed when it is not
// one.
func (m *Manager) accept(src io.Reader) (*fetched, error) {
	rc, err := m.receive(src)
	if err != nil {
		return nil, err
	}
	db, err := geoip.Open(rc.path)
	if err != nil {
		_ = os.Remove(rc.path)
		return nil, err
	}
	return &fetched{rc: rc, db: db}, nil
}

// received is a database that has been written to a temporary file.
type received struct {
	path string // of the file: the database, unpacked
	size int64
	sum  string // its SHA-256, lower-case hex
}

// receive writes what src holds to a new temporary file in the directory of the
// databases. If it starts with the magic bytes of gzip it is unpacked on the
// way, to at most m.maxUnpacked bytes. The SHA-256 is that of what was written.
func (m *Manager) receive(src io.Reader) (received, error) {
	br := bufio.NewReader(src)
	head, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return received{}, readError(err)
	}
	var in io.Reader = br
	what := "database"
	zipped := len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b
	if zipped {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return received{}, unpackError(err)
		}
		defer func() { _ = zr.Close() }()
		in, what = zr, "unpacked database"
	}

	// 0755: the directory holds public data, like the engines that the panel
	// keeps for the nodes.
	if err := os.MkdirAll(m.dir, 0o755); err != nil { //nolint:gosec // G301: public data, see above
		return received{}, fmt.Errorf("could not make the directory of the country databases: %w", err)
	}
	tmp, err := os.CreateTemp(m.dir, tempPrefix+"*")
	if err != nil {
		return received{}, fmt.Errorf("could not make a file for the country database: %w", err)
	}
	kept := false
	defer func() {
		if !kept {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), &capReader{r: in, left: m.maxUnpacked, what: what, limit: m.maxUnpacked})
	if err != nil {
		if zipped {
			return received{}, unpackError(err)
		}
		return received{}, readError(err)
	}
	// The file is public data: everyone may read it.
	if err := tmp.Chmod(0o644); err != nil {
		return received{}, fmt.Errorf("could not write the country database: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return received{}, fmt.Errorf("could not write the country database: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return received{}, fmt.Errorf("could not write the country database: %w", err)
	}
	kept = true
	return received{path: tmp.Name(), size: n, sum: hex.EncodeToString(h.Sum(nil))}, nil
}

// readError is the error of reading a file that is not the file's fault: a
// size that is too large says so, anything else is what went wrong.
func readError(err error) error {
	var tooLarge *sizeError
	if errors.As(err, &tooLarge) {
		return err
	}
	return fmt.Errorf("could not read the country database: %w", err)
}

// unpackError is the error of unpacking a gzip file. What is wrong with the data
// is the file's fault, which is geoip.ErrInvalid; what is wrong with what
// delivers it (a connection that broke) is not.
func unpackError(err error) error {
	var tooLarge *sizeError
	var corrupt flate.CorruptInputError
	switch {
	case errors.As(err, &tooLarge):
		return err
	case errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &corrupt):
		return &badFileError{err: fmt.Errorf("could not unpack the gzip file: %w", err)}
	}
	return fmt.Errorf("could not read the country database: %w", err)
}

// badFileError is an error that is the file's, not the panel's: it is
// geoip.ErrInvalid for errors.Is, as the errors of geoip.Open are.
type badFileError struct{ err error }

func (e *badFileError) Error() string { return e.err.Error() }

func (e *badFileError) Unwrap() error { return e.err }

func (e *badFileError) Is(target error) bool { return target == geoip.ErrInvalid }

// sizeError is the error of a file that is larger than it may be.
type sizeError struct {
	what  string // "download", "upload", "unpacked database"
	limit int64
}

func (e *sizeError) Error() string {
	return fmt.Sprintf("the %s is larger than %s", e.what, geoip.SizeText(e.limit))
}

func (e *sizeError) Is(target error) bool { return target == geoip.ErrInvalid }

// capReader reads from r and fails with a *sizeError as soon as there is more
// than limit bytes. io.LimitReader would end the data there, which looks like a
// file that was cut short, and not like one that is too large.
type capReader struct {
	r     io.Reader
	left  int64
	what  string
	limit int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, &sizeError{what: c.what, limit: c.limit}
	}
	// One byte beyond the cap is read, to know whether there is more.
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, &sizeError{what: c.what, limit: c.limit}
	}
	return n, err
}

// install makes a received database the current one, as the one of f.month: the
// file is renamed into its place, the state is written, and only then the
// database in memory is replaced. It runs with the turn taken.
func (m *Manager) install(ctx context.Context, f *fetched, source string, now time.Time) error {
	name := fileName(f.month)
	if err := os.Rename(f.rc.path, filepath.Join(m.dir, name)); err != nil {
		return fmt.Errorf("could not put the country database in its place: %w", err)
	}
	f.rc.path = "" // moved: nothing of it is left to discard
	syncDir(m.dir)

	st, err := m.readState(ctx)
	if err != nil {
		return err
	}
	built := f.db.Info().Built
	st.Month, st.File, st.SHA256, st.Size, st.BuiltUnix = f.month, name, f.rc.sum, f.rc.size, built.Unix()
	st.FetchedUnix = now.Unix()
	if source == sourceDownload {
		st.CheckedUnix = now.Unix() // an upload is no look at DB-IP
	}
	st.Error = ""
	if err := m.writeState(ctx, st); err != nil {
		return err
	}
	m.cur.Store(&loaded{db: f.db, month: f.month, file: name, sha: f.rc.sum, size: f.rc.size, built: built})
	m.prune(name)
	m.log.Info("country database installed", "month", f.month, "bytes", f.rc.size, "source", source)
	m.event(ctx, eventUpdated, "info", "the country database is now the one of "+f.month, map[string]string{
		"month":  f.month,
		"source": source,
		"sha256": f.rc.sum,
		"size":   fmt.Sprint(f.rc.size),
	})
	return nil
}

// checked notes that the panel has looked, and that what it has is what DB-IP
// has: there is nothing to report, and an error that it reported before is over.
func (m *Manager) checked(ctx context.Context, now time.Time) error {
	st, err := m.readState(ctx)
	if err != nil {
		return err
	}
	st.CheckedUnix = now.Unix()
	st.Error = ""
	return m.writeState(ctx, st)
}

// fail notes that getting a database failed: in the log, in the state, and, when
// the error is not the one that is noted already, as an event. looked says
// whether it was a look at DB-IP, which is noted as one.
func (m *Manager) fail(ctx context.Context, now time.Time, cause error, looked bool) {
	msg := clip(cleanText(cause), maxErrorLen)
	m.log.Warn("could not get the country database", "err", msg)
	st, err := m.readState(ctx)
	if err != nil {
		m.log.Error("could not read what is known of the country database", "err", err)
		return
	}
	first := st.Error != msg
	if looked {
		st.CheckedUnix = now.Unix()
	}
	st.Error = msg
	if err := m.writeState(ctx, st); err != nil {
		m.log.Error("could not note why the country database failed", "err", err)
		return
	}
	if first {
		m.event(ctx, eventFailed, "warn", msg, nil)
	}
}

// event records an event that is about neither a node nor a proxy. A failure is
// logged and goes no further.
func (m *Manager) event(ctx context.Context, kind, severity, message string, details map[string]string) {
	ev := &store.Event{Kind: kind, Severity: severity, Message: message, Details: details}
	if err := m.db.AppendEvent(ctx, ev); err != nil && ctx.Err() == nil {
		m.log.Error("could not record an event", "kind", kind, "err", err)
	}
}

// readState reads the setting "geoip_state"; without it, nothing is known.
func (m *Manager) readState(ctx context.Context) (state, error) {
	var st state
	if _, err := m.db.GetSetting(ctx, settingState, &st); err != nil {
		return state{}, err
	}
	return st, nil
}

func (m *Manager) writeState(ctx context.Context, st state) error {
	return m.db.PutSetting(ctx, settingState, st)
}

// prune removes what the directory holds that is not wanted: the leftovers of a
// crash, and every database but the one named keep and the newest of the others,
// which is the database before it. What is not a file that the manager makes is
// left alone. It runs with the turn taken.
func (m *Manager) prune(keep string) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		m.log.Warn("could not list the country databases", "err", err)
		return
	}
	type database struct{ name, month string }
	var others []database
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		if strings.HasPrefix(name, tempPrefix) {
			m.remove(name)
			continue
		}
		if month, ok := parseFileName(name); ok && name != keep {
			others = append(others, database{name, month})
		}
	}
	slices.SortFunc(others, func(a, b database) int { return strings.Compare(b.month, a.month) })
	for i, o := range others {
		if i > 0 {
			m.remove(o.name)
		}
	}
}

// removeTemps removes the leftovers of a crash. It runs with the turn taken.
func (m *Manager) removeTemps() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return // no directory yet is nothing to clear
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), tempPrefix) {
			m.remove(e.Name())
		}
	}
}

func (m *Manager) remove(name string) {
	if err := os.Remove(filepath.Join(m.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.log.Warn("could not remove a file of the country databases", "file", name, "err", err)
	}
}

// syncDir flushes the entry of a new file to disk. Not every system can flush a
// directory, and the file itself is flushed already, so an error is ignored.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// plausibleMonth refuses the month of an uploaded database that no database of
// DB-IP can be of: before 2000-01, or later than next month (a clock that is
// ahead by a day is allowed). The month is the file's own word. One that is
// absurd would never be pruned, would not survive a restart, or, above every
// real month, would keep the panel from ever downloading again.
func plausibleMonth(month string, now time.Time) error {
	t, err := time.Parse(monthLayout, month)
	first, _ := time.Parse(monthLayout, earliestMonth)
	u := now.UTC()
	last := time.Date(u.Year(), u.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	if err != nil || t.Before(first) || t.After(last) {
		return &badFileError{err: fmt.Errorf("the database says that it was built in %s: a database of DB-IP is of a month from %s to %s", clip(month, 24), earliestMonth, last.Format(monthLayout))}
	}
	return nil
}

// hostOf is the host of an address, with its port if it has one: nothing of the
// user name, the password, the path or the query, which a mirror may use for a
// secret. "" for an address that cannot be read.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// cleanText is the text of an error without what must not be kept in the state,
// in an event, in a log or on a screen: the address of a request, which may carry
// a user name and a path with a token (a *url.Error is its reason), and the
// paths of the disk of the panel (a *fs.PathError or *os.LinkError is its
// operation and its reason).
func cleanText(err error) string {
	msg := err.Error()
	var walk func(e error)
	walk = func(e error) {
		switch v := e.(type) {
		case *url.Error:
			msg = strings.ReplaceAll(msg, v.Error(), reasonText(v.Err))
		case *fs.PathError:
			msg = strings.ReplaceAll(msg, v.Error(), v.Op+": "+reasonText(v.Err))
		case *os.LinkError:
			msg = strings.ReplaceAll(msg, v.Error(), v.Op+": "+reasonText(v.Err))
		}
		switch u := e.(type) {
		case interface{ Unwrap() error }:
			if next := u.Unwrap(); next != nil {
				walk(next)
			}
		case interface{ Unwrap() []error }:
			for _, next := range u.Unwrap() {
				walk(next)
			}
		}
	}
	walk(err)
	return msg
}

// reasonText is the cleaned text of the reason inside an error of a request or
// of the disk.
func reasonText(err error) string {
	if err == nil {
		return ""
	}
	return cleanText(err)
}

// clip cuts s to at most n bytes, at the end of a character, and marks the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}
