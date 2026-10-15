package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/geoip"
)

const (
	// maxGeoIPUpload is the largest country database UploadGeoIP takes.
	maxGeoIPUpload = geoip.MaxFileSize
	// geoIPEvery is how often the loader looks at the desired database.
	geoIPEvery = 60 * time.Second
	// geoIPMissingAfter is how long a named database may be missing before
	// the event geoip_missing.
	geoIPMissingAfter = 10 * time.Minute

	evGeoIPStored  = "geoip_stored"
	evGeoIPLoaded  = "geoip_loaded"
	evGeoIPMissing = "geoip_missing"
)

// geoIPFileRe is the name of a stored database: data/geoip/<sha256>.mmdb.
var geoIPFileRe = regexp.MustCompile(`^[0-9a-f]{64}\.mmdb$`)

// geoStore keeps the country databases the panel uploads, each as
// data/geoip/<sha256>.mmdb, and the one the desired state names loaded in
// memory, for the countries of the minute statistics (spec 8.6: the node
// looks the addresses up, so that none leaves it under the countries policy).
type geoStore struct {
	dir       string
	now       func() time.Time
	event     func(kind, severity, msg string, details map[string]string)
	log       *slog.Logger
	maxUpload int64

	db       atomic.Pointer[geoip.DB] // the loaded database, nil for none
	uploadMu sync.Mutex               // one upload at a time

	mu           sync.Mutex
	loaded       string // the sha256 of db
	wanted       string // the sha256 the desired state names
	missingSince time.Time
	missingSaid  bool
	announced    map[string]bool // geoip_loaded went out for these
}

func newGeoStore(dir string, now func() time.Time, event func(kind, severity, msg string, details map[string]string), log *slog.Logger) *geoStore {
	return &geoStore{dir: dir, now: now, event: event, log: log, maxUpload: maxGeoIPUpload, announced: map[string]bool{}}
}

func (g *geoStore) path(sha string) string { return filepath.Join(g.dir, sha+".mmdb") }

// country is the country (ISO 3166 alpha-2) of a client address in the
// loaded database, "" without one or when it does not know the address.
func (g *geoStore) country(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return g.db.Load().Country(addr)
}

// loadedSHA is the sha256 of the loaded database, "" for none.
func (g *geoStore) loadedSHA() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.loaded
}

// stored lists the sha256 of every stored database, sorted.
func (g *geoStore) stored() []string {
	entries, err := os.ReadDir(g.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && geoIPFileRe.MatchString(e.Name()) {
			out = append(out, strings.TrimSuffix(e.Name(), ".mmdb"))
		}
	}
	slices.Sort(out)
	return out
}

// put stores the database of the given sha256 (lower-case hex), its chunks
// read with next until io.EOF. It answers at once, without reading the
// chunks, when the file is there already. The file is written to a temporary
// file beside the others, its sha256 checked, opened as a country database,
// then renamed. Afterwards every stored file is deleted but the new one and
// those keep names. fresh says whether the file was stored now.
func (g *geoStore) put(sha string, next func() ([]byte, error), keep func() []string) (fresh bool, err error) {
	g.uploadMu.Lock()
	defer g.uploadMu.Unlock()
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return false, connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	if err := os.Chmod(g.dir, 0o700); err != nil { //nolint:gosec // a directory: 0700 is the least that lets its owner in
		return false, connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	final := g.path(sha)
	if st, err := os.Stat(final); err == nil && st.Mode().IsRegular() {
		g.cleanup(append(keep(), sha))
		return false, nil
	}
	if err := g.receive(sha, final, next); err != nil {
		return false, err
	}
	g.cleanup(append(keep(), sha))
	return true, nil
}

func (g *geoStore) receive(sha, final string, next func() ([]byte, error)) (err error) {
	tmp, err := os.CreateTemp(g.dir, ".upload-*")
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	h := sha256.New()
	w := io.MultiWriter(tmp, h)
	var total int64
	for {
		chunk, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		total += int64(len(chunk))
		if total > g.maxUpload {
			return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("the database is over %s", geoip.SizeText(g.maxUpload)))
		}
		if _, err := w.Write(chunk); err != nil {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
		}
	}
	if err := tmp.Sync(); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the database's sha256 is %s, not %s", got, sha))
	}
	if _, err := geoip.Open(tmp.Name()); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("the node cannot store the database: %w", err))
	}
	return nil
}

// cleanup deletes every stored database, and every leftover upload, but
// those of the sha256 in keep. uploadMu is held.
func (g *geoStore) cleanup(keep []string) {
	entries, err := os.ReadDir(g.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, ".upload-"):
		case geoIPFileRe.MatchString(name) && !slices.Contains(keep, strings.TrimSuffix(name, ".mmdb")):
		default:
			continue
		}
		if err := os.Remove(filepath.Join(g.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			g.log.Warn("agent: a country database could not be deleted", "file", name, "err", err)
		}
	}
}

// sync makes the database ref names the loaded one: it opens a stored file
// that is not loaded yet and swaps it in; no ref unloads. A named file that
// is missing leaves the loaded one as it is, and is reported once when it
// stays missing for geoIPMissingAfter. A stored file that is not a usable
// database is deleted, so that GetInfo no longer lists it and the panel
// uploads it again.
func (g *geoStore) sync(ref *nodev1.GeoIPRef) {
	want := strings.ToLower(ref.GetSha256())
	g.mu.Lock()
	defer g.mu.Unlock()
	if want != g.wanted {
		g.wanted, g.missingSince, g.missingSaid = want, time.Time{}, false
	}
	if want == "" {
		if g.loaded != "" {
			g.db.Store(nil)
			g.loaded = ""
			g.log.Info("agent: the country database is unloaded")
		}
		return
	}
	if want == g.loaded {
		return
	}
	db, err := geoip.Open(g.path(want))
	if err != nil {
		if errors.Is(err, geoip.ErrInvalid) {
			g.log.Warn("agent: a stored country database cannot be used; it is deleted", "sha256", want, "err", err)
			_ = os.Remove(g.path(want))
		}
		g.missing(want, ref.GetMonth())
		return
	}
	g.db.Store(db)
	g.loaded, g.missingSince, g.missingSaid = want, time.Time{}, false
	g.log.Info("agent: country database loaded", "sha256", want, "month", clipText(ref.GetMonth(), 16))
	if !g.announced[want] {
		g.announced[want] = true
		g.event(evGeoIPLoaded, sevInfo, "country database "+want+" loaded",
			map[string]string{"sha256": want, "month": clipText(ref.GetMonth(), 16)})
	}
}

// missing notes that the named database is not there. g.mu is held.
func (g *geoStore) missing(want, month string) {
	now := g.now()
	if g.missingSince.IsZero() {
		g.missingSince = now
		return
	}
	if g.missingSaid || now.Sub(g.missingSince) < geoIPMissingAfter {
		return
	}
	g.missingSaid = true
	g.log.Warn("agent: the country database the desired state names is missing", "sha256", want)
	g.event(evGeoIPMissing, sevWarning,
		fmt.Sprintf("the country database %s that the desired state names has been missing for %v", want, geoIPMissingAfter),
		map[string]string{"sha256": want, "month": clipText(month, 16)})
}

// geoIPLoop runs the loader every geoIPEvery until ctx ends.
func geoIPLoop(ctx context.Context, s *Service, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncGeoIP()
		}
	}
}

// ---- UploadGeoIP ------------------------------------------------------------------

// UploadGeoIP receives a country database: the first message is its
// reference (meta), the rest are chunks of the file, at most 256 MiB in all.
// The file must have the sha256 of meta and be a country database; it is
// kept as data/geoip/<sha256>.mmdb, with the one the desired state names and
// the one loaded; the others are deleted.
func (s *Service) UploadGeoIP(_ context.Context, stream *connect.ClientStream[nodev1.UploadGeoIPRequest]) (*connect.Response[nodev1.UploadGeoIPResponse], error) {
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the upload is empty: the first message must be meta"))
	}
	meta := stream.Msg().GetMeta()
	if meta == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the first message of an upload must be meta, not a chunk"))
	}
	sha := strings.ToLower(meta.GetSha256())
	if len(sha) != 64 || !isLowerHex(sha) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("meta.sha256 must be 64 hex characters"))
	}
	month := clipText(meta.GetMonth(), 16)
	next := func() ([]byte, error) {
		if !stream.Receive() {
			if err := stream.Err(); err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		if stream.Msg().GetMeta() != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("meta may only be the first message of an upload"))
		}
		return stream.Msg().GetChunk(), nil
	}
	fresh, err := s.geo.put(sha, next, s.geoKeep)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeInternal {
			s.log.Error("agent: country database not stored", "sha256", sha, "err", err)
		} else {
			s.log.Warn("agent: country database refused", "sha256", sha, "err", err)
		}
		return nil, err
	}
	if fresh {
		s.log.Info("agent: country database stored", "sha256", sha, "month", month)
		s.event(evGeoIPStored, sevInfo, "country database "+sha+" stored", map[string]string{"sha256": sha, "month": month})
		s.syncGeoIP() // the desired state may name it already
	}
	return connect.NewResponse(&nodev1.UploadGeoIPResponse{Stored: true, Sha256: sha}), nil
}

// geoKeep is the databases an upload keeps besides its own: the one the
// desired state names and the one loaded.
func (s *Service) geoKeep() []string {
	s.mu.Lock()
	want := strings.ToLower(s.geoRef.GetSha256())
	s.mu.Unlock()
	return []string{want, s.geo.loadedSHA()}
}

// syncGeoIP runs the loader for the database of the desired state.
func (s *Service) syncGeoIP() {
	s.mu.Lock()
	ref := s.geoRef
	s.mu.Unlock()
	s.geo.sync(ref)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
