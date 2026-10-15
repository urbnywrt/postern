package insights

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/geodb"
)

// The defaults of GeoIPSync.
const (
	geoipChunkSize     = 64 << 10         // bytes of one chunk of an upload
	geoipUploadTimeout = 10 * time.Minute // for one upload in all
	geoipRetryAfter    = 30 * time.Minute // a failed (node, sha256) is tried again after this
	// geoipAttempts is how often an upload is started again when the file
	// changed while it was read (the database of the month was replaced).
	geoipAttempts = 3
)

// errFileChanged is a file whose bytes were not those of the database that it
// was opened for: it was replaced while it was read.
var errFileChanged = errors.New("the country database was replaced while it was read")

// GeoIPSync gives the nodes the country database that their state names: it
// is a nodes.ArtifactEnsurer. Before a state that names a database goes to a
// node, the database is uploaded with UploadGeoIP unless the node holds it
// (GetInfo.geoip_stored). The file is the one of geodb.Manager.Current. An
// upload that failed is not tried again for the same node and database
// within 30 minutes.
type GeoIPSync struct {
	current    func() (geodb.Current, bool)
	chunkSize  int
	timeout    time.Duration
	retryAfter time.Duration
	now        func() time.Time
	log        *slog.Logger

	mu     sync.Mutex
	failed map[geoipKey]time.Time // when the upload last failed
}

type geoipKey struct{ node, sha string }

// NewGeoIPSync returns the sync of the database that current names (the
// Current of the country database of the panel). A nil log discards the log.
func NewGeoIPSync(current func() (geodb.Current, bool), log *slog.Logger) *GeoIPSync {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &GeoIPSync{
		current: current, chunkSize: geoipChunkSize, timeout: geoipUploadTimeout, retryAfter: geoipRetryAfter,
		now: time.Now, log: log, failed: map[geoipKey]time.Time{},
	}
}

// EnsureArtifacts uploads the country database that the state names when the
// node does not hold it.
func (g *GeoIPSync) EnsureArtifacts(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse, st *nodev1.NodeState, c nodev1connect.NodeServiceClient) error {
	ref := st.GetSettings().GetGeoip()
	if ref == nil {
		return nil
	}
	want := strings.ToLower(ref.GetSha256())
	if slices.ContainsFunc(info.GetGeoipStored(), func(s string) bool { return strings.EqualFold(s, want) }) {
		return nil
	}
	key := geoipKey{nodeID, want}
	g.mu.Lock()
	last, failed := g.failed[key]
	g.mu.Unlock()
	if failed && g.now().Before(last.Add(g.retryAfter)) {
		return fmt.Errorf("the upload of country database %s failed; it is tried again %s after the failure", want, g.retryAfter)
	}

	var err error
	for range geoipAttempts {
		cur, ok := g.current()
		if !ok || !strings.EqualFold(cur.SHA256, want) {
			// The state is older than the database of the panel; the change of
			// the database brings a new state.
			return fmt.Errorf("the state names country database %s, which the panel does not have now", want)
		}
		err = g.upload(ctx, c, cur, want, ref.GetMonth())
		if !errors.Is(err, errFileChanged) {
			break
		}
	}
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, errFileChanged) {
			g.mu.Lock()
			g.failed[key] = g.now()
			g.mu.Unlock()
		}
		return fmt.Errorf("upload country database %s: %w", want, err)
	}
	g.mu.Lock()
	delete(g.failed, key)
	g.mu.Unlock()
	g.log.Info("uploaded the country database to the node", "node", nodeID, "sha256", want, "month", ref.GetMonth())
	return nil
}

// upload streams the file of cur to the node: meta, then chunks. The bytes
// are hashed on the way, and a file that is not the database it was opened
// for (it was replaced meanwhile) is not sent to the end: the stream is
// aborted, so that the node takes nothing, and errFileChanged returned.
func (g *GeoIPSync) upload(ctx context.Context, c nodev1connect.NodeServiceClient, cur geodb.Current, want, month string) error {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	f, err := os.Open(cur.Path)
	if err != nil {
		return fmt.Errorf("open the database: %w", err)
	}
	defer func() { _ = f.Close() }()

	stream := c.UploadGeoIP(ctx)
	abort := func() {
		cancel()
		_, _ = stream.CloseAndReceive()
	}
	// result is the answer of the node, which may come before every chunk is
	// sent: a node that holds the database already answers at once, and Send
	// then says io.EOF.
	result := func() error {
		resp, err := stream.CloseAndReceive()
		if err != nil {
			return err
		}
		switch {
		case !resp.Msg.GetStored():
			return errors.New("the node did not store it")
		case !strings.EqualFold(resp.Msg.GetSha256(), want):
			return fmt.Errorf("the node stored sha256 %.64q", resp.Msg.GetSha256())
		}
		return nil
	}
	send := func(req *nodev1.UploadGeoIPRequest) (done bool, err error) {
		err = stream.Send(req)
		switch {
		case err == nil:
			return false, nil
		case errors.Is(err, io.EOF):
			return true, result()
		}
		_, _ = stream.CloseAndReceive()
		return true, err
	}
	meta := &nodev1.UploadGeoIPRequest{Part: &nodev1.UploadGeoIPRequest_Meta{Meta: &nodev1.GeoIPRef{Month: month, Sha256: want}}}
	if done, err := send(meta); done {
		return err
	}
	h := sha256.New()
	for {
		// A buffer per chunk: a message must not change once it is sent.
		chunk := make([]byte, g.chunkSize)
		n, rerr := io.ReadFull(f, chunk)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			abort()
			return fmt.Errorf("read the database: %w", rerr)
		}
		if n > 0 {
			h.Write(chunk[:n])
			if done, err := send(&nodev1.UploadGeoIPRequest{Part: &nodev1.UploadGeoIPRequest_Chunk{Chunk: chunk[:n]}}); done {
				return err
			}
		}
		if rerr != nil {
			break
		}
	}
	// The stream is not closed yet, so the node has not taken the file: one
	// that is not the database is aborted before it ends.
	if hex.EncodeToString(h.Sum(nil)) != want {
		abort()
		return errFileChanged
	}
	return result()
}
