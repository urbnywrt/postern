package proxies

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The engines, by the names of their binaries, which are their names in the
// release catalog, and the built-in version of each (the stable channel before
// any signed list; the migration seeds the channels with it).
const (
	EngineTelemt         = "telemt"
	DefaultTelemtVersion = "3.5.13"
	EngineMtg            = "mtg"
	DefaultMtgVersion    = "v2.2.8"
)

// The providers of egresses, by the names of their binaries: Xray runs the
// egresses of kind xray-uri, xray-subscription and warp, and Psiphon's own
// client (psiphon-core, whose binary is psiphon-tunnel-core) those of kind
// psiphon.
const (
	EngineXray                = "xray"
	DefaultXrayVersion        = "v26.3.27"
	EnginePsiphonCore         = "psiphon-core"
	DefaultPsiphonCoreVersion = "20261005-c4a09096ab"
)

// The capability a node needs for the trial fields of an upload and the state
// of its artifacts to count (an older node leaves them unset).
const CapArtifactTrial = "artifact-trial"

// The states of an artifact as a node reports them (ArtifactRef.state).
const (
	artifactUntried  = "untried"
	artifactUnusable = "unusable"
)

// Limits of the uploads.
const (
	// defaultUploadTimeout bounds the upload of one artifact: the manager
	// calls EnsureArtifacts in line, before it applies a state, and it must
	// get an answer.
	defaultUploadTimeout = 2 * time.Minute
	// defaultChunkSize is the size of the messages of an upload.
	defaultChunkSize = 256 << 10
	// prepareTimeout bounds a background Prepare: a download of up to 5 min
	// per architecture and its checks.
	prepareTimeout = 15 * time.Minute
	// defaultPrepareWait is how long EnsureArtifacts waits for the Prepare
	// of an asset that a state names before it leaves the upload to a later
	// resync: an engine archive is a few megabytes, so the common case is
	// served in line, as the first state of a fresh panel needs.
	defaultPrepareWait = 2 * time.Minute
)

// Catalog is the release catalog as the proxies see it: the artifacts that
// desired states name, and the uploads of them to the nodes that need them,
// the ArtifactEnsurer of the node manager. It is an adapter over
// releases.Catalog, which tracks, downloads and verifies the releases.
type Catalog struct {
	rel *releases.Catalog
	log *slog.Logger

	uploadTimeout time.Duration
	chunkSize     int

	// prepare prepares an asset that a state names and the catalog has not
	// prepared yet, in the background (releases.Catalog.Prepare), and
	// returns a channel closed when the Prepare ends. Tests replace it.
	prepare     func(component, version, arch string) <-chan struct{}
	prepareWait time.Duration

	mu        sync.Mutex
	preparing map[string]chan struct{} // component/version/arch being prepared → closed at its end
	wg        sync.WaitGroup           // the background Prepares
}

// NewCatalog returns the catalog over the release catalog. A nil log discards
// the log.
func NewCatalog(rel *releases.Catalog, log *slog.Logger) *Catalog {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &Catalog{rel: rel, log: log, uploadTimeout: defaultUploadTimeout, chunkSize: defaultChunkSize,
		prepareWait: defaultPrepareWait, preparing: map[string]chan struct{}{}}
	c.prepare = c.prepareInBackground
	return c
}

// Releases returns the release catalog underneath.
func (c *Catalog) Releases() *releases.Catalog { return c.rel }

// Ref returns the reference of the artifact of a component version for an
// architecture, as a desired state names it: any version with a pinned SHA-256
// for the architecture is named, ready or not (F10). Unknown is
// releases.ErrUnknown, not pinned yet releases.ErrNoPin.
func (c *Catalog) Ref(ctx context.Context, component, version, arch string) (*nodev1.ArtifactRef, error) {
	return c.rel.Ref(ctx, component, version, arch)
}

// Known reports whether the catalog has this version of the component.
func (c *Catalog) Known(ctx context.Context, component, version string) bool {
	return c.rel.Known(ctx, component, version)
}

// Ready says whether the asset of a component version for an architecture may
// be given to a node: releases.ErrNotReady, releases.ErrUnusable or
// releases.ErrUnknown otherwise.
func (c *Catalog) Ready(ctx context.Context, component, version, arch string) error {
	return c.rel.Ready(ctx, component, version, arch)
}

// Newest returns the newest version of the component on the channel with an
// asset for every one of archs that no node found unusable, "" for none.
func (c *Catalog) Newest(ctx context.Context, component, channel string, archs []string) (string, error) {
	return c.rel.Newest(ctx, component, channel, archs)
}

// Prepare starts the preparation of an asset in the background, unless one is
// under way: the download, the checks and the extraction, after which the
// asset is ready and the next resync uploads it.
func (c *Catalog) Prepare(component, version, arch string) {
	c.prepare(component, version, arch)
}

func (c *Catalog) prepareInBackground(component, version, arch string) <-chan struct{} {
	key := component + "/" + version + "/" + arch
	c.mu.Lock()
	if done, ok := c.preparing[key]; ok {
		c.mu.Unlock()
		return done
	}
	done := make(chan struct{})
	c.preparing[key] = done
	c.mu.Unlock()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			c.mu.Lock()
			delete(c.preparing, key)
			c.mu.Unlock()
			close(done)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), prepareTimeout)
		defer cancel()
		if err := c.rel.Prepare(ctx, component, version, []string{arch}); err != nil {
			c.log.Warn("could not prepare an artifact", "component", component, "version", version, "arch", arch, "err", err)
		}
	}()
	return done
}

// Wait waits for the background Prepares to end.
func (c *Catalog) Wait() { c.wg.Wait() }

// BuiltinRef returns the artifact reference of a built-in release, as the
// catalog names it once seeded, and whether there is one.
func BuiltinRef(component, version, arch string) (*nodev1.ArtifactRef, bool) {
	comp, ok := releases.ComponentOf(component)
	if !ok {
		return nil, false
	}
	for _, b := range releases.Builtins() {
		if b.Component != component || b.Version != version {
			continue
		}
		a, ok := b.Assets[arch]
		if !ok {
			return nil, false
		}
		url := comp.DownloadURL(version, a.File)
		if comp.Postern {
			url = "" // in the release of Postern that the panel is: the catalog names it
		}
		return &nodev1.ArtifactRef{Engine: component, Version: version, Arch: arch, Sha256: a.SHA256,
			FileName: a.File, Url: url, Binary: comp.Binary}, true
	}
	return nil, false
}

// EnsureArtifacts makes sure that a node has every artifact that a state
// names, as far as the catalog can: each one that the info of the node does not
// list (with the same SHA-256) is uploaded when the catalog has it ready; one
// that it has not prepared yet is prepared in the background, waited for a
// bounded time (prepareWait, or the context), and uploaded when it is ready by
// then; otherwise the node reports the artifact missing until a later resync
// uploads it; one that the catalog found unusable, or that the node lists as
// unusable, is not uploaded.
// A state that names an artifact that the catalog does not pin is an error,
// and nothing of it is uploaded. Each upload is bounded in time.
//
// A node with the capability artifact-trial tries every upload out and says
// so: an answer tried and not usable marks the asset unusable for the
// architecture, with the node and the reason; one not tried marks nothing,
// and the artifact is uploaded again at the next resync. A node without the
// capability leaves the fields unset, and they are not read.
//
// A node that downloads its artifacts itself (artifact_source direct, with
// the capability artifact-direct) gets nothing when the panel pushes it a
// generation that it does not have yet (info.desired_generation is older than
// the state): it downloads them. Once it has the state, at the next resync,
// what it still lacks is uploaded as for any node (R5-1).
func (c *Catalog) EnsureArtifacts(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse, state *nodev1.NodeState, client nodev1connect.NodeServiceClient) error {
	if state.GetSettings().GetArtifactSource() == store.ArtifactSourceDirect &&
		slices.Contains(info.GetCapabilities(), CapArtifactDirect) &&
		info.GetDesiredGeneration() < state.GetGeneration() {
		return nil
	}
	trial := slices.Contains(info.GetCapabilities(), CapArtifactTrial)
	for _, ref := range state.GetArtifacts() {
		pinned, err := c.rel.Ref(ctx, ref.GetEngine(), ref.GetVersion(), ref.GetArch())
		if err != nil || !strings.EqualFold(ref.GetSha256(), pinned.GetSha256()) || ref.GetFileName() != pinned.GetFileName() {
			return fmt.Errorf("proxies: the state names %.64s %.64s for %.64s, which the catalog does not have",
				ref.GetEngine(), ref.GetVersion(), ref.GetArch())
		}
		if has, ok := nodeHas(info, pinned); ok {
			if !trial || has.GetState() != artifactUntried {
				continue // the node has it, or has tried it and found it unusable
			}
		}
		if client == nil {
			return errors.New("proxies: no client to upload artifacts with")
		}
		ready, err := c.readyOrPrepare(ctx, nodeID, pinned)
		if err != nil {
			return err
		}
		if !ready {
			continue
		}
		resp, err := c.upload(ctx, client, pinned)
		if err != nil {
			return fmt.Errorf("proxies: upload %s to node %s: %w", pinned.GetFileName(), nodeID, err)
		}
		c.log.Info("uploaded an artifact to a node", "node", nodeID,
			"component", pinned.GetEngine(), "version", pinned.GetVersion(), "arch", pinned.GetArch())
		if !trial || !resp.GetTried() || resp.GetUsable() {
			continue
		}
		if err := c.rel.MarkUnusable(ctx, pinned.GetEngine(), pinned.GetVersion(), pinned.GetArch(), nodeID, resp.GetReason()); err != nil {
			return fmt.Errorf("proxies: record that node %s cannot use %s %s: %w", nodeID, pinned.GetEngine(), pinned.GetVersion(), err)
		}
	}
	return nil
}

// readyOrPrepare says whether the asset of ref may be uploaded now: it is
// ready, or its Prepare, started here or under way already, ends within
// prepareWait (and the context) and leaves it ready. An unusable asset, and
// one still not ready by then, is not uploaded; a later resync asks again.
func (c *Catalog) readyOrPrepare(ctx context.Context, nodeID string, ref *nodev1.ArtifactRef) (bool, error) {
	component, version, arch := ref.GetEngine(), ref.GetVersion(), ref.GetArch()
	for attempt := 0; ; attempt++ {
		switch err := c.rel.Ready(ctx, component, version, arch); {
		case err == nil:
			return true, nil
		case errors.Is(err, releases.ErrUnusable):
			c.log.Warn("an artifact that a node needs is unusable", "node", nodeID,
				"component", component, "version", version, "arch", arch, "err", err)
			return false, nil
		case !errors.Is(err, releases.ErrNotReady):
			return false, err
		}
		if attempt > 0 {
			c.log.Info("an artifact is not prepared yet; the node gets it at a later resync", "node", nodeID,
				"component", component, "version", version, "arch", arch)
			return false, nil
		}
		done := c.prepare(component, version, arch)
		timer := time.NewTimer(c.prepareWait)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return false, nil
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		}
	}
}

// nodeHas returns the artifact of the info of a node that is ref, with the
// state the node gives it, and whether there is one.
func nodeHas(info *nodev1.GetInfoResponse, ref *nodev1.ArtifactRef) (*nodev1.ArtifactRef, bool) {
	for _, a := range info.GetArtifacts() {
		if strings.EqualFold(a.GetEngine(), ref.GetEngine()) && a.GetVersion() == ref.GetVersion() &&
			a.GetArch() == ref.GetArch() && strings.EqualFold(a.GetSha256(), ref.GetSha256()) {
			return a, true
		}
	}
	return nil, false
}

// upload sends the file of the artifact meta to the node: meta first, then the
// bytes in chunks. The catalog hashes the bytes on the way (releases.Open), and
// a file that no longer has the pinned SHA-256 is not sent to the end.
func (c *Catalog) upload(ctx context.Context, client nodev1connect.NodeServiceClient, meta *nodev1.ArtifactRef) (*nodev1.UploadArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.uploadTimeout)
	defer cancel()
	f, _, err := c.rel.Open(ctx, meta.GetEngine(), meta.GetVersion(), meta.GetArch())
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	stream := client.UploadArtifact(ctx)
	// abort ends the stream without completing it: the node must not take
	// what was sent so far.
	abort := func() {
		cancel()
		_, _ = stream.CloseAndReceive()
	}
	send := func(req *nodev1.UploadArtifactRequest) error {
		err := stream.Send(req)
		if err == nil {
			return nil
		}
		// A stream that the node has ended says io.EOF here; what went
		// wrong comes with the response.
		if _, cerr := stream.CloseAndReceive(); errors.Is(err, io.EOF) && cerr != nil {
			return cerr
		}
		return err
	}
	if err := send(&nodev1.UploadArtifactRequest{Part: &nodev1.UploadArtifactRequest_Meta{Meta: proto.Clone(meta).(*nodev1.ArtifactRef)}}); err != nil {
		return nil, err
	}
	for {
		// A buffer per chunk: the message must not change once it is sent.
		chunk := make([]byte, c.chunkSize)
		n, rerr := io.ReadFull(f, chunk)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			abort()
			return nil, rerr
		}
		if n > 0 {
			if err := send(&nodev1.UploadArtifactRequest{Part: &nodev1.UploadArtifactRequest_Chunk{Chunk: chunk[:n]}}); err != nil {
				return nil, err
			}
		}
		if rerr != nil {
			break
		}
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	switch {
	case !resp.Msg.GetStored():
		return nil, errors.New("the node did not store it")
	case !strings.EqualFold(resp.Msg.GetSha256(), meta.GetSha256()):
		return nil, fmt.Errorf("the node stored sha256 %.64s, want %s", resp.Msg.GetSha256(), meta.GetSha256())
	}
	return resp.Msg, nil
}
