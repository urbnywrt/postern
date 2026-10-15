package proxies

import (
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// TestEnsureArtifactsWaitsForAPrepareThatEndsInTime: an asset that is not
// prepared when a state needs it is prepared and uploaded in line when the
// Prepare ends within the wait (the first state of a fresh panel); one whose
// Prepare takes longer is left to a later resync, without an error.
func TestEnsureArtifactsWaitsForAPrepareThatEndsInTime(t *testing.T) {
	e := newEnv(t)
	ref := e.readyRelease(store.AssetUnchecked) // pinned, the file there, not ready
	node := &uploadNode{}
	client := serveUploadNode(t, node)

	// The Prepare makes the asset ready before it ends.
	e.catalog.prepare = func(component, version, arch string) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := e.db.SetAssetState(e.ctx, component, version, arch, store.AssetReady, "", ""); err != nil {
				t.Error(err)
			}
		}()
		return done
	}
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil), stateWith(ref), client); err != nil {
		t.Fatalf("EnsureArtifacts: %v", err)
	}
	if len(node.got()) != 1 {
		t.Fatalf("uploads = %d, want the archive once its Prepare ended", len(node.got()))
	}

	// A Prepare that outlasts the wait: nothing uploaded, no error.
	if err := e.db.SetAssetState(e.ctx, EngineTelemt, readyVersion, "amd64", store.AssetUnchecked, "", ""); err != nil {
		t.Fatal(err)
	}
	e.catalog.prepareWait = 50 * time.Millisecond
	e.catalog.prepare = func(string, string, string) <-chan struct{} { return make(chan struct{}) }
	start := time.Now()
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", infoWith(nil), stateWith(ref), client); err != nil {
		t.Fatalf("EnsureArtifacts with a slow Prepare: %v", err)
	}
	if len(node.got()) != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("uploads = %d after %v, want no new upload within the wait", len(node.got()), time.Since(start))
	}
}
