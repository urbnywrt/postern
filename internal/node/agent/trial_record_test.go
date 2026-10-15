package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/trial"
)

// removingTrials is a trial runner that takes the artifact away while it runs
// (as a concurrent Remove would), so that the record cannot be written.
type removingTrials struct {
	*fakeTrials
	dir string
}

func (r removingTrials) Run(ctx context.Context, binaryPath, binaryName string, t engines.Trial) trial.Result {
	_ = os.RemoveAll(r.dir)
	return r.fakeTrials.Run(ctx, binaryPath, binaryName, t)
}

// A trial that ran but whose record could not be written is answered as not
// run: the panel is not told usable or unusable for an outcome the node does
// not keep, and uploads again later.
func TestUploadArtifactRecordFailure(t *testing.T) {
	r := newRig(t)
	body := bytes.Repeat([]byte("telemt binary "), 1000)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	ref := artifacts.Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: sha, Binary: "telemt"}
	r.svc.trials = removingTrials{fakeTrials: r.trials, dir: r.arts.Dir(ref)}
	r.trials.set(trial.Result{Ran: true, OK: true})

	meta := &nodev1.ArtifactRef{Engine: "telemt", Version: "3.5.13", Arch: "amd64", Sha256: sha, FileName: "telemt", Binary: "telemt"}
	resp, err := r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(meta)}, uploadChunks(body, 4096)...)...)
	if err != nil || !resp.GetStored() || resp.GetTried() || resp.GetUsable() ||
		!strings.HasPrefix(resp.GetReason(), "trial not run: recording the trial: ") {
		t.Fatalf("upload = %v, %v", resp, err)
	}
	if _, ok := r.arts.Trial(ref); ok {
		t.Error("a record exists")
	}
}
