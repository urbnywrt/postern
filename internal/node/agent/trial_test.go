package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/node/trial"
)

// The trial after the upload decides what the panel is told and what the node
// records: a failed trial makes the artifact unusable with its reason; one
// that did not run is answered tried=false and recorded nowhere, and the
// artifact is reported untried.
func TestUploadArtifactTrials(t *testing.T) {
	r := newRig(t)
	body := bytes.Repeat([]byte("xray binary "), 1000)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	ref := func(version string) *nodev1.ArtifactRef {
		// No binary name: the provider's is taken.
		return &nodev1.ArtifactRef{Engine: "xray", Version: version, Arch: "amd64", Sha256: sha, FileName: "xray"}
	}
	storeRef := func(version string) artifacts.Ref {
		return artifacts.Ref{Engine: "xray", Version: version, Arch: "amd64", SHA256: sha, Binary: "xray"}
	}
	artifactState := func(version string) (string, string) {
		t.Helper()
		resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range resp.Msg.GetArtifacts() {
			if a.GetEngine() == "xray" && a.GetVersion() == version {
				return a.GetState(), a.GetStateReason()
			}
		}
		t.Fatalf("GetInfo lists no xray %s: %v", version, resp.Msg.GetArtifacts())
		return "", ""
	}
	upload := func(version string) (*nodev1.UploadArtifactResponse, error) {
		return r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(ref(version))}, uploadChunks(body, 4096)...)...)
	}

	// Failed: stored, tried, unusable, with the reason; recorded.
	longReason := "exited with 1, want 0: " + strings.Repeat("x", 300)
	r.trials.set(trial.Result{Ran: true, OK: false, ExitCode: 1, Output: "exec format error", Reason: longReason})
	resp, err := upload("v26.3.27")
	if err != nil || !resp.GetStored() || !resp.GetTried() || resp.GetUsable() || resp.GetReason() != longReason {
		t.Fatalf("upload = %v, %v", resp, err)
	}
	if run, _ := r.trials.last(); run.binary != "xray" || !reflect.DeepEqual(run.trial.Args, []string{"version"}) || !run.trial.Output.MatchString("Xray 26.3.27 (") {
		t.Errorf("the trial run was %+v, want xray's", run)
	}
	if rec, ok := r.arts.Trial(storeRef("v26.3.27")); !ok || rec.OK || rec.Reason != longReason {
		t.Errorf("trial record = %+v, %v", rec, ok)
	}
	if st, reason := artifactState("v26.3.27"); st != "unusable" || len(reason) > 256 || !strings.HasPrefix(longReason, reason) {
		t.Errorf("state = %q, reason %d bytes %q", st, len(reason), reason)
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times, want 1", n)
	}

	// Not run: stored, not tried, nothing recorded, reported untried.
	r.trials.set(trial.Result{Reason: "asking Docker about the runner image: dial unix: no such file"})
	resp, err = upload("v26.3.28")
	if err != nil || !resp.GetStored() || resp.GetTried() || resp.GetUsable() || resp.GetReason() != "trial not run: asking Docker about the runner image: dial unix: no such file" {
		t.Fatalf("upload = %v, %v", resp, err)
	}
	if _, ok := r.arts.Trial(storeRef("v26.3.28")); ok {
		t.Error("a trial that did not run was recorded")
	}
	if st, reason := artifactState("v26.3.28"); st != "untried" || reason != "" {
		t.Errorf("state = %q, reason %q", st, reason)
	}

	// Passed again, replacing the unusable one: the record follows.
	r.trials.set(trial.Result{Ran: true, OK: true})
	if resp, err := upload("v26.3.27"); err != nil || !resp.GetUsable() {
		t.Fatalf("upload = %v, %v", resp, err)
	}
	if st, _ := artifactState("v26.3.27"); st != "" {
		t.Errorf("state = %q, want usable", st)
	}

	// A node without a runner does not try.
	r.svc.trials = nil
	resp, err = upload("v26.3.29")
	if err != nil || !resp.GetStored() || resp.GetTried() || !strings.HasPrefix(resp.GetReason(), "trial not run: ") {
		t.Fatalf("upload without a runner = %v, %v", resp, err)
	}
	if n := strings.Count(strings.Join(r.bufferKinds(), ","), evArtifact); n != 4 {
		t.Errorf("%d artifact events, want 4", n)
	}

	// A component nobody knows a trial for is refused by the reference check
	// (no binary name), and tried by nobody when it names one.
	r.svc.trials = r.trials
	before, _ := r.trials.last()
	_, n0 := r.trials.last()
	other := &nodev1.ArtifactRef{Engine: "other", Version: "1", Arch: "amd64", Sha256: sha, FileName: "other", Binary: "other"}
	resp, err = r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(other)}, uploadChunks(body, 4096)...)...)
	if err != nil || !resp.GetStored() || resp.GetTried() || resp.GetReason() != "trial not run: no trial is known for other" {
		t.Fatalf("upload of an unknown component = %v, %v", resp, err)
	}
	if last, n := r.trials.last(); n != n0 || !reflect.DeepEqual(last, before) {
		t.Error("a trial ran for a component without one")
	}
}
