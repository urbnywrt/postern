package server

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/jobs"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// A job that a panel left running, because it was killed, is failed when the
// panel starts again: no process runs it, and the node could run no other.
func TestJobsLeftRunningAreFailedAtStart(t *testing.T) {
	p := newPanel(t)
	ctx := context.Background()
	left := &store.Job{NodeID: "NODE1", Kind: "install"}
	if err := p.srv.db.CreateJob(ctx, left); err != nil {
		t.Fatal(err)
	}
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.ts.Close()

	p.start()
	got, err := p.srv.db.JobByID(ctx, left.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.JobFailed || got.Error != jobs.RestartedError {
		t.Errorf("the job left running is %s %q after a start, want failed with %q", got.Status, got.Error, jobs.RestartedError)
	}
}

// When the panel stops, a job that runs is stopped and recorded as failed
// before the database is closed.
func TestServeStopsTheJobs(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()
	started := make(chan struct{})
	id, err := p.srv.jobs.Start(context.Background(), "NODE1", "install", nil, func(ctx context.Context, _ io.Writer) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-started:
	case <-time.After(waitFor):
		t.Fatal("the job did not start")
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}

	p.start()
	got, err := p.srv.db.JobByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.JobFailed || got.Error != jobs.StoppedError {
		t.Errorf("the job is %s %q after the panel stopped, want failed with %q", got.Status, got.Error, jobs.StoppedError)
	}
}
