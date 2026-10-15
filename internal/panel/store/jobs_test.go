package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// mustJob creates a running job of a node.
func mustJob(t *testing.T, db *DB, nodeID, kind string) *Job {
	t.Helper()
	j := &Job{NodeID: nodeID, Kind: kind}
	if err := db.CreateJob(context.Background(), j); err != nil {
		t.Fatalf("CreateJob(%s, %s): %v", nodeID, kind, err)
	}
	return j
}

func TestJobRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow.Add(300 * time.Millisecond)) // the sub-second part is not kept

	j := &Job{NodeID: "NODE1", Kind: "install", Log: "first line\n"}
	if err := db.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if len(j.ID) != 26 {
		t.Errorf("ID = %q, want a ULID", j.ID)
	}
	want := Job{ID: j.ID, NodeID: "NODE1", Kind: "install", Status: JobRunning, Log: "first line\n", StartedAt: testNow}
	if !reflect.DeepEqual(*j, want) {
		t.Errorf("the record after CreateJob = %+v, want %+v", *j, want)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatalf("JobByID: %v", err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("JobByID = %+v, want %+v", *got, want)
	}
}

// A job is created running, whatever the record says, so that a caller cannot
// make a finished job that never ran.
func TestCreateJobIsAlwaysRunning(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	finished := testNow
	j := &Job{NodeID: "NODE1", Kind: "install", Status: JobDone, Error: "old", FinishedAt: &finished}
	if err := db.CreateJob(ctx, j); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if j.Status != JobRunning || j.Error != "" || j.FinishedAt != nil {
		t.Errorf("record after CreateJob = %+v, want a running job without an error or an end", *j)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != JobRunning || got.Error != "" || got.FinishedAt != nil {
		t.Errorf("JobByID = %+v, want a running job without an error or an end", *got)
	}
}

func TestJobByIDNotFound(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.JobByID(context.Background(), "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("JobByID of an unknown id: err = %v, want ErrNotFound", err)
	}
}

// One node runs one job at a time; the database says so too, not only the
// runner.
func TestOneRunningJobPerNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	first := mustJob(t, db, "NODE1", "install")

	if err := db.CreateJob(ctx, &Job{NodeID: "NODE1", Kind: "collect"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second running job of the same node: err = %v, want ErrConflict", err)
	}
	mustJob(t, db, "NODE2", "install") // another node is not affected

	if err := db.FinishJob(ctx, first.ID, JobDone, "", ""); err != nil {
		t.Fatalf("FinishJob: %v", err)
	}
	mustJob(t, db, "NODE1", "collect") // a finished job does not count
}

func TestUpdateJobLog(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	j := mustJob(t, db, "NODE1", "install")

	if err := db.UpdateJobLog(ctx, j.ID, "one\ntwo\n"); err != nil {
		t.Fatalf("UpdateJobLog: %v", err)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Log != "one\ntwo\n" || got.Status != JobRunning {
		t.Errorf("after UpdateJobLog: log %q, status %q; want the new log of a running job", got.Log, got.Status)
	}

	if err := db.UpdateJobLog(ctx, "NOPE", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateJobLog of an unknown job: err = %v, want ErrNotFound", err)
	}
}

func TestFinishJob(t *testing.T) {
	for _, status := range []string{JobDone, JobFailed, JobCancelled} {
		t.Run(status, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			db.now = fixedClock(testNow)
			j := mustJob(t, db, "NODE1", "install")

			db.now = fixedClock(testNow.Add(90*time.Second + 700*time.Millisecond))
			errText := ""
			if status != JobDone {
				errText = "it went wrong"
			}
			if err := db.FinishJob(ctx, j.ID, status, "the whole log\n", errText); err != nil {
				t.Fatalf("FinishJob: %v", err)
			}
			got, err := db.JobByID(ctx, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			end := testNow.Add(90 * time.Second)
			want := Job{ID: j.ID, NodeID: "NODE1", Kind: "install", Status: status, Log: "the whole log\n",
				Error: errText, StartedAt: testNow, FinishedAt: &end}
			if !reflect.DeepEqual(*got, want) {
				t.Errorf("JobByID = %+v, want %+v", *got, want)
			}
		})
	}
}

// A finished job is history: neither its log nor its status change again.
func TestFinishedJobDoesNotChange(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	j := mustJob(t, db, "NODE1", "install")
	if err := db.FinishJob(ctx, j.ID, JobFailed, "log\n", "boom"); err != nil {
		t.Fatal(err)
	}

	if err := db.UpdateJobLog(ctx, j.ID, "rewritten"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateJobLog of a finished job: err = %v, want ErrNotFound", err)
	}
	if err := db.FinishJob(ctx, j.ID, JobDone, "rewritten", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("FinishJob of a finished job: err = %v, want ErrNotFound", err)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != JobFailed || got.Log != "log\n" || got.Error != "boom" {
		t.Errorf("the finished job changed: %+v", *got)
	}
}

func TestFinishJobRefusesAStatusThatIsNotFinal(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	j := mustJob(t, db, "NODE1", "install")
	for _, status := range []string{JobRunning, "", "paused"} {
		if err := db.FinishJob(ctx, j.ID, status, "", ""); err == nil {
			t.Errorf("FinishJob with status %q succeeded", status)
		}
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != JobRunning || got.FinishedAt != nil {
		t.Errorf("a refused FinishJob changed the job: %+v", *got)
	}
}

func TestFailRunningJobs(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	a := mustJob(t, db, "NODE1", "install")
	b := mustJob(t, db, "NODE2", "collect")
	done := mustJob(t, db, "NODE3", "install")
	if err := db.FinishJob(ctx, done.ID, JobDone, "ok\n", ""); err != nil {
		t.Fatal(err)
	}

	db.now = fixedClock(testNow.Add(time.Hour))
	n, err := db.FailRunningJobs(ctx, "the panel restarted")
	if err != nil {
		t.Fatalf("FailRunningJobs: %v", err)
	}
	if n != 2 {
		t.Errorf("FailRunningJobs = %d, want 2", n)
	}
	end := testNow.Add(time.Hour)
	for _, id := range []string{a.ID, b.ID} {
		got, err := db.JobByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != JobFailed || got.Error != "the panel restarted" || got.FinishedAt == nil || !got.FinishedAt.Equal(end) {
			t.Errorf("job %s after FailRunningJobs = %+v, want failed at %v with the reason", id, *got, end)
		}
	}
	got, err := db.JobByID(ctx, done.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != JobDone || got.Error != "" {
		t.Errorf("a finished job was changed: %+v", *got)
	}

	// Nothing is left to fail, and the nodes can run jobs again.
	if n, err := db.FailRunningJobs(ctx, "again"); err != nil || n != 0 {
		t.Errorf("second FailRunningJobs = %d, %v; want 0, nil", n, err)
	}
	mustJob(t, db, "NODE1", "install")
}

// The schema takes no status that a job cannot have.
func TestJobStatusIsChecked(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	j := mustJob(t, db, "NODE1", "install")
	for _, status := range []string{"", "paused", "Running"} {
		if _, err := db.sql.ExecContext(ctx, `UPDATE jobs SET status = ? WHERE id = ?`, status, j.ID); err == nil {
			t.Errorf("status %q was stored", status)
		}
	}
	for _, status := range []string{JobDone, JobFailed, JobCancelled, JobRunning} {
		if _, err := db.sql.ExecContext(ctx, `UPDATE jobs SET status = ? WHERE id = ?`, status, j.ID); err != nil {
			t.Errorf("status %q: %v", status, err)
		}
	}
}

// Jobs are history: a job keeps naming its node after the node is deleted.
func TestJobOutlivesItsNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	j := mustJob(t, db, n.ID, "install")
	if err := db.DeleteNode(ctx, n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatalf("JobByID after the node was deleted: %v", err)
	}
	if got.NodeID != n.ID {
		t.Errorf("NodeID = %q, want %q", got.NodeID, n.ID)
	}
}

// A log is text that goes to the browser as it is; the store keeps every byte.
func TestJobLogKeepsItsBytes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	j := mustJob(t, db, "NODE1", "install")
	log := strings.Repeat("ünïcödé line with a tab\t and a quote ' \" \\\n", 1000)
	if err := db.FinishJob(ctx, j.ID, JobDone, log, ""); err != nil {
		t.Fatal(err)
	}
	got, err := db.JobByID(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Log != log {
		t.Errorf("the log came back changed (%d bytes, want %d)", len(got.Log), len(log))
	}
}

// The running job of a node is what the UI shows again after a reload; a node
// whose jobs have all ended has none.
func TestRunningJobByNode(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if _, err := db.RunningJobByNode(ctx, "NODE1", "install"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RunningJobByNode of a node without jobs: err = %v, want ErrNotFound", err)
	}
	old := mustJob(t, db, "NODE1", "install")
	if err := db.FinishJob(ctx, old.ID, JobFailed, "", "it failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunningJobByNode(ctx, "NODE1", "install"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RunningJobByNode of a node whose job ended: err = %v, want ErrNotFound", err)
	}
	running := mustJob(t, db, "NODE1", "install")
	mustJob(t, db, "NODE2", "install")

	got, err := db.RunningJobByNode(ctx, "NODE1", "install")
	if err != nil {
		t.Fatalf("RunningJobByNode: %v", err)
	}
	if got.ID != running.ID || got.Status != JobRunning || got.NodeID != "NODE1" || got.Kind != "install" {
		t.Errorf("RunningJobByNode = %+v, want the running job %s of NODE1", *got, running.ID)
	}
}

// The jobs of every service share one table, and a service asks for the kind
// that it runs: the collection that a node is running is not its running
// install, and the other way round, whatever the history of the node holds.
func TestRunningJobByNodeOfAKind(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// An install that is over, and a collection that runs, on the same node.
	old := mustJob(t, db, "NODE1", "install")
	if err := db.FinishJob(ctx, old.ID, JobDone, "", ""); err != nil {
		t.Fatal(err)
	}
	collecting := mustJob(t, db, "NODE1", "collect")
	other := mustJob(t, db, "NODE2", "install") // the install of another node is not the answer for NODE1

	if got, err := db.RunningJobByNode(ctx, "NODE1", "install"); !errors.Is(err, ErrNotFound) {
		t.Errorf("RunningJobByNode(install) of a node that collects = %+v, %v; want ErrNotFound", got, err)
	}
	got, err := db.RunningJobByNode(ctx, "NODE1", "collect")
	if err != nil || got.ID != collecting.ID || got.Kind != "collect" {
		t.Errorf("RunningJobByNode(collect) = %+v, %v; want the collection %s", got, err, collecting.ID)
	}
	if got, err := db.RunningJobByNode(ctx, "NODE2", "collect"); !errors.Is(err, ErrNotFound) {
		t.Errorf("RunningJobByNode(collect) of a node that installs = %+v, %v; want ErrNotFound", got, err)
	}

	// The collection ends and an install starts: the answers swap.
	if err := db.FinishJob(ctx, collecting.ID, JobDone, "", ""); err != nil {
		t.Fatal(err)
	}
	installing := mustJob(t, db, "NODE1", "install")
	if got, err := db.RunningJobByNode(ctx, "NODE1", "collect"); !errors.Is(err, ErrNotFound) {
		t.Errorf("RunningJobByNode(collect) of a node that installs = %+v, %v; want ErrNotFound", got, err)
	}
	got, err = db.RunningJobByNode(ctx, "NODE1", "install")
	if err != nil || got.ID != installing.ID || got.ID == other.ID {
		t.Errorf("RunningJobByNode(install) = %+v, %v; want the install %s", got, err, installing.ID)
	}
}
