package jobs

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// waitTimeout bounds every wait of these tests, so that a regression is a
// failure and not a hang.
const waitTimeout = 10 * time.Second

// newSecret returns a made-up secret, a new one for every test, so that no
// secret is written in the source.
func newSecret() string { return crand.Text() }

// openDB opens a panel database in a temporary directory.
func openDB(t *testing.T, path string) *store.DB {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newRunner returns a runner over a new database. It is closed when the test
// ends.
func newRunner(t *testing.T) (*Runner, *store.DB) {
	t.Helper()
	db := openDB(t, filepath.Join(t.TempDir(), "panel.db"))
	r, err := New(context.Background(), db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { closeRunner(t, r) })
	return r, db
}

func closeRunner(t *testing.T, r *Runner) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	if err := r.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// start starts a job and fails the test if it cannot.
func start(t *testing.T, r *Runner, nodeID string, secrets []string, fn func(context.Context, io.Writer) error) string {
	t.Helper()
	id, err := r.Start(context.Background(), nodeID, "install", secrets, fn)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return id
}

// released reports whether the runner has let go of a job. It does so a moment
// after the database has the end of the job.
func released(r *Runner, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, running := r.jobs[id]
	return !running
}

// waitDone polls a job until it has finished and the runner has let go of it,
// and returns it.
func waitDone(t *testing.T, r *Runner, id string) Job {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		j, err := r.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if j.Status != StatusRunning && released(r, id) {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s is still running", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// writeLines writes each line, with its end, in a Write of its own.
func writeLines(log io.Writer, lines ...string) {
	for _, l := range lines {
		_, _ = io.WriteString(log, l+"\n")
	}
}

// --- the life of a job ---

func TestJobThatSucceeds(t *testing.T) {
	r, _ := newRunner(t)
	begin := time.Now().Truncate(time.Second)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		writeLines(log, "one", "two")
		_, _ = io.WriteString(log, "three, without an end")
		return nil
	})
	j := waitDone(t, r, id)
	if j.ID != id || j.NodeID != "NODE1" || j.Kind != "install" || j.Status != StatusDone || j.Error != "" {
		t.Errorf("job = %+v, want a done install of NODE1", j)
	}
	if want := "one\ntwo\nthree, without an end"; j.Log != want {
		t.Errorf("log = %q, want %q", j.Log, want)
	}
	if j.StartedAt.Before(begin) || j.FinishedAt == nil || j.FinishedAt.Before(j.StartedAt) {
		t.Errorf("started %v, finished %v; want a start from now and an end after it", j.StartedAt, j.FinishedAt)
	}
}

func TestJobThatFails(t *testing.T) {
	r, _ := newRunner(t)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		writeLines(log, "trying")
		return errors.New("docker is not installed")
	})
	j := waitDone(t, r, id)
	if j.Status != StatusFailed || j.Error != "docker is not installed" || j.Log != "trying\n" || j.FinishedAt == nil {
		t.Errorf("job = %+v, want failed with the error and the log", j)
	}
}

func TestCancel(t *testing.T) {
	r, _ := newRunner(t)
	running := make(chan struct{})
	id := start(t, r, "NODE1", nil, func(ctx context.Context, log io.Writer) error {
		writeLines(log, "waiting")
		close(running)
		<-ctx.Done()
		return ctx.Err()
	})
	<-running
	if err := r.Cancel(id); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	j := waitDone(t, r, id)
	if j.Status != StatusCancelled || j.Error == "" || j.Log != "waiting\n" {
		t.Errorf("job = %+v, want cancelled with a reason and the log", j)
	}
	if err := r.Cancel(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Cancel of a finished job: err = %v, want ErrNotFound", err)
	}
	if err := r.Cancel("NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Cancel of an unknown job: err = %v, want ErrNotFound", err)
	}
}

// A job that finishes its work although it was cancelled is done.
func TestCancelledJobThatFinishesAnyway(t *testing.T) {
	r, _ := newRunner(t)
	running := make(chan struct{})
	id := start(t, r, "NODE1", nil, func(ctx context.Context, _ io.Writer) error {
		close(running)
		<-ctx.Done()
		return nil
	})
	<-running
	if err := r.Cancel(id); err != nil {
		t.Fatal(err)
	}
	if j := waitDone(t, r, id); j.Status != StatusDone {
		t.Errorf("status = %q, want done", j.Status)
	}
}

// The error of a job that was cancelled, or that Close stopped, keeps the
// notice that the error of its function holds, deep in it as well, with the
// secrets replaced; any other error of the function is left out.
func TestNoticeOfAJobThatDidNotEndByItself(t *testing.T) {
	const secret = "the-password-of-the-server"
	fn := func(running chan<- struct{}) func(context.Context, io.Writer) error {
		return func(ctx context.Context, _ io.Writer) error {
			close(running)
			<-ctx.Done()
			left := Notice(fmt.Errorf("the file /root/key may still be there (%s): remove it by hand", secret))
			return fmt.Errorf("install.sh: %w; and %w", ctx.Err(), left)
		}
	}
	const want = "; the file /root/key may still be there (***): remove it by hand"

	r, _ := newRunner(t)
	running := make(chan struct{})
	id := start(t, r, "NODE1", []string{secret}, fn(running))
	<-running
	if err := r.Cancel(id); err != nil {
		t.Fatal(err)
	}
	if j := waitDone(t, r, id); j.Status != StatusCancelled || j.Error != CancelledError+want {
		t.Errorf("cancelled job = %s %q, want %q", j.Status, j.Error, CancelledError+want)
	}

	stopped, _ := newRunner(t)
	running = make(chan struct{})
	id = start(t, stopped, "NODE1", []string{secret}, fn(running))
	<-running
	closeRunner(t, stopped)
	if j, err := stopped.Get(context.Background(), id); err != nil || j.Status != StatusFailed || j.Error != StoppedError+want {
		t.Errorf("stopped job = %+v (%v), want failed with %q", j, err, StoppedError+want)
	}

	// Without a notice, the error is the fixed one.
	plain, _ := newRunner(t)
	running = make(chan struct{})
	id = start(t, plain, "NODE1", nil, func(ctx context.Context, _ io.Writer) error {
		close(running)
		<-ctx.Done()
		return fmt.Errorf("install.sh: %w", ctx.Err())
	})
	<-running
	if err := plain.Cancel(id); err != nil {
		t.Fatal(err)
	}
	if j := waitDone(t, plain, id); j.Error != CancelledError {
		t.Errorf("error = %q, want %q", j.Error, CancelledError)
	}
	if Notice(nil) != nil {
		t.Error("Notice(nil) is not nil")
	}
}

type ctxKey struct{}

// The context of Start is that of a request, which ends when Start has
// returned; the job does not end with it, but sees its values.
func TestJobOutlivesTheContextOfStart(t *testing.T) {
	r, _ := newRunner(t)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "admin-1"))
	release := make(chan struct{})
	type seen struct {
		value any
		err   error
	}
	saw := make(chan seen, 1)
	id, err := r.Start(ctx, "NODE1", "install", nil, func(ctx context.Context, _ io.Writer) error {
		<-release
		saw <- seen{ctx.Value(ctxKey{}), ctx.Err()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	close(release)
	j := waitDone(t, r, id)
	got := <-saw
	if j.Status != StatusDone || got.err != nil || got.value != "admin-1" {
		t.Errorf("status %q, context error %v, value %v; want done, nil, admin-1", j.Status, got.err, got.value)
	}
}

func TestOneRunningJobPerNode(t *testing.T) {
	r, _ := newRunner(t)
	release := make(chan struct{})
	first := start(t, r, "NODE1", nil, func(context.Context, io.Writer) error {
		<-release
		return nil
	})

	if _, err := r.Start(context.Background(), "NODE1", "collect", nil, func(context.Context, io.Writer) error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second job of NODE1: err = %v, want ErrBusy", err)
	}
	other := start(t, r, "NODE2", nil, func(context.Context, io.Writer) error { return nil })
	if j := waitDone(t, r, other); j.Status != StatusDone {
		t.Errorf("the job of NODE2: %+v", j)
	}

	close(release)
	waitDone(t, r, first)
	again := start(t, r, "NODE1", nil, func(context.Context, io.Writer) error { return nil })
	waitDone(t, r, again)
}

// Starting jobs for one node from many places at once starts one.
func TestOneRunningJobPerNodeUnderContention(t *testing.T) {
	r, _ := newRunner(t)
	release := make(chan struct{})
	defer close(release)
	var wg sync.WaitGroup
	var mu sync.Mutex
	started, busy := 0, 0
	for range 16 {
		wg.Go(func() {
			_, err := r.Start(context.Background(), "NODE1", "install", nil, func(context.Context, io.Writer) error {
				<-release
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				started++
			case errors.Is(err, ErrBusy):
				busy++
			default:
				t.Errorf("Start: %v", err)
			}
		})
	}
	wg.Wait()
	if started != 1 || busy != 15 {
		t.Errorf("started %d, busy %d; want 1 and 15", started, busy)
	}
}

func TestStartRefusesWhatCannotRun(t *testing.T) {
	r, _ := newRunner(t)
	fn := func(context.Context, io.Writer) error { return nil }
	for _, c := range []struct {
		name, node, kind string
		fn               func(context.Context, io.Writer) error
	}{
		{"no node", "", "install", fn},
		{"no kind", "NODE1", "", fn},
		{"no function", "NODE1", "install", nil},
	} {
		if _, err := r.Start(context.Background(), c.node, c.kind, nil, c.fn); err == nil {
			t.Errorf("%s: Start succeeded", c.name)
		}
	}
}

func TestGetOfAnUnknownJob(t *testing.T) {
	r, _ := newRunner(t)
	if _, err := r.Get(context.Background(), "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: err = %v, want ErrNotFound", err)
	}
}

// A job that panics fails, and the panel goes on.
func TestJobThatPanics(t *testing.T) {
	r, _ := newRunner(t)
	pw := newSecret()
	id := start(t, r, "NODE1", []string{pw}, func(_ context.Context, log io.Writer) error {
		writeLines(log, "before")
		panic("the password " + pw + " broke it")
	})
	j := waitDone(t, r, id)
	if j.Status != StatusFailed || !strings.Contains(j.Error, "panic") || j.Log != "before\n" {
		t.Errorf("job = %+v, want failed by a panic with the log", j)
	}
	if strings.Contains(j.Error, pw) {
		t.Error("the error shows the secret")
	}
	next := start(t, r, "NODE1", nil, func(context.Context, io.Writer) error { return nil })
	if j := waitDone(t, r, next); j.Status != StatusDone {
		t.Errorf("the next job: %+v", j)
	}
}

// What a job writes once its function has returned is refused.
func TestWritesAfterTheEnd(t *testing.T) {
	r, _ := newRunner(t)
	logs := make(chan io.Writer, 1)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		writeLines(log, "the only line")
		logs <- log
		return nil
	})
	j := waitDone(t, r, id)
	if _, err := io.WriteString(<-logs, "too late\n"); err == nil {
		t.Error("a write after the end succeeded")
	}
	again, err := r.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if again.Log != j.Log || j.Log != "the only line\n" {
		t.Errorf("log = %q, then %q; want the only line", j.Log, again.Log)
	}
}

// The log can be written from several goroutines; every Write is kept whole.
func TestConcurrentWrites(t *testing.T) {
	r, _ := newRunner(t)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		var wg sync.WaitGroup
		for g := range 4 {
			wg.Go(func() {
				for i := range 200 {
					_, _ = fmt.Fprintf(log, "writer %d line %d\n", g, i)
				}
			})
		}
		wg.Wait()
		return nil
	})
	j := waitDone(t, r, id)
	lines := strings.Split(strings.TrimSuffix(j.Log, "\n"), "\n")
	if len(lines) != 800 {
		t.Fatalf("%d lines, want 800", len(lines))
	}
	for _, l := range lines {
		var g, i int
		if n, err := fmt.Sscanf(l, "writer %d line %d", &g, &i); n != 2 || err != nil {
			t.Fatalf("a line was mixed up: %q", l)
		}
	}
}

// The log goes to the browser as text: bytes that are not UTF-8 are replaced.
func TestLogIsUTF8(t *testing.T) {
	r, _ := newRunner(t)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		_, _ = log.Write([]byte("binary \xff\xfe\x00 and ünïcödé\n"))
		return errors.New("bad \xff byte")
	})
	j := waitDone(t, r, id)
	if !utf8.ValidString(j.Log) || !utf8.ValidString(j.Error) {
		t.Errorf("log %q or error %q is not UTF-8", j.Log, j.Error)
	}
	if !strings.Contains(j.Log, "ünïcödé") {
		t.Errorf("log %q lost the text that was UTF-8", j.Log)
	}
}

// --- secrets ---

func TestSecretsAreScrubbed(t *testing.T) {
	r, _ := newRunner(t)
	pw, token := newSecret(), newSecret()
	// A secret of several lines, in the shape of a PEM block.
	key := "-----BEGIN TEST KEY-----\n" + newSecret() + newSecret() + "\n" + newSecret() + "\n-----END TEST KEY-----\n"
	id := start(t, r, "NODE1", []string{pw, token, key, "abc"}, func(_ context.Context, log io.Writer) error {
		writeLines(log, "login with "+pw+" and "+pw+" again")
		// A secret that arrives in pieces, one byte at a time.
		for _, b := range []byte("token=" + token + ";\n") {
			_, _ = log.Write([]byte{b})
		}
		// A secret of several lines, such as a private key.
		_, _ = io.WriteString(log, "key:\n"+key)
		// Secrets shorter than 4 bytes would hide too much.
		writeLines(log, "abc stays")
		return fmt.Errorf("the server refused %s", pw)
	})
	j := waitDone(t, r, id)
	for _, secret := range append([]string{pw, token}, strings.Split(strings.TrimSpace(key), "\n")[1:3]...) {
		if strings.Contains(j.Log, secret) || strings.Contains(j.Error, secret) {
			t.Errorf("a secret is in the job: log %q, error %q", j.Log, j.Error)
		}
	}
	for _, want := range []string{"login with *** and *** again\n", "token=***;\n", "abc stays\n"} {
		if !strings.Contains(j.Log, want) {
			t.Errorf("log %q does not contain %q", j.Log, want)
		}
	}
	if j.Error != "the server refused ***" {
		t.Errorf("error = %q, want the secret replaced", j.Error)
	}
}

// A job that learns secrets as it runs, such as the tokens that it reads from a
// server, adds them: from then on they are hidden in its log and its error as
// the secrets that it started with are.
func TestSecretsAddedWhileTheJobRuns(t *testing.T) {
	r, _ := newRunner(t)
	pw, token, key := newSecret(), newSecret(), newSecret()+"\n"+newSecret()
	early := newSecret()
	id := start(t, r, "NODE1", []string{pw}, func(_ context.Context, log io.Writer) error {
		// Written before it was added: what the log has taken is not looked at
		// again, so a job adds a secret before it could write it.
		writeLines(log, "early "+early)
		AddSecrets(log, token, key, early)
		writeLines(log, "token "+token, "password "+pw, "early "+early)
		_, _ = io.WriteString(log, "key:\n"+key+"\n")
		return fmt.Errorf("refused %s", token)
	})
	j := waitDone(t, r, id)
	for _, want := range []string{"token ***\n", "password ***\n", "key:\n***\n***\n"} {
		if !strings.Contains(j.Log, want) {
			t.Errorf("log %q does not contain %q", j.Log, want)
		}
	}
	for _, secret := range append([]string{token, pw}, strings.Split(key, "\n")...) {
		if strings.Contains(j.Log, secret) || strings.Contains(j.Error, secret) {
			t.Errorf("a secret that was added is in the job: log %q, error %q", j.Log, j.Error)
		}
	}
	if j.Error != "refused ***" {
		t.Errorf("error = %q, want the added secret replaced", j.Error)
	}
	if !strings.Contains(j.Log, "early "+early+"\n") || !strings.Contains(j.Log, "early ***\n") {
		t.Errorf("log %q: want the line from before the secret was added as it was, and the one after it hidden", j.Log)
	}
}

// A secret is added while the start of it waits in the log to be decided: the
// log keeps the end of a line that has no end yet when it could be the start of
// a secret, and those bytes are looked at with the secrets that are known when
// they are decided.
func TestSecretAddedWhileItsStartIsUndecided(t *testing.T) {
	r, _ := newRunner(t)
	long := strings.Repeat("L", 40) // known from the start, so the log keeps the last 39 bytes undecided
	later := newSecret()[:12]
	id := start(t, r, "NODE1", []string{long}, func(_ context.Context, log io.Writer) error {
		_, _ = io.WriteString(log, "the secret is "+later[:6])
		AddSecrets(log, later)
		_, _ = io.WriteString(log, later[6:]+", hidden\n")
		return nil
	})
	j := waitDone(t, r, id)
	if j.Log != "the secret is ***, hidden\n" {
		t.Errorf("log = %q, want the secret hidden", j.Log)
	}
}

// AddSecrets does nothing to a writer that is not the log of a job, or to the
// log of a job that has ended.
func TestAddSecretsElsewhere(t *testing.T) {
	var b strings.Builder
	AddSecrets(&b, "a-secret-of-nobody")
	_, _ = b.WriteString("a-secret-of-nobody")
	if b.String() != "a-secret-of-nobody" {
		t.Errorf("a plain writer was changed: %q", b.String())
	}

	r, _ := newRunner(t)
	kept := make(chan io.Writer, 1)
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		kept <- log
		return nil
	})
	waitDone(t, r, id)
	AddSecrets(<-kept, newSecret()) // must not panic or race
}

// Secrets may be added while other goroutines of the job write.
func TestAddSecretsConcurrently(t *testing.T) {
	r, _ := newRunner(t)
	secrets := make([]string, 50)
	for i := range secrets {
		secrets[i] = newSecret()
	}
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Go(func() {
				for n := range 200 {
					writeLines(log, fmt.Sprintf("writer %d line %d", i, n))
				}
			})
		}
		for _, s := range secrets {
			AddSecrets(log, s)
		}
		wg.Wait()
		writeLines(log, strings.Join(secrets, " "))
		return nil
	})
	j := waitDone(t, r, id)
	for _, s := range secrets {
		if strings.Contains(j.Log, s) {
			t.Fatalf("secret %d of the ones added is in the log", slices.Index(secrets, s))
		}
	}
}

// When one secret is part of another, the longer one is replaced whole.
func TestLongerSecretWins(t *testing.T) {
	s := newScrubber([]string{"abcd", "abcdefgh"})
	if got := s.replace("xx abcdefgh yy abcd zz"); got != "xx *** yy *** zz" {
		t.Errorf("scrub = %q", got)
	}
}

// Secrets that overlap, in one another or with themselves, are hidden as one:
// every byte of every secret is under the mask.
func TestOverlappingSecrets(t *testing.T) {
	for _, c := range []struct {
		secrets  []string
		in, want string
	}{
		{[]string{"xxsec", "secret"}, "a xxsecret b", "a *** b"},
		{[]string{"secret", "xxsec"}, "a xxsecret b", "a *** b"},
		{[]string{"abab"}, "x ababab y", "x *** y"},
		{[]string{"secret"}, "secretsecret!", "***!"},
		{[]string{"abcd", "cdef", "efgh"}, "_abcdefgh_", "_***_"},
		{[]string{"abcd", "efgh"}, "_abcd-efgh_", "_***-***_"},
	} {
		if got := newScrubber(c.secrets).replace(c.in); got != c.want {
			t.Errorf("secrets %q: replace(%q) = %q, want %q", c.secrets, c.in, got, c.want)
		}
	}
}

// reference is what scrubbing the whole stream at once gives: every byte of
// every occurrence of a secret of 4 bytes and more (a secret of several lines
// counting line by line), overlapping or not, is under the mask, and every run
// of such bytes becomes one ***.
func reference(stream string, secrets []string) string {
	hidden := make([]bool, len(stream))
	for _, s := range secrets {
		for _, part := range strings.Split(s, "\n") {
			if len(part) < MinSecretLen {
				continue
			}
			for i := 0; i+len(part) <= len(stream); i++ {
				if stream[i:i+len(part)] == part {
					for j := i; j < i+len(part); j++ {
						hidden[j] = true
					}
				}
			}
		}
	}
	var b strings.Builder
	for i := range len(stream) {
		switch {
		case !hidden[i]:
			b.WriteByte(stream[i])
		case i == 0 || !hidden[i-1]:
			b.WriteString("***")
		}
	}
	return strings.ToValidUTF8(b.String(), "\uFFFD")
}

// However the output is cut into writes, and however long its lines are, the
// log is the stream with the secrets hidden as if it had come in one piece.
// The alphabets are small, so that secrets overlap each other and the text
// around them often; the second has characters of two and three bytes.
func TestScrubbingDoesNotDependOnTheWrites(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, alphabet := range [][]string{
		{"a", "b", "c", "x"},
		{"a", "é", "€", "x"},
	} {
		randString := func(n int, withLines bool) string {
			var b strings.Builder
			for range n {
				if withLines && rng.IntN(25) == 0 {
					b.WriteByte('\n')
					continue
				}
				b.WriteString(alphabet[rng.IntN(len(alphabet))])
			}
			return b.String()
		}
		for round := range 3000 {
			var secrets []string
			for range 1 + rng.IntN(3) {
				secrets = append(secrets, randString(3+rng.IntN(5), false))
			}
			if rng.IntN(4) == 0 {
				secrets = append(secrets, randString(4, false)+"\n"+randString(5, false)) // a secret of two lines
			}
			var stream strings.Builder
			for range rng.IntN(12) {
				stream.WriteString(randString(rng.IntN(20), rng.IntN(3) == 0))
				if rng.IntN(2) == 0 {
					stream.WriteString(secrets[rng.IntN(len(secrets))])
				}
			}
			in := stream.String()

			l := newJobLog(newScrubber(secrets), 1<<20, 1+rng.IntN(12))
			for rest := in; rest != ""; {
				n := 1 + rng.IntN(len(rest))
				l.write([]byte(rest[:n]))
				rest = rest[n:]
			}
			l.end()
			got, want := l.String(), reference(in, secrets)
			if got != want {
				t.Fatalf("alphabet %q, round %d: secrets %q, stream %q, cut at %d:\n got %q\nwant %q",
					alphabet, round, secrets, in, l.maxPartial, got, want)
			}
			for _, s := range secrets {
				for _, part := range strings.Split(s, "\n") {
					if len(part) >= MinSecretLen && strings.Contains(got, part) {
						t.Fatalf("alphabet %q, round %d: secret %q is in the log %q", alphabet, round, part, got)
					}
				}
			}
		}
	}
}

// A line that never ends is cut, so that it does not grow without bound, and
// a secret on the cut is still replaced.
func TestEndlessLineIsCut(t *testing.T) {
	secret := newSecret()
	l := newJobLog(newScrubber([]string{secret}), 1<<20, 64)
	stream := strings.Repeat("x", 100) + secret + strings.Repeat("y", 100) + secret + strings.Repeat("z", 1000)
	for i := range len(stream) {
		l.write([]byte{stream[i]})
		if held := len(l.pending) + len(l.cur); held > 64+len(secret)+len(mask) {
			t.Fatalf("after %d bytes %d are held back", i+1, held)
		}
	}
	l.end()
	want := strings.Repeat("x", 100) + "***" + strings.Repeat("y", 100) + "***" + strings.Repeat("z", 1000)
	if got := l.String(); got != want {
		t.Errorf("log = %q, want %q", got, want)
	}
}

// A cut of a line that never ends does not go through a character, also when
// there are no secrets.
func TestCutKeepsCharactersWhole(t *testing.T) {
	l := newJobLog(newScrubber(nil), 1<<20, 3)
	in := strings.Repeat("é€", 50) // 2 and 3 bytes: a cut after 3 goes through €
	for i := range len(in) {
		l.write([]byte{in[i]})
	}
	l.end()
	if got := l.String(); got != in {
		t.Errorf("log = %q, want %q", got, in)
	}
}

// --- the size of the log ---

func TestLogIsCapped(t *testing.T) {
	r, _ := newRunner(t)
	const lines = 60000 // about 3 MiB
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		for i := range lines {
			_, _ = fmt.Fprintf(log, "line %06d %s\n", i, strings.Repeat(".", 40))
		}
		return nil
	})
	j := waitDone(t, r, id)
	if len(j.Log) > MaxLog {
		t.Fatalf("the log has %d bytes, more than %d", len(j.Log), MaxLog)
	}
	if len(j.Log) < MaxLog-200 {
		t.Errorf("the log has %d bytes, it should keep nearly %d", len(j.Log), MaxLog)
	}
	marker, rest, ok := strings.Cut(j.Log, "\n")
	if !ok || !strings.Contains(marker, "dropped") {
		t.Fatalf("the log does not start with a marker: %q", marker)
	}
	if strings.Count(j.Log, "dropped") != 1 {
		t.Errorf("the log has %d markers, want one", strings.Count(j.Log, "dropped"))
	}
	kept := strings.Split(strings.TrimSuffix(rest, "\n"), "\n")
	for i, l := range kept {
		want := fmt.Sprintf("line %06d %s", lines-len(kept)+i, strings.Repeat(".", 40))
		if l != want {
			t.Fatalf("kept line %d = %q, want %q: the newest whole lines, in order", i, l, want)
		}
	}
}

func TestLogCapKeepsTheNewestLines(t *testing.T) {
	l := newJobLog(newScrubber(nil), 120, 1<<10)
	for i := range 50 {
		l.write(fmt.Appendf(nil, "line %02d\n", i))
	}
	l.end()
	got := l.String()
	if len(got) > 120 {
		t.Fatalf("log of %d bytes, want at most 120: %q", len(got), got)
	}
	marker, rest, _ := strings.Cut(got, "\n")
	if !strings.Contains(marker, "dropped") || !strings.HasSuffix(rest, "line 49\n") || !strings.HasPrefix(rest, "line ") {
		t.Errorf("log = %q, want a marker and the newest whole lines", got)
	}
	// One line longer than the whole log keeps its end.
	l.write([]byte(strings.Repeat("a", 500) + "the end\n"))
	if got := l.String(); len(got) > 120 || !strings.HasSuffix(got, "aaathe end\n") || strings.Count(got, "dropped") != 1 {
		t.Errorf("log = %q, want the end of the long line under one marker", got)
	}
}

// --- persistence ---

// The log of a running job is in the database while it runs, so that a page
// that is opened again sees how far it got.
func TestProgressIsSaved(t *testing.T) {
	r, db := newRunner(t)
	release := make(chan struct{})
	id := start(t, r, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		writeLines(log, "step 1 of 2")
		<-release
		writeLines(log, "step 2 of 2")
		return nil
	})
	deadline := time.Now().Add(waitTimeout)
	for {
		rec, err := db.JobByID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status != store.JobRunning {
			t.Fatalf("the job ended early: %+v", rec)
		}
		if rec.Log == "step 1 of 2\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log of the running job is %q in the database", rec.Log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if j := waitDone(t, r, id); j.Log != "step 1 of 2\nstep 2 of 2\n" {
		t.Errorf("final log %q", j.Log)
	}
}

// A job that was running when the panel stopped is failed when it starts
// again: nothing runs it any more.
func TestRestartFailsTheJobsThatWereRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db1 := openDB(t, path)
	old, err := New(context.Background(), db1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRunner(t, old)
	release := make(chan struct{})
	running := start(t, old, "NODE1", nil, func(_ context.Context, log io.Writer) error {
		writeLines(log, "halfway")
		<-release
		return nil
	})
	finished := start(t, old, "NODE2", nil, func(context.Context, io.Writer) error { return nil })
	waitDone(t, old, finished)
	waitFor(t, "the log to be saved", func() bool {
		rec, err := db1.JobByID(context.Background(), running)
		return err == nil && rec.Log != ""
	})

	// The panel starts again, on the same database.
	db2 := openDB(t, path)
	restarted, err := New(context.Background(), db2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeRunner(t, restarted)
	j, err := restarted.Get(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != StatusFailed || j.Error != RestartedError || j.FinishedAt == nil || j.Log != "halfway\n" {
		t.Errorf("the interrupted job = %+v, want failed because the panel restarted, with its log", j)
	}
	if j, _ := restarted.Get(context.Background(), finished); j.Status != StatusDone {
		t.Errorf("a finished job changed: %+v", j)
	}
	// The node can run a job again.
	again := start(t, restarted, "NODE1", nil, func(context.Context, io.Writer) error { return nil })
	waitDone(t, restarted, again)

	// The old process going on does not bring the job back.
	close(release)
	closeRunner(t, old)
	if j, _ := restarted.Get(context.Background(), running); j.Status != StatusFailed || j.Error != RestartedError {
		t.Errorf("after the old runner finished it: %+v", j)
	}
}

func TestCloseStopsTheJobs(t *testing.T) {
	r, _ := newRunner(t)
	running := make(chan struct{})
	id := start(t, r, "NODE1", nil, func(ctx context.Context, _ io.Writer) error {
		close(running)
		<-ctx.Done()
		return ctx.Err()
	})
	<-running
	closeRunner(t, r)
	j, err := r.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != StatusFailed || j.Error != StoppedError {
		t.Errorf("job after Close = %+v, want failed because the panel stopped", j)
	}
	if _, err := r.Start(context.Background(), "NODE2", "install", nil, func(context.Context, io.Writer) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close: err = %v, want ErrClosed", err)
	}
}

// Close gives up waiting when its context ends; the job is failed when the
// panel starts again.
func TestCloseDoesNotWaitForever(t *testing.T) {
	r, _ := newRunner(t)
	release := make(chan struct{})
	defer close(release)
	start(t, r, "NODE1", nil, func(context.Context, io.Writer) error {
		<-release // ignores its context
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close: err = %v, want DeadlineExceeded", err)
	}
}

// --- the timing of saves, in a bubble with a fake clock ---

// memStore is a Store in memory that records when logs were saved and when
// the ends of jobs were tried.
type memStore struct {
	mu        sync.Mutex
	jobs      map[string]store.Job
	saves     map[string][]time.Time
	endTries  map[string][]time.Time
	failSaves int // UpdateJobLog fails this many times first
	failEnds  int // FinishJob fails this many times first

	// manyRunning makes CreateJob take a second running job of a node, which
	// the database refuses: only the runner keeps a node to one job then.
	manyRunning bool

	// onCreate, if set, is called by CreateJob before it does anything, as a
	// database that takes its time.
	onCreate func(nodeID string)
}

func newMemStore() *memStore {
	return &memStore{jobs: map[string]store.Job{}, saves: map[string][]time.Time{}, endTries: map[string][]time.Time{}}
}

func (m *memStore) CreateJob(_ context.Context, j *store.Job) error {
	if m.onCreate != nil {
		m.onCreate(j.NodeID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.jobs {
		if o.NodeID == j.NodeID && o.Status == store.JobRunning && !m.manyRunning {
			return store.ErrConflict
		}
	}
	j.ID, j.Status, j.StartedAt = ids.New(), store.JobRunning, time.Now()
	m.jobs[j.ID] = *j
	return nil
}

func (m *memStore) JobByID(_ context.Context, id string) (*store.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &j, nil
}

func (m *memStore) UpdateJobLog(_ context.Context, id, log string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSaves > 0 {
		m.failSaves--
		return errors.New("disk full")
	}
	j, ok := m.jobs[id]
	if !ok || j.Status != store.JobRunning {
		return store.ErrNotFound
	}
	j.Log = log
	m.jobs[id] = j
	m.saves[id] = append(m.saves[id], time.Now())
	return nil
}

func (m *memStore) FinishJob(_ context.Context, id, status, log, errText string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endTries[id] = append(m.endTries[id], time.Now())
	if m.failEnds > 0 {
		m.failEnds--
		return errors.New("database is locked")
	}
	j, ok := m.jobs[id]
	if !ok || j.Status != store.JobRunning {
		return store.ErrNotFound
	}
	now := time.Now()
	j.Status, j.Log, j.Error, j.FinishedAt = status, log, errText, &now
	m.jobs[id] = j
	return nil
}

func (m *memStore) FailRunningJobs(context.Context, string) (int64, error) { return 0, nil }

func (m *memStore) savesOf(id string) []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.saves[id])
}

func (m *memStore) endTriesOf(id string) []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.endTries[id])
}

// all returns every job.
func (m *memStore) all() []store.Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Job
	for _, j := range m.jobs {
		out = append(out, j)
	}
	return out
}

// waitDoneInBubble is waitDone in a synctest bubble, where sleeping costs no
// time.
func waitDoneInBubble(t *testing.T, r *Runner, id string) Job {
	t.Helper()
	for range 100000 { // up to 5000 s of the fake clock

		j, err := r.Get(t.Context(), id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if j.Status != StatusRunning && released(r, id) {
			return j
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s is still running", id)
	return Job{}
}

// A job that writes a line every 10 ms for 2 s has its log saved as it goes,
// but at most every 500 ms.
func TestLogIsSavedAtMostEvery500ms(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		id, err := r.Start(t.Context(), "NODE1", "install", nil, func(_ context.Context, log io.Writer) error {
			for i := range 200 {
				_, _ = fmt.Fprintf(log, "line %d\n", i)
				time.Sleep(10 * time.Millisecond)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		j := waitDoneInBubble(t, r, id)
		if j.Status != StatusDone || strings.Count(j.Log, "\n") != 200 {
			t.Fatalf("job = %s with %d lines", j.Status, strings.Count(j.Log, "\n"))
		}
		saves := st.savesOf(id)
		if len(saves) < 3 || len(saves) > 5 {
			t.Errorf("the log was saved %d times in 2 s, want 3 to 5", len(saves))
		}
		if len(saves) > 0 && saves[0].Sub(begin) > 0 {
			t.Errorf("the first line was saved after %v, want at once", saves[0].Sub(begin))
		}
		for i := 1; i < len(saves); i++ {
			if gap := saves[i].Sub(saves[i-1]); gap < FlushInterval {
				t.Errorf("saves %d and %d are %v apart, want at least %v", i-1, i, gap, FlushInterval)
			}
		}
		if err := r.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// A job that writes nothing for a while costs no saves.
func TestNoSavesWithoutNewLines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		id, err := r.Start(t.Context(), "NODE1", "install", nil, func(_ context.Context, log io.Writer) error {
			writeLines(log, "one")
			time.Sleep(10 * time.Second)
			_, _ = io.WriteString(log, "an unfinished line, which waits for its end")
			time.Sleep(10 * time.Second)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		waitDoneInBubble(t, r, id)
		if n := len(st.savesOf(id)); n != 1 {
			t.Errorf("%d saves, want 1", n)
		}
		if err := r.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// A save that fails is tried again with the next one, and the end of a job is
// tried again until the database takes it.
func TestFailedSavesAreRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.failSaves, st.failEnds = 1, 2
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		id, err := r.Start(t.Context(), "NODE1", "install", nil, func(_ context.Context, log io.Writer) error {
			writeLines(log, "one")
			time.Sleep(2 * time.Second)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if j, _ := r.Get(t.Context(), id); j.Log != "one\n" {
			t.Errorf("log while running = %q, want the line saved by a second try", j.Log)
		}
		if j := waitDoneInBubble(t, r, id); j.Status != StatusDone || j.Log != "one\n" {
			t.Errorf("job = %+v, want done after the end was tried again", j)
		}
		if err := r.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// When the database does not take the end of a job, the runner tries again,
// further and further apart, but never more than finishMaxDelay apart, until
// it does; the node stays busy in the meantime, as the database has it. The
// store here would take a second running job of the node, so the runner
// itself has to keep the node busy.
func TestEndOfAJobIsRecordedAtLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.failEnds, st.manyRunning = 8, true
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		nothing := func(context.Context, io.Writer) error { return nil }
		id, err := r.Start(t.Context(), "NODE1", "install", nil, nothing)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		if j, _ := r.Get(t.Context(), id); j.Status != StatusRunning {
			t.Errorf("a minute on, the job is %s; want it still running, as its end is not recorded", j.Status)
		}
		if _, err := r.Start(t.Context(), "NODE1", "install", nil, nothing); !errors.Is(err, ErrBusy) {
			t.Errorf("Start for the node: err = %v, want ErrBusy", err)
		}

		if j := waitDoneInBubble(t, r, id); j.Status != StatusDone {
			t.Fatalf("job = %+v, want done at last", j)
		}
		tries := st.endTriesOf(id)
		if len(tries) != 9 {
			t.Fatalf("the end was tried %d times, want 9", len(tries))
		}
		var last time.Duration
		for i := 1; i < len(tries); i++ {
			gap := tries[i].Sub(tries[i-1])
			if gap < last || gap > finishMaxDelay || (i == 1 && gap != finishFirstDelay) {
				t.Errorf("tries %d and %d are %v apart (the one before: %v)", i-1, i, gap, last)
			}
			last = gap
		}
		if last != finishMaxDelay {
			t.Errorf("the last gap is %v, want the longest, %v", last, finishMaxDelay)
		}
		again, err := r.Start(t.Context(), "NODE1", "install", nil, nothing)
		if err != nil {
			t.Fatalf("Start once the end is recorded: %v", err)
		}
		waitDoneInBubble(t, r, again)
		if err := r.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// lockedBuffer is a bytes.Buffer that goroutines may write at the same time.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A database that keeps refusing the end of a job shows in the log: the first
// failure, and every tenth try after it.
func TestFailedEndsAreLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.failEnds = 25
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		var logs lockedBuffer
		r.logger = slog.New(slog.NewTextHandler(&logs, nil))
		id, err := r.Start(t.Context(), "NODE1", "install", nil, func(context.Context, io.Writer) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		waitDoneInBubble(t, r, id)
		var attempts []string
		for line := range strings.SplitSeq(logs.String(), "\n") {
			if strings.Contains(line, "could not record the end of a job") {
				_, after, _ := strings.Cut(line, "attempt=")
				attempt, _, _ := strings.Cut(after, " ")
				attempts = append(attempts, attempt)
			}
		}
		if want := []string{"1", "10", "20"}; !slices.Equal(attempts, want) {
			t.Errorf("failures logged at the tries %q, want %q\n%s", attempts, want, logs.String())
		}
		if err := r.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

// The runner logs to the default logger as it is when it logs, not as it was
// when the runner was made: the panel may set it up later.
func TestRunnerLogsToTheCurrentDefault(t *testing.T) {
	// The first default is a logger of its own: the one that a program starts
	// with sends its output to whatever the default is later, which would hide
	// the difference.
	old := slog.Default()
	defer slog.SetDefault(old)
	var before, after lockedBuffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&before, nil)))
	r, _ := newRunner(t)
	slog.SetDefault(slog.New(slog.NewTextHandler(&after, nil)))

	id := start(t, r, "NODE1", nil, func(context.Context, io.Writer) error { panic("on purpose") })
	waitDone(t, r, id)
	if !strings.Contains(after.String(), "a job panicked") || strings.Contains(before.String(), "a job panicked") {
		t.Errorf("the default before got %q and the default after %q; want the panic in the latter",
			before.String(), after.String())
	}
}

// Close does not wait for ever for a database that does not take the ends of
// jobs: it gives up when its context ends, and the runner stops trying. A job
// whose end is not recorded is failed when the panel starts again.
func TestCloseGivesUpOnTheEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newMemStore()
		st.failEnds = 1 << 30
		r, err := New(t.Context(), st)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Start(t.Context(), "NODE1", "install", nil, func(context.Context, io.Writer) error { return nil }); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Close: err = %v, want DeadlineExceeded", err)
		}
		// The bubble ends only when every goroutine of the runner has.
	})
}

// A start that waits for the database does not hold the runner up: another job
// is cancelled meanwhile.
func TestSlowStartDoesNotHoldTheRunner(t *testing.T) {
	st := newMemStore()
	release := make(chan struct{})
	creating := make(chan struct{})
	st.onCreate = func(nodeID string) {
		if nodeID == "NODE2" {
			close(creating)
			<-release
		}
	}
	r, err := New(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRunner(t, r)
	waiting := start(t, r, "NODE1", nil, func(ctx context.Context, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	})
	started := make(chan error, 1)
	go func() {
		_, err := r.Start(context.Background(), "NODE2", "install", nil, func(context.Context, io.Writer) error { return nil })
		started <- err
	}()
	<-creating
	defer func() {
		close(release)
		if err := <-started; err != nil {
			t.Errorf("the slow Start: %v", err)
		}
	}()

	cancelled := make(chan error, 1)
	go func() { cancelled <- r.Cancel(waiting) }()
	select {
	case err := <-cancelled:
		if err != nil {
			t.Errorf("Cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Cancel waited for a Start that waits for the database")
	}
	if _, err := r.Start(context.Background(), "NODE2", "install", nil, func(context.Context, io.Writer) error { return nil }); !errors.Is(err, ErrBusy) {
		t.Errorf("a second Start for the node that is starting: err = %v, want ErrBusy", err)
	}
}

// A runner that is closed while a job is being created does not run it: the
// job is recorded as failed, and Start says that the runner is closed.
func TestCloseDuringASlowStart(t *testing.T) {
	st := newMemStore()
	release := make(chan struct{})
	creating := make(chan struct{})
	st.onCreate = func(string) {
		close(creating)
		<-release
	}
	r, err := New(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	var ran atomic.Bool
	started := make(chan error, 1)
	go func() {
		_, err := r.Start(context.Background(), "NODE1", "install", nil, func(context.Context, io.Writer) error {
			ran.Store(true)
			return nil
		})
		started <- err
	}()
	<-creating
	closed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()
		closed <- r.Close(ctx)
	}()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while a job was being created: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-started; !errors.Is(err, ErrClosed) {
		t.Errorf("Start: err = %v, want ErrClosed", err)
	}
	if err := <-closed; err != nil {
		t.Errorf("Close: %v", err)
	}
	if ran.Load() {
		t.Error("the job ran")
	}
	all := st.all()
	if len(all) != 1 || all[0].Status != StatusFailed || all[0].Error != StoppedError {
		t.Errorf("jobs = %+v, want one, failed because the panel stopped", all)
	}
}

// waitFor polls cond until it holds and fails the test if it does not within
// waitTimeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
