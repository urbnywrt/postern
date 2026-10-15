//go:build unix

package nodes

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// mkfifo puts a FIFO where the file name of the kit was. Nothing ever writes
// to it, so a reader that opens it the blocking way waits for ever.
func (k *testKit) mkfifo(name string) {
	k.t.Helper()
	k.remove(name)
	if err := syscall.Mkfifo(k.path(name), 0o644); err != nil {
		k.t.Fatal(err)
	}
}

// within runs f and fails the test unless it returns within d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s still waits after %v", what, d)
	}
}

// A file of a kit that is a FIFO is no file of a kit, and it holds nothing up:
// neither the check of the kit nor a download waits for a writer that never
// comes.
func TestKitWithAFIFOIsNotAKit(t *testing.T) {
	for _, name := range []string{"amd64/postern-node", "install.sh", "compose.yaml"} {
		t.Run(name, func(t *testing.T) {
			kit := newTestKit(t, "amd64")
			kit.mkfifo(name)
			logs := &lockedBuffer{}
			s := &Service{kitDir: kit.dir, log: slog.New(slog.NewTextHandler(logs, nil))}

			within(t, 2*time.Second, "the check of the kit", func() {
				if s.kitAvailable("amd64") {
					t.Error("a kit with a FIFO in it is available")
				}
			})
			within(t, 2*time.Second, "the download of the kit", func() {
				req := httptest.NewRequest(http.MethodGet, "/api/node-kit/amd64", nil)
				req.SetPathValue("arch", "amd64")
				rec := httptest.NewRecorder()
				s.serveKit(rec, req)
				if rec.Code != http.StatusNotFound {
					t.Errorf("status %d, want 404", rec.Code)
				}
			})
			if got := logs.String(); !strings.Contains(got, "is not a regular file") {
				t.Errorf("the log does not say what is wrong:\n%s", got)
			}
		})
	}
}

// What openKitFile looked at may be given a FIFO before it is opened: the
// open does not wait for a writer either, and what is open is refused.
func TestKitFileIsOpenedWithoutWaiting(t *testing.T) {
	kit := newTestKit(t, "amd64")
	kit.mkfifo("install.sh")
	within(t, 2*time.Second, "opening the FIFO", func() {
		f, _, err := openCheckedKitFile(kit.path("install.sh"), false)
		if err == nil {
			_ = f.Close()
			t.Error("a FIFO was taken for a file of the kit")
		} else if !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("err = %v, want one that says it is not a regular file", err)
		}
	})
	// A regular file is read as ever, whatever O_NONBLOCK would do to another.
	f, size, err := openCheckedKitFile(kit.path("launcher.sh"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	data, err := os.ReadFile(kit.path("launcher.sh"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, size)
	if n, err := f.Read(buf); err != nil || n != len(data) || string(buf) != string(data) {
		t.Errorf("read %d bytes (%v) of launcher.sh, want its %d", n, err, len(data))
	}
}
