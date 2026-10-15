package selfupdate

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// FuzzUpload sends tar bodies to the upload: whatever they hold, the handler
// does not panic, answers once, and keeps nothing of a bundle it did not
// accept (and no temporary directory ever).
func FuzzUpload(f *testing.F) {
	fx := newUpload(f)
	good := fx.good(f, "v0.5.0")
	f.Add(tarOf(f, good...))
	f.Add(tarOf(f, good[:2]...)[:600])
	f.Add(tarOf(f, member{"../x", []byte("x")}, member{"postern-node-linux-amd64", []byte("not an elf")}))
	f.Add([]byte("not a tar at all"))
	f.Add(bytes.Repeat([]byte{0}, 1024))
	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, UploadRoute, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-tar")
		rr := httptest.NewRecorder()
		fx.h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			return // only a verified bundle gets here (the seed)
		}
		entries, _ := os.ReadDir(fx.cache.Dir)
		for _, e := range entries {
			if e.Name() != "v0.5.0" {
				t.Fatalf("status %d left %s under the cache", rr.Code, e.Name())
			}
		}
	})
}
