package acme

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Put stores an imported certificate as the manager stores its own: the same
// layout, the key 0600, and a status that is valid for the domain.
func TestPutStoresAnImportedCertificate(t *testing.T) {
	r := newRig(t)
	ca := newTestCA(t)
	now := r.clock.now()
	is := ca.issue(t, "web.example.com", now.Add(-time.Hour), now.Add(80*24*time.Hour))

	res, err := r.m.Put(context.Background(), "web.example.com", is.fullchain, is.key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(is.fullchain)
	if res.SHA256 != hex.EncodeToString(sum[:]) || !res.Stored || !res.NotAfter.Equal(now.Add(80*24*time.Hour).Truncate(time.Second)) {
		t.Errorf("result = %+v", res)
	}
	dir := r.dir("web.example.com")
	if got := mode(t, filepath.Join(dir, privkeyFile)); got != 0o600 {
		t.Errorf("privkey mode = %o, want 0600", got)
	}
	meta, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil || !strings.Contains(string(meta), `"staging": false`) {
		t.Errorf("meta.json = %s, %v", meta, err)
	}
	st := r.m.Status("web.example.com")
	if !st.Valid || st.FullchainSHA256 != res.SHA256 {
		t.Errorf("status = %+v, want valid with the stored digest", st)
	}

	// The same certificate again is not written again.
	before, _ := os.Stat(filepath.Join(dir, fullchainFile))
	time.Sleep(10 * time.Millisecond)
	again, err := r.m.Put(context.Background(), "web.example.com", is.fullchain, is.key)
	if err != nil || again.Stored || again.SHA256 != res.SHA256 {
		t.Errorf("second Put = %+v, %v; want not stored", again, err)
	}
	after, _ := os.Stat(filepath.Join(dir, fullchainFile))
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("the files were written again")
	}

	// A new certificate replaces it.
	next := ca.issue(t, "web.example.com", now, now.Add(90*24*time.Hour))
	res2, err := r.m.Put(context.Background(), "web.example.com", next.fullchain, next.key)
	if err != nil || !res2.Stored || res2.SHA256 == res.SHA256 {
		t.Errorf("third Put = %+v, %v; want stored with a new digest", res2, err)
	}
}

func TestPutRefusesWhatCannotBeServed(t *testing.T) {
	r := newRig(t)
	ca := newTestCA(t)
	now := r.clock.now()
	good := ca.issue(t, "web.example.com", now.Add(-time.Hour), now.Add(80*24*time.Hour))
	other := ca.issue(t, "other.example.com", now.Add(-time.Hour), now.Add(80*24*time.Hour))
	expired := ca.issue(t, "web.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour))

	cases := []struct {
		name, domain string
		chain, key   []byte
		want         string
	}{
		{"upper case domain", "Web.example.com", good.fullchain, good.key, "lowercase"},
		{"path in the domain", "../web.example.com", good.fullchain, good.key, "lowercase"},
		{"wrong domain", "web.example.com", other.fullchain, other.key, "not for web.example.com"},
		{"key of another", "web.example.com", good.fullchain, other.key, "not a pair"},
		{"expired", "web.example.com", expired.fullchain, expired.key, "expired"},
		{"garbage", "web.example.com", []byte("not pem"), good.key, "not a pair"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.m.Put(context.Background(), c.domain, c.chain, c.key)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Error("the error holds key material")
			}
		})
	}
	if _, err := os.Stat(r.dir("web.example.com")); !os.IsNotExist(err) {
		t.Errorf("a refused certificate left files: %v", err)
	}
}

// F5 of the real-server pass: a certificate minted a moment ago by a clock a
// little ahead of the node's is taken and valid (webrules.ClockTolerance); one
// that starts later than that is refused.
func TestPutToleratesASmallClockSkew(t *testing.T) {
	r := newRig(t)
	ca := newTestCA(t)
	now := r.clock.now()
	soon := ca.issue(t, "web.example.com", now.Add(2*time.Minute), now.Add(80*24*time.Hour))
	if _, err := r.m.Put(context.Background(), "web.example.com", soon.fullchain, soon.key); err != nil {
		t.Fatalf("Put of a certificate valid in 2 minutes: %v", err)
	}
	if st := r.m.Status("web.example.com"); !st.Valid {
		t.Errorf("status = %+v, want valid", st)
	}
	later := ca.issue(t, "late.example.com", now.Add(time.Hour), now.Add(80*24*time.Hour))
	if _, err := r.m.Put(context.Background(), "late.example.com", later.fullchain, later.key); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Errorf("Put of a certificate valid in an hour: %v", err)
	}
}

// Put waits for an issuance of the domain that runs: the files are never
// written by two hands at once.
func TestPutWaitsForTheIssuance(t *testing.T) {
	r := newRig(t)
	ca := newTestCA(t)
	now := r.clock.now()
	is := ca.issue(t, "web.example.com", now.Add(-time.Hour), now.Add(80*24*time.Hour))
	f := &flight{done: make(chan struct{})}
	r.m.init()
	r.m.mu.Lock()
	r.m.flights["web.example.com"] = f
	r.m.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := r.m.Put(context.Background(), "web.example.com", is.fullchain, is.key)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("Put returned %v while the issuance ran", err)
	case <-time.After(50 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.m.Put(ctx, "web.example.com", is.fullchain, is.key); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Put with an ending context = %v, want its error", err)
	}
	r.m.mu.Lock()
	delete(r.m.flights, "web.example.com")
	r.m.mu.Unlock()
	close(f.done)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !r.m.Status("web.example.com").Valid {
		t.Error("the certificate was not stored after the issuance ended")
	}
}

// F6 of the real-server pass: Trusted verifies the stored chain against the
// roots: a chain of a private CA is not publicly trusted, and is with that CA
// as a root.
func TestTrustedVerifiesTheStoredChain(t *testing.T) {
	r := newRig(t)
	ca := newTestCA(t)
	now := r.clock.now()
	good := ca.issue(t, "web.example.com", now.Add(-time.Hour), now.Add(80*24*time.Hour))
	if _, err := r.m.Put(context.Background(), "web.example.com", good.fullchain, good.key); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if err := r.m.Trusted("web.example.com", pool); err != nil {
		t.Errorf("with the CA as a root: %v", err)
	}
	if err := r.m.Trusted("web.example.com", x509.NewCertPool()); err == nil || errors.Is(err, ErrNoRoots) {
		t.Errorf("with no such root: %v", err)
	}
	if err := r.m.Trusted("web.example.com", nil); err == nil {
		t.Error("a private CA is trusted by the system's roots")
	}
	if err := r.m.Trusted("none.example.com", pool); err == nil {
		t.Error("no certificate is trusted")
	}
}
