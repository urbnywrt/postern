package geodb

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

// put sends a PUT /api/geoip with the client and the body, and returns the
// response and what it says.
func (p *panel) put(client *http.Client, body io.Reader, header map[string]string) (*http.Response, string) {
	p.t.Helper()
	return p.send(client, http.MethodPut, body, header)
}

func (p *panel) send(client *http.Client, method string, body io.Reader, header map[string]string) (*http.Response, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, p.srv.URL+"/api/geoip", body)
	if err != nil {
		p.t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		p.t.Fatalf("%s /api/geoip: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.t.Fatal(err)
	}
	return resp, string(data)
}

// unknownLength hides the length of a body, so that it is sent chunked.
func unknownLength(b []byte) io.Reader { return io.NopCloser(bytes.NewReader(b)) }

// uploads are the audit entries of uploads, from the log.
func (p *panel) uploads() []string {
	var out []string
	for _, line := range p.audit() {
		if strings.HasPrefix(line, "geoip.upload ") {
			out = append(out, line)
		}
	}
	return out
}

// The upload takes the file of an admin only: whoever else sends it, and
// whatever it is, is turned away before the body is read.
func TestUploadNeedsAnAdmin(t *testing.T) {
	p := newPanel(t)
	db := monthDB(t, "2026-10", "DE")

	for _, c := range []struct {
		name   string
		header map[string]string
		body   io.Reader
	}{
		{"no session", nil, bytes.NewReader(db)},
		{"a cookie that is no session", map[string]string{"Cookie": "postern_session=" + strings.Repeat("A", 43)}, bytes.NewReader(db)},
		// The size is no reason to answer before asking who it is.
		{"no session, and too much", nil, unknownLength(bytes.Repeat([]byte("x"), 5000))},
	} {
		t.Run(c.name, func(t *testing.T) {
			p.m.maxUpload = int64(len(db))
			resp, body := p.put(p.plain, c.body, c.header)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d (%.100q), want 401", resp.StatusCode, body)
			}
			var e struct{ Code string }
			if err := json.Unmarshal([]byte(body), &e); err != nil || e.Code != "unauthenticated" {
				t.Errorf("body %q, want a Connect error of code unauthenticated", body)
			}
			if st, _ := p.m.Status(p.ctx); st.Present {
				t.Error("a database was installed by a stranger")
			}
			if got := p.names(); len(got) != 0 {
				t.Errorf("the directory holds %q", got)
			}
			if got := p.uploads(); len(got) != 0 {
				t.Errorf("audit: %q", got)
			}
		})
	}
}

func TestUploadInstallsTheDatabase(t *testing.T) {
	for _, c := range []struct {
		name string
		pack func(*testing.T, []byte) []byte
		// header is what a client says about the body, which does not matter: the
		// first bytes tell whether it is gzip.
		header map[string]string
	}{
		{"unpacked", func(_ *testing.T, b []byte) []byte { return b }, map[string]string{"Content-Type": "application/octet-stream"}},
		{"gzip", gzipped, map[string]string{"Content-Type": "application/gzip"}},
		{"gzip with nothing said about it", gzipped, nil},
		{"unpacked, called gzip", func(_ *testing.T, b []byte) []byte { return b }, map[string]string{"Content-Encoding": "gzip"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPanel(t)
			built := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
			db := monthDB(t, "2026-09", "DE", geoiptest.WithBuilt(built))
			changes := 0
			p.m.OnChange(func() { changes++ })

			resp, body := p.put(p.web, bytes.NewReader(c.pack(t, db)), c.header)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if got := resp.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type %q, want application/json", got)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q, want no-store", got)
			}

			// The answer is the status, as JSON that the UI can read.
			var st panelv1.GeoIPStatus
			if err := protojson.Unmarshal([]byte(body), &st); err != nil {
				t.Fatalf("the answer is not a GeoIPStatus: %v: %s", err, body)
			}
			if !st.GetEnabled() || !st.GetPresent() || st.GetMonth() != "2026-09" || st.GetBuiltUnix() != built.Unix() ||
				st.GetSize() != int64(len(db)) || st.GetSha256() != sumOf(db) || st.GetFetchedUnix() != t0.Unix() ||
				st.GetCheckedUnix() != 0 || st.GetError() != "" ||
				st.GetAttribution() != geoip.Attribution || st.GetAttributionUrl() != geoip.AttributionURL || st.GetLicence() != geoip.Licence {
				t.Errorf("status = %+v", &st)
			}
			// The zero values are in it, too: a client that reads fields by name
			// finds them all.
			var fields map[string]any
			if err := json.Unmarshal([]byte(body), &fields); err != nil {
				t.Fatal(err)
			}
			if _, ok := fields["checkedUnix"]; !ok {
				t.Errorf("the answer has no checkedUnix: %s", body)
			}

			if got := p.m.Country(addrV4); got != "DE" {
				t.Errorf("Country = %q, want DE", got)
			}
			if changes != 1 {
				t.Errorf("OnChange was called %d times, want 1", changes)
			}
			// Audited, with the admin that did it.
			uploads := p.uploads()
			if len(uploads) != 1 {
				t.Fatalf("audit: %q, want one geoip.upload", uploads)
			}
			for _, want := range []string{" " + p.adminID + " ", `"month":"2026-09"`, `"sha256":"` + sumOf(db) + `"`} {
				if !strings.Contains(uploads[0], want) {
					t.Errorf("the audit entry %q does not have %q", uploads[0], want)
				}
			}
			if got := p.events("geoip.updated"); len(got) != 1 || got[0].Details["source"] != "upload" {
				t.Errorf("events = %+v", got)
			}
		})
	}
}

// A file that is no country database is refused with the reason, and what the
// panel had stays.
func TestUploadRefusesWhatIsNotADatabase(t *testing.T) {
	good := monthDB(t, "2026-09", "FR")
	packed := gzipped(t, good)
	corrupt := bytes.Clone(packed)
	for i := len(corrupt) / 2; i < len(corrupt)/2+8; i++ {
		corrupt[i] ^= 0xff
	}
	for _, c := range []struct {
		name string
		body []byte
		want string
	}{
		{"text", []byte("hello"), "not a MaxMind DB file"},
		{"nothing", nil, "not a MaxMind DB file"},
		{"gzip that is corrupt", corrupt, "could not unpack"},
		{"a database of ASNs", monthDB(t, "2026-10", "DE", geoiptest.WithType("GeoLite2-ASN")), "not a country database"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPanel(t)
			if _, err := p.m.Install(p.ctx, bytes.NewReader(good)); err != nil {
				t.Fatal(err)
			}
			resp, body := p.put(p.web, bytes.NewReader(c.body), nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d (%.100q), want 400", resp.StatusCode, body)
			}
			if !strings.Contains(body, c.want) {
				t.Errorf("the answer does not say %q: %q", c.want, body)
			}
			if got := p.m.Country(addrV4); got != "FR" {
				t.Errorf("Country = %q, want FR from the database that was there", got)
			}
			if got := p.uploads(); len(got) != 0 {
				t.Errorf("audit: %q, want nothing for an upload that failed", got)
			}
			if got, want := p.names(), []string{"dbip-country-lite-2026-09.mmdb"}; !slices.Equal(got, want) {
				t.Errorf("the directory holds %q, want %q", got, want)
			}
		})
	}
}

func TestUploadRefusesABodyThatIsTooLarge(t *testing.T) {
	db := monthDB(t, "2026-09", "FR")
	packed := gzipped(t, db)

	t.Run("by its length", func(t *testing.T) {
		p := newPanel(t)
		p.m.maxUpload = int64(len(db)) - 1
		resp, body := p.put(p.web, bytes.NewReader(db), nil)
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "larger than") {
			t.Errorf("status %d (%q), want 413 that says how large", resp.StatusCode, body)
		}
		if st, _ := p.m.Status(p.ctx); st.Present {
			t.Error("a database was installed")
		}
	})
	t.Run("a body that does not say how long it is", func(t *testing.T) {
		p := newPanel(t)
		p.m.maxUpload = 1000
		resp, body := p.put(p.web, unknownLength(bytes.Repeat([]byte("x"), 5000)), nil)
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "larger than") {
			t.Errorf("status %d (%q), want 413", resp.StatusCode, body)
		}
		if got := p.names(); len(got) != 0 {
			t.Errorf("the directory holds %q", got)
		}
	})
	t.Run("a gzip that unpacks to too much", func(t *testing.T) {
		p := newPanel(t)
		p.m.maxUnpacked = int64(len(db)) - 1
		resp, body := p.put(p.web, bytes.NewReader(packed), nil)
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(body, "the unpacked database is larger than") {
			t.Errorf("status %d (%q), want 413 that says that it is the unpacked database", resp.StatusCode, body)
		}
	})
	t.Run("exactly as much as may be sent", func(t *testing.T) {
		p := newPanel(t)
		p.m.maxUpload = int64(len(db))
		for _, body := range []io.Reader{bytes.NewReader(db), unknownLength(db)} {
			if resp, text := p.put(p.web, body, nil); resp.StatusCode != http.StatusOK {
				t.Errorf("status %d (%q), want 200", resp.StatusCode, text)
			}
		}
	})
}

// A body that says that it is too long is not read at all: the answer is sent
// from the length alone, before a byte of it is asked for. The handler is
// called without the admin check, which is in front of it in the panel, and
// without a client, since a client that stops sending when the server answers
// would only show how long net/http waits for it.
func TestUploadRefusesALongBodyWithoutReadingIt(t *testing.T) {
	e := newEnv(t)
	e.m.maxUpload = 1000
	body := &unreadableBody{}
	req := httptest.NewRequest(http.MethodPut, "/api/geoip", body)
	req.ContentLength = 5000
	rec := httptest.NewRecorder()
	e.m.serveUpload(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "larger than") {
		t.Errorf("status %d (%q), want 413", rec.Code, rec.Body.String())
	}
	if body.reads != 0 {
		t.Errorf("the body was read %d times, want not at all", body.reads)
	}
}

// unreadableBody counts the times that it is read.
type unreadableBody struct{ reads int }

func (b *unreadableBody) Read([]byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *unreadableBody) Close() error { return nil }

func TestUploadIsPutOnly(t *testing.T) {
	p := newPanel(t)
	db := monthDB(t, "2026-09", "FR")
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		resp, _ := p.send(p.web, method, bytes.NewReader(db), nil)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != "PUT" {
			t.Errorf("%s: Allow %q, want PUT", method, got)
		}
		// And a stranger is no better off.
		if resp, _ := p.send(p.plain, method, bytes.NewReader(db), nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a session: status %d, want 401", method, resp.StatusCode)
		}
	}
	if st, _ := p.m.Status(p.ctx); st.Present {
		t.Error("a database was installed by a method that is not PUT")
	}
}
