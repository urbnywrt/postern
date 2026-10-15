package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testToken is the API token of the tests: made up, and long enough to stand
// out in a message that would quote it.
const testToken = "made-up-token-for-the-tests-0123"

// fakeCF is the part of the Cloudflare API that the provider uses, on an
// httptest TLS server. Listing the records of a zone returns all of them,
// whatever the filters say: the provider must not trust the filters.
type fakeCF struct {
	*httptest.Server
	t *testing.T

	mu      sync.Mutex
	zones   []cfZone
	records map[string][]cfRecord // by zone ID
	nextID  int
	log     []string // "METHOD path?query" of every request
	bodies  []cfRecord
	headers []http.Header
	// reject, when set, answers every request with its status and body.
	reject func() (int, string)
}

// newFakeCF returns the fake API with zones, active unless they say otherwise.
func newFakeCF(t *testing.T, zones ...cfZone) *fakeCF {
	t.Helper()
	for i := range zones {
		if zones[i].Status == "" {
			zones[i].Status = "active"
		}
	}
	f := &fakeCF{t: t, zones: zones, records: map[string][]cfRecord{}}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCF) api() string { return f.URL + "/client/v4" }

func (f *fakeCF) id() string {
	f.nextID++
	return fmt.Sprintf("%032x", f.nextID)
}

func (f *fakeCF) add(zone string, r cfRecord) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ID = f.id()
	f.records[zone] = append(f.records[zone], r)
	return r.ID
}

func (f *fakeCF) recordsOf(zone string) []cfRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.records[zone])
}

func (f *fakeCF) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeCF) reply(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status/100 == 2, "errors": []any{}, "result": result})
}

func (f *fakeCF) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/client/v4")
	if r.URL.RawQuery != "" {
		entry += "?" + r.URL.RawQuery
	}
	f.log = append(f.log, entry)
	f.headers = append(f.headers, r.Header.Clone())
	if f.reject != nil {
		status, body := f.reject()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/client/v4"), "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "zones":
		var out []cfZone
		for _, z := range f.zones {
			if z.Name == r.URL.Query().Get("name") {
				out = append(out, z)
			}
		}
		f.reply(w, http.StatusOK, out)
	case r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "dns_records":
		// One page of all the records, whatever the filters say.
		page, perPage := 1, 100
		if n, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
			page = n
		}
		if n, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil {
			perPage = n
		}
		recs := f.records[parts[1]]
		from, to := min((page-1)*perPage, len(recs)), min(page*perPage, len(recs))
		f.reply(w, http.StatusOK, recs[from:to])
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "dns_records":
		var rec cfRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			f.reply(w, http.StatusBadRequest, nil)
			return
		}
		f.bodies = append(f.bodies, rec)
		rec.ID = f.id()
		f.records[parts[1]] = append(f.records[parts[1]], rec)
		f.reply(w, http.StatusOK, rec)
	case r.Method == http.MethodDelete && len(parts) == 4 && parts[2] == "dns_records":
		recs := f.records[parts[1]]
		i := slices.IndexFunc(recs, func(rec cfRecord) bool { return rec.ID == parts[3] })
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":81044,"message":"Record does not exist."}],"result":null}`)
			return
		}
		f.records[parts[1]] = slices.Delete(recs, i, i+1)
		f.reply(w, http.StatusOK, map[string]string{"id": parts[3]})
	default:
		f.reply(w, http.StatusNotFound, nil)
	}
}

// testCloudflare is the provider of a manager that trusts the fake API.
func testCloudflare(t *testing.T, f *fakeCF, token string) *cloudflare {
	t.Helper()
	m := &Manager{RootCAs: trust(f.Server)}
	m.init()
	t.Cleanup(m.transport.CloseIdleConnections)
	return newCloudflare(CloudflareToken(token), m.httpClient(), f.api())
}

const zoneA = "0000000000000000000000000000000a"

func TestCloudflareFindsTheZoneByTheSuffixesOfTheDomain(t *testing.T) {
	tests := []struct {
		label    string
		zones    []cfZone
		domain   string
		wantZone string
		lookups  []string
	}{
		{
			label:    "a zone two labels up",
			zones:    []cfZone{{ID: zoneA, Name: "example.com"}},
			domain:   "web.sub.example.com",
			wantZone: zoneA,
			lookups:  []string{"web.sub.example.com", "sub.example.com", "example.com"},
		},
		{
			label:    "the longest suffix wins",
			zones:    []cfZone{{ID: zoneA, Name: "example.com"}, {ID: "0000000000000000000000000000000b", Name: "sub.example.com"}},
			domain:   "web.sub.example.com",
			wantZone: "0000000000000000000000000000000b",
			lookups:  []string{"web.sub.example.com", "sub.example.com"},
		},
		{
			label:    "the domain is a zone",
			zones:    []cfZone{{ID: zoneA, Name: "example.com"}},
			domain:   "example.com",
			wantZone: zoneA,
			lookups:  []string{"example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			f := newFakeCF(t, tt.zones...)
			cf := testCloudflare(t, f, testToken)
			if err := cf.Present(t.Context(), tt.domain, "v"); err != nil {
				t.Fatalf("Present: %v", err)
			}
			if err := cf.CleanUp(t.Context(), tt.domain, "v"); err != nil {
				t.Fatalf("CleanUp: %v", err)
			}
			var lookups []string
			for _, r := range f.requests() {
				if name, ok := strings.CutPrefix(r, "GET /zones?name="); ok {
					lookups = append(lookups, strings.TrimSuffix(name, "&per_page=50"))
				}
			}
			if !slices.Equal(lookups, tt.lookups) {
				t.Errorf("zone lookups = %q, want %q: once per provider, never the TLD", lookups, tt.lookups)
			}
			if got := f.requests(); !strings.HasPrefix(got[len(lookups)], "POST /zones/"+tt.wantZone+"/dns_records") {
				t.Errorf("the record went to %q, not to zone %s", got[len(lookups)], tt.wantZone)
			}
		})
	}
}

func TestCloudflareWithoutAZoneSaysSo(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "zone.test"})
	cf := testCloudflare(t, f, testToken)
	err := cf.Present(t.Context(), "web.example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "no active zone that the token sees holds web.example.com") {
		t.Fatalf("Present = %v, want that no zone holds the domain", err)
	}
	if want := []string{"GET /zones?name=web.example.com&per_page=50", "GET /zones?name=example.com&per_page=50"}; !slices.Equal(f.requests(), want) {
		t.Errorf("requests = %q, want %q", f.requests(), want)
	}
}

func TestCloudflarePresentWritesTheChallengeRecord(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com"})
	cf := testCloudflare(t, f, testToken)
	if err := cf.Present(t.Context(), "web.example.com", "Zm9vYmFy"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	want := cfRecord{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: `"Zm9vYmFy"`, TTL: 60}
	if !slices.Equal(f.bodies, []cfRecord{want}) {
		t.Errorf("the records written = %+v, want %+v", f.bodies, want)
	}
	for i, h := range f.headers {
		if got := h.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("request %d: Authorization = %q", i, got)
		}
		if got := h.Get("Accept"); got != "application/json" {
			t.Errorf("request %d: Accept = %q", i, got)
		}
	}
	if got := f.headers[len(f.headers)-1].Get("Content-Type"); got != "application/json" {
		t.Errorf("the POST has Content-Type %q", got)
	}
}

func TestCloudflareRemovesOnlyTheStaleChallengeRecords(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com"})
	stale1 := f.add(zoneA, cfRecord{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: `"old"`})
	stale2 := f.add(zoneA, cfRecord{Type: "TXT", Name: "_ACME-challenge.web.example.com.", Content: `"older"`})
	keep := []cfRecord{
		{Type: "A", Name: "_acme-challenge.web.example.com", Content: "192.0.2.1"},
		{Type: "TXT", Name: "web.example.com", Content: `"v=spf1 -all"`},
		{Type: "TXT", Name: "_acme-challenge.other.example.com", Content: `"theirs"`},
		{Type: "TXT", Name: "x._acme-challenge.web.example.com", Content: `"deeper"`},
		{Type: "CNAME", Name: "_acme-challenge.web.example.com", Content: "elsewhere.test"},
		{Type: "TXT", Name: "_acme-challenge.web.example.com.example.com", Content: `"look-alike"`},
	}
	for _, r := range keep {
		f.add(zoneA, r)
	}
	cf := testCloudflare(t, f, testToken)
	if err := cf.RemoveStale(t.Context(), "web.example.com"); err != nil {
		t.Fatalf("RemoveStale: %v", err)
	}
	var deleted []string
	for _, r := range f.requests() {
		if id, ok := strings.CutPrefix(r, "DELETE /zones/"+zoneA+"/dns_records/"); ok {
			deleted = append(deleted, id)
		}
	}
	if want := []string{stale1, stale2}; !slices.Equal(deleted, want) {
		t.Errorf("deleted %q, want only the stale TXT records %q", deleted, want)
	}
	if got := len(f.recordsOf(zoneA)); got != len(keep) {
		t.Errorf("%d records are left, want the %d others", got, len(keep))
	}
	if !slices.Contains(f.requests(), "GET /zones/"+zoneA+"/dns_records?name=_acme-challenge.web.example.com&page=1&per_page=100&type=TXT") {
		t.Errorf("the records were not asked for by type and name: %q", f.requests())
	}
}

func TestCloudflareRemovesTheStaleRecordsOfEveryPage(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com"})
	for i := range 150 {
		f.add(zoneA, cfRecord{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: fmt.Sprintf(`"old-%d"`, i)})
	}
	f.add(zoneA, cfRecord{Type: "TXT", Name: "web.example.com", Content: `"v=spf1 -all"`})
	cf := testCloudflare(t, f, testToken)
	if err := cf.RemoveStale(t.Context(), "web.example.com"); err != nil {
		t.Fatalf("RemoveStale: %v", err)
	}
	left := f.recordsOf(zoneA)
	if len(left) != 1 || left[0].Name != "web.example.com" {
		t.Errorf("%d records left, want only the one that is not a challenge", len(left))
	}
	var pages []string
	for _, r := range f.requests() {
		if strings.HasPrefix(r, "GET /zones/"+zoneA+"/dns_records?") {
			pages = append(pages, r)
		}
	}
	if len(pages) != 2 || !strings.Contains(pages[0], "page=1") || !strings.Contains(pages[1], "page=2") {
		t.Errorf("the records were listed by %q, want page 1 and page 2, which is short", pages)
	}
}

const zoneB = "0000000000000000000000000000000b"

func TestCloudflareTakesTheActiveZoneOnly(t *testing.T) {
	// A zone that is not active (pending, moved) does not answer for the
	// domain: the other one, active, of the same name does.
	f := newFakeCF(t, cfZone{ID: zoneB, Name: "example.com", Status: "pending"}, cfZone{ID: zoneA, Name: "example.com", Status: "active"})
	cf := testCloudflare(t, f, testToken)
	if err := cf.Present(t.Context(), "web.example.com", "v"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := f.requests(); !slices.Contains(got, "POST /zones/"+zoneA+"/dns_records") {
		t.Errorf("requests = %q, want the record in the active zone", got)
	}

	// A pending zone alone is no zone: the next suffix is looked at.
	f = newFakeCF(t, cfZone{ID: zoneB, Name: "web.example.com", Status: "pending"}, cfZone{ID: zoneA, Name: "example.com"})
	cf = testCloudflare(t, f, testToken)
	if err := cf.Present(t.Context(), "web.example.com", "v"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := f.requests(); !slices.Contains(got, "POST /zones/"+zoneA+"/dns_records") {
		t.Errorf("requests = %q, want the record in the active zone of the shorter suffix", got)
	}
}

func TestCloudflareRefusesTwoActiveZonesOfOneName(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com", Status: "active"}, cfZone{ID: zoneB, Name: "example.com", Status: "active"})
	cf := testCloudflare(t, f, testToken)
	for _, call := range []func() error{
		func() error { return cf.RemoveStale(t.Context(), "web.example.com") },
		func() error { return cf.Present(t.Context(), "web.example.com", "v") },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "2 active zones named example.com") {
			t.Errorf("= %v, want the two zones refused", err)
		}
	}
	for _, r := range f.requests() {
		if strings.Contains(r, "dns_records") {
			t.Errorf("a record was asked for or written: %s", r)
		}
	}
}

func TestCloudflareCleanUpDeletesOnlyItsOwnRecord(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com"})
	cf := testCloudflare(t, f, testToken)
	theirs := f.add(zoneA, cfRecord{Type: "TXT", Name: "_acme-challenge.web.example.com", Content: `"theirs"`})
	if err := cf.Present(t.Context(), "web.example.com", "mine"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// A value it never wrote: nothing to delete, and nothing is asked.
	before := len(f.requests())
	if err := cf.CleanUp(t.Context(), "web.example.com", "never-written"); err != nil {
		t.Fatalf("CleanUp of another value: %v", err)
	}
	if got := len(f.requests()); got != before {
		t.Errorf("CleanUp of a value it never wrote made %d requests", got-before)
	}
	if err := cf.CleanUp(t.Context(), "web.example.com", "mine"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	left := f.recordsOf(zoneA)
	if len(left) != 1 || left[0].ID != theirs {
		t.Errorf("records left = %+v, want only the one it did not write", left)
	}
	// Twice is fine; a record that is gone already is fine.
	if err := cf.CleanUp(t.Context(), "web.example.com", "mine"); err != nil {
		t.Errorf("a second CleanUp: %v", err)
	}
	if err := cf.Present(t.Context(), "web.example.com", "again"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.records[zoneA] = nil // someone deleted it
	f.mu.Unlock()
	if err := cf.CleanUp(t.Context(), "web.example.com", "again"); err != nil {
		t.Errorf("CleanUp of a record that is gone: %v", err)
	}
}

func TestCloudflareErrorsNeverHoldTheToken(t *testing.T) {
	tests := []struct {
		label  string
		status int
		body   string
		want   []string
	}{
		{
			label:  "an API error that quotes the token",
			status: http.StatusForbidden,
			body: `{"success":false,"errors":[{"code":10000,"message":"Authentication error for ` + testToken + `",` +
				`"error_chain":[{"code":6111,"message":"Invalid format for Authorization header: Bearer ` + testToken + `"}]}]}`,
			want: []string{"cloudflare: looking for the zone: HTTP 403: 10000 Authentication error for [redacted]; 6111 Invalid format"},
		},
		{
			label:  "a success that is not one",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1003,"message":"Invalid or missing zone id."}],"result":null}`,
			want:   []string{"HTTP 200: 1003 Invalid or missing zone id."},
		},
		{
			// Shortened after the token is taken out: no part of it is left.
			label:  "a long message with the token where it is cut",
			status: http.StatusBadRequest,
			body:   `{"success":false,"errors":[{"code":9000,"message":"` + strings.Repeat("x", 150) + testToken + `"}]}`,
			want:   []string{"HTTP 400: 9000 xxx"},
		},
		{
			label:  "an answer that is not JSON",
			status: http.StatusBadGateway,
			body:   "<html>bad gateway " + testToken + "</html>",
			want:   []string{"cloudflare: looking for the zone: HTTP 502"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			f := newFakeCF(t)
			f.reject = func() (int, string) { return tt.status, tt.body }
			cf := testCloudflare(t, f, testToken)
			for _, call := range []func() error{
				func() error { return cf.RemoveStale(t.Context(), "web.example.com") },
				func() error { return cf.Present(t.Context(), "web.example.com", "v") },
			} {
				err := call()
				if err == nil {
					t.Fatal("no error")
				}
				if strings.Contains(err.Error(), testToken[:8]) {
					t.Errorf("the error holds the token, or a part of it: %v", err)
				}
				for _, s := range tt.want {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("the error %q does not say %q", err, s)
					}
				}
			}
		})
	}

	// A connection that fails: the error names the step, not the URL.
	f := newFakeCF(t)
	cf := testCloudflare(t, f, testToken)
	f.Close()
	err := cf.Present(t.Context(), "web.example.com", "v")
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "/client/v4") {
		t.Errorf("a failed connection: %v", err)
	}
}

func TestCloudflareRefusesIDsThatAreNotIDs(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: "../../accounts", Name: "example.com"})
	cf := testCloudflare(t, f, testToken)
	err := cf.Present(t.Context(), "web.example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "no valid ID") {
		t.Fatalf("Present = %v, want the zone ID refused", err)
	}
	for _, r := range f.requests() {
		if strings.Contains(r, "accounts") {
			t.Errorf("a request went to %q", r)
		}
	}
}

func TestCloudflareStopsWithTheContext(t *testing.T) {
	f := newFakeCF(t, cfZone{ID: zoneA, Name: "example.com"})
	f.reject = func() (int, string) {
		time.Sleep(200 * time.Millisecond)
		return http.StatusOK, `{"success":true,"result":[]}`
	}
	cf := testCloudflare(t, f, testToken)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := cf.RemoveStale(ctx, "web.example.com"); err == nil {
		t.Error("RemoveStale went on after its context ended")
	}
}
