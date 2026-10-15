package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

var germany = netip.MustParseAddr("198.51.100.7")

// enableGeoIP turns the country lookups of a panel of a test on: they are off
// for every panel of the tests, see start.
func (p *panel) enableGeoIP() {
	p.t.Helper()
	if _, err := p.srv.geo.SetEnabled(context.Background(), true); err != nil {
		p.t.Fatalf("SetEnabled: %v", err)
	}
}

// countryDB is a country database that says that 198.51.100.0/24 is in country,
// built now.
func countryDB(t *testing.T, country string) []byte {
	t.Helper()
	data, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": country})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dbip is a stand-in for the download site of DB-IP: it serves a database as the
// file of every month, and counts what it is asked for.
func dbip(t *testing.T, db []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	packed := gzipBytes(t, db)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/free/dbip-country-lite-") || !strings.HasSuffix(r.URL.Path, ".mmdb.gz") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(packed)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The upload of the country database is for admins: nobody else gets to put a
// file on the disk of the panel, and the route answers as it does everywhere
// else, with the headers and the Connect error.
func TestGeoIPUploadRoute(t *testing.T) {
	p := newPanel(t)
	p.enableGeoIP()
	b := p.signIn()
	db := countryDB(t, "DE")

	resp, body := p.do(http.MethodPut, "/api/geoip", bytes.NewReader(db), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: status %d, want 401", resp.StatusCode)
	}
	if code, _ := errorBody(t, body); code != "unauthenticated" {
		t.Errorf("without a session: error code %q, want unauthenticated", code)
	}
	checkSecurityHeaders(t, "the upload without a session", resp)
	if got := p.srv.geo.Country(germany); got != "" {
		t.Errorf("a stranger's file is in use: Country = %q", got)
	}

	// A method that is not PUT is not the upload.
	resp, _ = b.do(http.MethodGet, "/api/geoip", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "PUT" {
		t.Errorf("GET: status %d, Allow %q, want 405 and PUT", resp.StatusCode, resp.Header.Get("Allow"))
	}

	// An admin: the file is installed under the data directory, and the answer
	// is the status.
	resp, body = b.do(http.MethodPut, "/api/geoip", bytes.NewReader(gzipBytes(t, db)), map[string]string{"Content-Type": "application/gzip"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with a session: status %d: %s", resp.StatusCode, body)
	}
	checkSecurityHeaders(t, "the upload", resp)
	var st panelv1.GeoIPStatus
	if err := protojson.Unmarshal([]byte(body), &st); err != nil || !st.GetPresent() || st.GetMonth() != time.Now().UTC().Format("2006-01") {
		t.Errorf("the answer is %s (%v), want the status of a database of this month", body, err)
	}
	if got := p.srv.geo.Country(germany); got != "DE" {
		t.Errorf("Country = %q, want DE", got)
	}
	files, err := filepath.Glob(filepath.Join(p.dataDir, "geoip", "dbip-country-lite-*.mmdb"))
	if err != nil || len(files) != 1 {
		t.Errorf("the data directory holds %q (err %v), want one database in geoip/", files, err)
	}

	// The service says the same, through the API.
	geo := panelv1connect.NewGeoIPServiceClient(b.http, p.ts.URL+"/api")
	got, err := geo.GetGeoIP(context.Background(), connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil || !got.Msg.GetStatus().GetPresent() || got.Msg.GetStatus().GetSha256() != st.GetSha256() || got.Msg.GetStatus().GetAttributionUrl() != "https://db-ip.com" {
		t.Errorf("GetGeoIP = %+v, %v", got, err)
	}

	// It is not an upload without a session either through the service.
	anon := panelv1connect.NewGeoIPServiceClient(p.plain, p.ts.URL+"/api")
	if _, err := anon.SetGeoIPEnabled(context.Background(), connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: false})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("SetGeoIPEnabled without a session: %v", err)
	}
}

// The base URL of the configuration is where the panel looks for its database.
func TestGeoIPBaseURLOfTheConfiguration(t *testing.T) {
	src, hits := dbip(t, countryDB(t, "FR"))
	p := newPanel(t, func(c *Config) { c.GeoIPBaseURL = src.URL + "/free" })
	p.enableGeoIP()
	b := p.signIn()
	geo := panelv1connect.NewGeoIPServiceClient(b.http, p.ts.URL+"/api")

	before := time.Now().UTC().Format("2006-01")
	resp, err := geo.RefreshGeoIP(context.Background(), connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
	if err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}
	after := time.Now().UTC().Format("2006-01")
	if !resp.Msg.GetStatus().GetPresent() || resp.Msg.GetStatus().GetError() != "" || (resp.Msg.GetStatus().GetMonth() != before && resp.Msg.GetStatus().GetMonth() != after) {
		t.Errorf("status = %+v", resp.Msg.GetStatus())
	}
	if hits.Load() != 1 {
		t.Errorf("the source was asked %d times, want once", hits.Load())
	}
	if got := p.srv.geo.Country(germany); got != "FR" {
		t.Errorf("Country = %q, want FR", got)
	}
}

// A panel that is served loads the database that it has before it takes a
// request, looks for a newer one in the background, and stops that before it
// closes the database that it writes to.
func TestServeLoadsAndRefreshesTheCountryDatabase(t *testing.T) {
	src, hits := dbip(t, countryDB(t, "FR"))
	p := newPanel(t, func(c *Config) { c.GeoIPBaseURL = src.URL + "/free" })

	// What a panel has installed, which the next start of it finds.
	installed := countryDB(t, "DE")
	if _, err := p.srv.geo.Install(context.Background(), bytes.NewReader(installed)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.start(func(c *Config) { c.GeoIPBaseURL = src.URL + "/free" })
	p.enableGeoIP()
	if got := p.srv.geo.Country(germany); got != "" {
		t.Fatalf("Country before the panel is served = %q: the database is loaded by Serve", got)
	}

	r := serve(t, p.srv)
	r.ready()
	// Loaded by the time that it answers; the database of this month that it has
	// is the one that it keeps, so it asks DB-IP for nothing.
	if got := p.srv.geo.Country(germany); got != "DE" {
		t.Errorf("Country after Serve began = %q, want DE from the installed database", got)
	}
	eventually(t, "the loop of the refresh", func() bool { return goroutineIn("internal/panel/geodb.(*Manager).loop") })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if goroutineIn("internal/panel/geodb.(*Manager).loop") {
		t.Error("the refresh of the country database was still running when Serve returned")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("DB-IP was asked %d times, want none: the month was installed", n)
	}
}

// A panel with nothing looks for the database as soon as it serves.
func TestServeLooksForTheCountryDatabaseAtOnce(t *testing.T) {
	src, hits := dbip(t, countryDB(t, "FR"))
	p := newPanel(t, func(c *Config) { c.GeoIPBaseURL = src.URL + "/free" })
	p.enableGeoIP()
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the database to be downloaded", func() bool { return p.srv.geo.Country(germany) == "FR" })
	if n := hits.Load(); n != 1 {
		t.Errorf("DB-IP was asked %d times, want once", n)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(filepath.Join(p.dataDir, "geoip"))
	if len(files) != 1 {
		t.Errorf("the directory of the databases holds %d files, want 1", len(files))
	}
}

// A panel of the tests that is served makes no request and notes no failure to
// get its database: its lookups are off until a test turns them on.
func TestServedTestPanelNotesNoFailureOfTheCountryDatabase(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the loop of the refresh", func() bool { return goroutineIn("internal/panel/geodb.(*Manager).loop") })
	events, err := p.srv.db.ListEvents(context.Background(), 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if strings.HasPrefix(ev.Kind, "geoip.") {
			t.Errorf("the panel noted %s: %s", ev.Kind, ev.Message)
		}
	}
	if strings.Contains(p.logs.String(), "could not get the country database") {
		t.Errorf("the log has a failure to get the country database:\n%s", p.logs.String())
	}
}
