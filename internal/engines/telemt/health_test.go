package telemt

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/urbnywrt/postern/internal/engines"
)

// The answer shape of telemt 3.5.13's GET /v1/stats/dcs (src/api/model.rs),
// with the fields this package does not read.
const dcsBody = `{"ok":true,"data":{"middle_proxy_enabled":true,"generated_at_epoch_secs":1791342946,"dcs":[
 {"dc":2,"endpoints":["149.154.167.51:8888"],"endpoint_writers":[],"available_endpoints":1,"available_pct":100.0,
  "required_writers":2,"floor_min":1,"floor_target":2,"floor_max":4,"floor_capped":false,"alive_writers":1,
  "coverage_pct":50.0,"fresh_alive_writers":1,"fresh_coverage_pct":50.0,"rtt_ms":null,"load":0},
 {"dc":4,"available_endpoints":-1,"available_pct":140.0,"coverage_pct":-3}]},"revision":"x"}`

func TestParseDCs(t *testing.T) {
	h, err := ParseDCs([]byte(dcsBody))
	if err != nil {
		t.Fatal(err)
	}
	// DC 4 is an older answer without fresh_coverage_pct: it reads, and says so.
	want := []engines.DCHealth{
		{DC: 2, AvailableEndpoints: 1, AvailablePct: 100, CoveragePct: 50, FreshCoveragePct: 50, HasFreshCoverage: true},
		{DC: 4, AvailableEndpoints: 0, AvailablePct: 100, CoveragePct: 0},
	}
	if !h.MiddleProxy || len(h.DCs) != 2 || h.DCs[0] != want[0] || h.DCs[1] != want[1] {
		t.Errorf("ParseDCs = %+v", h)
	}
	h, err = ParseDCs([]byte(`{"ok":true,"data":{"middle_proxy_enabled":true,"dcs":[{"dc":1,"coverage_pct":100,"fresh_coverage_pct":250}]}}`))
	if err != nil || len(h.DCs) != 1 || !h.DCs[0].HasFreshCoverage || h.DCs[0].FreshCoveragePct != 100 {
		t.Errorf("fresh coverage clamped = %+v, %v", h, err)
	}
	h, err = ParseDCs([]byte(`{"ok":true,"data":{"middle_proxy_enabled":false,"reason":"source_unavailable","generated_at_epoch_secs":1,"dcs":[]}}`))
	if err != nil || h.MiddleProxy || h.Reason != "source_unavailable" {
		t.Errorf("ME off = %+v, %v", h, err)
	}
	for _, bad := range []string{`not json`, `{"ok":false}`, `{"ok":true}`} {
		if _, err := ParseDCs([]byte(bad)); err == nil {
			t.Errorf("ParseDCs(%q) took it", bad)
		}
	}
}

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case readyPath:
			_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true}}`))
		case dcsPath:
			_, _ = w.Write([]byte(dcsBody))
		}
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	h, err := New().Health(context.Background(), engines.Instance{APIPort: uint16(p), APIToken: "tok"})
	if err != nil || !h.Ready || !h.MiddleProxy || len(h.DCs) != 2 {
		t.Errorf("Health = %+v, %v", h, err)
	}
	h, err = New().Health(context.Background(), engines.Instance{APIPort: uint16(p), APIToken: "wrong"})
	if err == nil || h.Ready || h.Reason == "" {
		t.Errorf("wrong token: %+v, %v", h, err)
	}
}
