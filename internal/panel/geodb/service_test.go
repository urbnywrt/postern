package geodb

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// code is the Connect code of an error.
func code(err error) connect.Code { return connect.CodeOf(err) }

// actions are the audit entries of the service: "action target admin details".
func (p *panel) actions(prefix string) []string {
	var out []string
	for _, line := range p.audit() {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func TestServiceNeedsAnAdmin(t *testing.T) {
	p := newPanel(t)
	// Over the wire, through the middleware.
	if _, err := p.anon.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("GetGeoIP without a session: %v, want unauthenticated", err)
	}
	if _, err := p.anon.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("RefreshGeoIP without a session: %v, want unauthenticated", err)
	}
	if _, err := p.anon.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: false})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("SetGeoIPEnabled without a session: %v, want unauthenticated", err)
	}
	// And the service asks for itself, wherever it is mounted.
	svc := NewService(p.m, nil)
	if _, err := svc.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("GetGeoIP with no admin in the context: %v", err)
	}
	if _, err := svc.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("RefreshGeoIP with no admin in the context: %v", err)
	}
	if _, err := svc.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("SetGeoIPEnabled with no admin in the context: %v", err)
	}
	// None of it did anything.
	if got := p.src.asked(); len(got) != 0 {
		t.Errorf("a stranger made the panel ask DB-IP for %q", got)
	}
	if got := p.actions("geoip."); len(got) != 0 {
		t.Errorf("audit: %q", got)
	}
	if st, _ := p.m.Status(p.ctx); !st.Enabled {
		t.Error("a stranger turned the database off")
	}
}

func TestGetGeoIP(t *testing.T) {
	p := newPanel(t)

	// A panel that has nothing: on, and nothing else. The words of the
	// attribution are always there.
	resp, err := p.geoip.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil {
		t.Fatalf("GetGeoIP: %v", err)
	}
	empty := &panelv1.GeoIPStatus{
		Enabled: true, Attribution: "IP Geolocation by DB-IP", AttributionUrl: "https://db-ip.com", Licence: "CC BY 4.0",
	}
	if !protoEqual(resp.Msg.GetStatus(), empty) {
		t.Errorf("status = %+v, want %+v", resp.Msg.GetStatus(), empty)
	}

	// After a refresh: everything that is known.
	built := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	db := monthDB(t, "2026-10", "DE", geoiptest.WithBuilt(built))
	p.src.publish("2026-10", gzipped(t, db))
	if _, err := p.m.Refresh(p.ctx); err != nil {
		t.Fatal(err)
	}
	resp, err = p.geoip.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil {
		t.Fatalf("GetGeoIP: %v", err)
	}
	want := &panelv1.GeoIPStatus{
		Enabled: true, Present: true, Month: "2026-10", BuiltUnix: built.Unix(), Size: int64(len(db)), Sha256: sumOf(db),
		FetchedUnix: t0.Unix(), CheckedUnix: t0.Unix(),
		Attribution: geoip.Attribution, AttributionUrl: geoip.AttributionURL, Licence: geoip.Licence,
	}
	if !protoEqual(resp.Msg.GetStatus(), want) {
		t.Errorf("status = %+v, want %+v", resp.Msg.GetStatus(), want)
	}

	// With an error.
	p.clock.Set(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	p.src.answer("2026-11", http.StatusBadGateway)
	_, _ = p.m.Refresh(p.ctx)
	resp, err = p.geoip.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Msg.GetStatus().GetError(), "502") || !resp.Msg.GetStatus().GetPresent() || resp.Msg.GetStatus().GetMonth() != "2026-10" {
		t.Errorf("status = %+v, want the database of October and the error of the 502", resp.Msg.GetStatus())
	}
	if resp.Msg.GetStatus().GetCheckedUnix() != time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("checked_unix = %d", resp.Msg.GetStatus().GetCheckedUnix())
	}
}

func TestRefreshGeoIP(t *testing.T) {
	p := newPanel(t)
	db := monthDB(t, "2026-10", "DE")
	p.src.publish("2026-10", gzipped(t, db))

	resp, err := p.geoip.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
	if err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}
	if !resp.Msg.GetStatus().GetPresent() || resp.Msg.GetStatus().GetMonth() != "2026-10" || resp.Msg.GetStatus().GetSha256() != sumOf(db) || resp.Msg.GetStatus().GetError() != "" ||
		resp.Msg.GetStatus().GetAttribution() != geoip.Attribution {
		t.Errorf("status = %+v", resp.Msg.GetStatus())
	}
	if got := p.m.Country(addrV4); got != "DE" {
		t.Errorf("Country = %q, want DE", got)
	}
	entries := p.actions("geoip.refresh ")
	if len(entries) != 1 || !strings.Contains(entries[0], " "+p.adminID+" ") || !strings.HasPrefix(entries[0], "geoip.refresh geoip ") {
		t.Errorf("audit = %q, want geoip.refresh of the target geoip by the admin %s", entries, p.adminID)
	}

	// A refresh that finds nothing new is the same answer, and is audited, too.
	if _, err := p.geoip.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{})); err != nil {
		t.Fatal(err)
	}
	if got := p.actions("geoip.refresh "); len(got) != 2 {
		t.Errorf("audit = %q, want two refreshes", got)
	}
	if n := len(p.src.asked()); n != 1 {
		t.Errorf("%d requests to DB-IP, want 1", n)
	}
}

// A refresh that cannot get a database is not an error of the call: the answer
// is the status with the error in it.
func TestRefreshGeoIPThatFails(t *testing.T) {
	p := newPanel(t) // nothing is published
	resp, err := p.geoip.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
	if err != nil {
		t.Fatalf("RefreshGeoIP: %v, want the status with the error in it", err)
	}
	if resp.Msg.GetStatus().GetPresent() || !strings.Contains(resp.Msg.GetStatus().GetError(), "no country database for 2026-10 or 2026-09") ||
		!resp.Msg.GetStatus().GetEnabled() || resp.Msg.GetStatus().GetCheckedUnix() != t0.Unix() {
		t.Errorf("status = %+v", resp.Msg.GetStatus())
	}
	if got := p.actions("geoip.refresh "); len(got) != 1 {
		t.Errorf("audit = %q, want the refresh that was asked for", got)
	}
}

func TestRefreshGeoIPWhileDisabledDoesNothing(t *testing.T) {
	p := newPanel(t)
	p.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	if _, err := p.geoip.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: false})); err != nil {
		t.Fatal(err)
	}
	resp, err := p.geoip.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
	if err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}
	if resp.Msg.GetStatus().GetEnabled() || resp.Msg.GetStatus().GetPresent() || resp.Msg.GetStatus().GetError() != "" {
		t.Errorf("status = %+v, want disabled and nothing else", resp.Msg.GetStatus())
	}
	if got := p.src.asked(); len(got) != 0 {
		t.Errorf("a disabled panel asked DB-IP for %q", got)
	}
}

func TestSetGeoIPEnabled(t *testing.T) {
	p := newPanel(t)
	changes := 0
	p.m.OnChange(func() { changes++ })
	if _, err := p.m.Install(p.ctx, bytes.NewReader(monthDB(t, "2026-10", "DE"))); err != nil {
		t.Fatal(err)
	}
	changes = 0 // the install

	resp, err := p.geoip.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: false}))
	if err != nil {
		t.Fatalf("SetGeoIPEnabled(false): %v", err)
	}
	if resp.Msg.GetStatus().GetEnabled() || !resp.Msg.GetStatus().GetPresent() || resp.Msg.GetStatus().GetMonth() != "2026-10" {
		t.Errorf("status = %+v, want disabled, the database kept", resp.Msg.GetStatus())
	}
	if got := p.m.Country(addrV4); got != "" {
		t.Errorf("Country while disabled = %q", got)
	}
	if changes != 1 {
		t.Errorf("OnChange was called %d times, want 1", changes)
	}
	get, err := p.geoip.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
	if err != nil || get.Msg.GetStatus().GetEnabled() {
		t.Errorf("GetGeoIP after it = %+v, %v; want disabled", get.Msg.GetStatus(), err)
	}

	resp, err = p.geoip.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: true}))
	if err != nil || !resp.Msg.GetStatus().GetEnabled() {
		t.Fatalf("SetGeoIPEnabled(true) = %+v, %v", resp, err)
	}
	if got := p.m.Country(addrV4); got != "DE" {
		t.Errorf("Country after enabling = %q, want DE", got)
	}

	// Both are audited, with what they set.
	entries := p.actions("geoip.enabled ")
	if len(entries) != 2 || !strings.Contains(entries[0], `"enabled":"false"`) || !strings.Contains(entries[1], `"enabled":"true"`) {
		t.Errorf("audit = %q, want geoip.enabled for false and then for true", entries)
	}
	for _, e := range entries {
		if !strings.Contains(e, " "+p.adminID+" ") {
			t.Errorf("the audit entry %q does not name the admin %s", e, p.adminID)
		}
	}
}

// What the panel tells a caller of its own faults is nothing that it could use:
// the cause is in the log.
func TestServiceTellsNothingOfItsOwnFaults(t *testing.T) {
	p := newPanel(t)
	// The manager gets a handle of its own that is closed; the sessions are
	// read with the other, which works.
	broken, err := store.Open(p.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}
	p.m.db = broken
	for name, call := range map[string]func() error{
		"GetGeoIP": func() error {
			_, err := p.geoip.GetGeoIP(p.ctx, connect.NewRequest(&panelv1.GetGeoIPRequest{}))
			return err
		},
		"RefreshGeoIP": func() error {
			_, err := p.geoip.RefreshGeoIP(p.ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
			return err
		},
		"SetGeoIPEnabled": func() error {
			_, err := p.geoip.SetGeoIPEnabled(p.ctx, connect.NewRequest(&panelv1.SetGeoIPEnabledRequest{Enabled: true}))
			return err
		},
	} {
		err := call()
		var ce *connect.Error
		if code(err) != connect.CodeInternal || !errors.As(err, &ce) || ce.Message() != "internal error" {
			t.Errorf("%s with a database that fails: %v, want internal: internal error", name, err)
		}
	}
	if !strings.Contains(p.logs.String(), "level=ERROR") {
		t.Error("the faults were not logged")
	}
}

// A caller that has gone away is told so, which is no fault.
func TestServiceAnswersACanceledCallerAsCanceled(t *testing.T) {
	p := newPanel(t)
	p.src.handle(func(_ http.ResponseWriter, r *http.Request, _ string) bool {
		<-r.Context().Done()
		return true
	})
	ctx, cancel := context.WithTimeout(p.ctx, 100*time.Millisecond)
	defer cancel()
	_, err := p.geoip.RefreshGeoIP(ctx, connect.NewRequest(&panelv1.RefreshGeoIPRequest{}))
	if got := code(err); got != connect.CodeDeadlineExceeded && got != connect.CodeCanceled {
		t.Errorf("RefreshGeoIP of a caller that gave up: %v", err)
	}
	// The panel does not note a failure of DB-IP in it.
	idle(t, p.m)
	if st, err := p.m.Status(p.ctx); err != nil || st.Error != "" || !st.Checked.IsZero() {
		t.Errorf("Status = %+v, %v; want nothing noted", st, err)
	}
	if n := len(p.events("geoip.failed")); n != 0 {
		t.Errorf("%d geoip.failed events for a caller that went away", n)
	}
}

func TestStatusProto(t *testing.T) {
	got := statusProto(Status{})
	want := &panelv1.GeoIPStatus{Attribution: geoip.Attribution, AttributionUrl: geoip.AttributionURL, Licence: geoip.Licence}
	if !protoEqual(got, want) {
		t.Errorf("statusProto(Status{}) = %+v, want %+v", got, want)
	}
	when := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	got = statusProto(Status{Enabled: true, Present: true, Month: "2026-10", Built: when, Size: 7, SHA256: "ab", Fetched: when.Add(time.Hour), Checked: when.Add(2 * time.Hour), Error: "e"})
	want = &panelv1.GeoIPStatus{
		Enabled: true, Present: true, Month: "2026-10", BuiltUnix: when.Unix(), Size: 7, Sha256: "ab",
		FetchedUnix: when.Add(time.Hour).Unix(), CheckedUnix: when.Add(2 * time.Hour).Unix(), Error: "e",
		Attribution: geoip.Attribution, AttributionUrl: geoip.AttributionURL, Licence: geoip.Licence,
	}
	if !protoEqual(got, want) {
		t.Errorf("statusProto = %+v, want %+v", got, want)
	}
}

// The package is the one that the plan says: it imports the store, geoip and
// auth of the panel, and not the packages of proxies and nodes.
func TestImports(t *testing.T) {
	for _, forbidden := range []string{"internal/panel/proxies", "internal/panel/nodes"} {
		if slices.ContainsFunc(importsOfPackage(t), func(path string) bool { return strings.HasSuffix(path, forbidden) }) {
			t.Errorf("the package imports %s", forbidden)
		}
	}
}
