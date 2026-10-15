package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// pageFixture is a node with a listener and three proxies.
func pageFixture(t *testing.T, db *DB) (nodeID string, proxies []*Proxy) {
	t.Helper()
	n := mustNode(t, db, "n1")
	l := &Listener{NodeID: n.ID, BindIP: "0.0.0.0", Port: 443}
	if err := db.CreateListener(context.Background(), l); err != nil {
		t.Fatalf("CreateListener: %v", err)
	}
	for _, name := range []string{"a", "b", "c"} {
		proxies = append(proxies, mustProxy(t, db, n.ID, l.ID, name))
	}
	return n.ID, proxies
}

// A fresh database has the page of the migration: off, no host, the defaults.
func TestPublicPageDefaults(t *testing.T) {
	db := newTestDB(t)
	got, err := db.PublicPage(context.Background())
	if err != nil {
		t.Fatalf("PublicPage: %v", err)
	}
	want := &PublicPage{Unavailable: PublicUnavailableMark, NoIndex: true, DefaultLocale: "ru"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PublicPage() = %+v, want %+v", got, want)
	}
}

func TestUpdatePublicPageRoundTrip(t *testing.T) {
	db := newTestDB(t)
	_, ps := pageFixture(t, db)
	ctx := context.Background()

	p := &PublicPage{
		Enabled: true, Host: "proxies.example.test", Title: "Proxies", BodyMD: "# Hello",
		Unavailable: PublicUnavailableHide, NoIndex: false, DefaultLocale: "en",
		Items: []PublicPageItem{
			{ProxyID: ps[2].ID, PublicName: "third", PublicNote: "note 3"},
			{ProxyID: ps[0].ID, PublicName: "first"},
		},
	}
	if err := db.UpdatePublicPage(ctx, p); err != nil {
		t.Fatalf("UpdatePublicPage: %v", err)
	}
	if p.UpdatedAt.IsZero() {
		t.Error("UpdatePublicPage did not set UpdatedAt")
	}
	got, err := db.PublicPage(ctx)
	if err != nil {
		t.Fatalf("PublicPage: %v", err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("PublicPage() = %+v\nwant %+v", got, p)
	}

	// A second update replaces the items as a whole, in a new order: the unique
	// index on position refuses a row-by-row reorder, so this is the test of
	// delete-then-insert in one transaction.
	p2 := *p
	p2.Items = []PublicPageItem{
		{ProxyID: ps[0].ID, PublicName: "first"},
		{ProxyID: ps[2].ID, PublicName: "third"},
		{ProxyID: ps[1].ID, PublicName: "second"},
	}
	if err := db.UpdatePublicPage(ctx, &p2); err != nil {
		t.Fatalf("UpdatePublicPage (reorder): %v", err)
	}
	got, err = db.PublicPage(ctx)
	if err != nil {
		t.Fatalf("PublicPage: %v", err)
	}
	if !reflect.DeepEqual(got.Items, p2.Items) {
		t.Errorf("items = %+v, want %+v", got.Items, p2.Items)
	}

	// No items at all.
	p3 := *p
	p3.Items = nil
	if err := db.UpdatePublicPage(ctx, &p3); err != nil {
		t.Fatalf("UpdatePublicPage (no items): %v", err)
	}
	if got, _ := db.PublicPage(ctx); len(got.Items) != 0 {
		t.Errorf("items = %+v, want none", got.Items)
	}
}

// A write that fails leaves the page and its items as they were.
func TestUpdatePublicPageIsAtomic(t *testing.T) {
	db := newTestDB(t)
	_, ps := pageFixture(t, db)
	ctx := context.Background()
	before := &PublicPage{Enabled: true, Host: "a.example.test", Unavailable: PublicUnavailableMark, DefaultLocale: "ru",
		Items: []PublicPageItem{{ProxyID: ps[0].ID, PublicName: "a"}}}
	if err := db.UpdatePublicPage(ctx, before); err != nil {
		t.Fatalf("UpdatePublicPage: %v", err)
	}

	for _, c := range []struct {
		name  string
		items []PublicPageItem
		want  error
	}{
		{"a proxy that does not exist", []PublicPageItem{{ProxyID: ps[1].ID}, {ProxyID: "01K6Y00000000000000000000Z"}}, ErrNotFound},
		{"a proxy twice", []PublicPageItem{{ProxyID: ps[1].ID}, {ProxyID: ps[1].ID}}, ErrConflict},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := *before
			bad.Host = "b.example.test"
			bad.Items = c.items
			err := db.UpdatePublicPage(ctx, &bad)
			if !errors.Is(err, c.want) {
				t.Fatalf("UpdatePublicPage = %v, want %v", err, c.want)
			}
			got, err := db.PublicPage(ctx)
			if err != nil {
				t.Fatalf("PublicPage: %v", err)
			}
			if !reflect.DeepEqual(got, before) {
				t.Errorf("after the failed write the page is %+v, want %+v", got, before)
			}
		})
	}

	if err := db.UpdatePublicPage(ctx, &PublicPage{Unavailable: "sometimes", DefaultLocale: "ru"}); err == nil {
		t.Error("an unavailable value that is neither hide nor mark was stored")
	}
}

// Deleting a proxy takes it off the page.
func TestPublicPageItemGoesWithItsProxy(t *testing.T) {
	db := newTestDB(t)
	_, ps := pageFixture(t, db)
	ctx := context.Background()
	p := &PublicPage{Unavailable: PublicUnavailableMark, DefaultLocale: "ru",
		Items: []PublicPageItem{{ProxyID: ps[0].ID}, {ProxyID: ps[1].ID}}}
	if err := db.UpdatePublicPage(ctx, p); err != nil {
		t.Fatalf("UpdatePublicPage: %v", err)
	}
	if err := db.DeleteProxy(ctx, ps[0].ID); err != nil {
		t.Fatalf("DeleteProxy: %v", err)
	}
	got, err := db.PublicPage(ctx)
	if err != nil {
		t.Fatalf("PublicPage: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].ProxyID != ps[1].ID {
		t.Errorf("items = %+v, want the second proxy alone", got.Items)
	}
}

func TestAdminHosts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	hosts, err := db.AdminHosts(ctx)
	if err != nil || len(hosts) != 0 {
		t.Fatalf("AdminHosts of a fresh database = %v, %v", hosts, err)
	}

	// Names are kept newest first, and a name seen again moves up with its time.
	for i, h := range []string{"a.example.test", "b.example.test", "a.example.test"} {
		if err := db.RecordAdminHost(ctx, h, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("RecordAdminHost(%s): %v", h, err)
		}
	}
	hosts, err = db.AdminHosts(ctx)
	if err != nil {
		t.Fatalf("AdminHosts: %v", err)
	}
	want := []AdminHost{
		{Host: "a.example.test", LastSeenUnix: t0.Add(2 * time.Minute).Unix()},
		{Host: "b.example.test", LastSeenUnix: t0.Add(time.Minute).Unix()},
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("AdminHosts = %+v, want %+v", hosts, want)
	}
	if raw := settingJSON(t, db, "admin_hosts"); raw == "" || raw[0] != '[' {
		t.Errorf("admin_hosts is stored as %q, want a JSON list", raw)
	}

	// At most 32 names: the oldest go.
	for i := range 40 {
		h := "h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.test"
		if err := db.RecordAdminHost(ctx, h, t0.Add(time.Hour+time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("RecordAdminHost: %v", err)
		}
	}
	hosts, err = db.AdminHosts(ctx)
	if err != nil {
		t.Fatalf("AdminHosts: %v", err)
	}
	if len(hosts) != MaxAdminHosts {
		t.Fatalf("%d admin hosts kept, want %d", len(hosts), MaxAdminHosts)
	}
	for _, h := range hosts {
		if h.Host == "a.example.test" || h.Host == "b.example.test" {
			t.Errorf("%s, the oldest, is still kept", h.Host)
		}
	}
	for i := 1; i < len(hosts); i++ {
		if hosts[i-1].LastSeenUnix < hosts[i].LastSeenUnix {
			t.Errorf("admin hosts are not newest first: %+v", hosts)
			break
		}
	}
}
