package store

import (
	"context"
	"errors"
	"testing"
)

func TestDNSCredentialRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c := &DNSCredential{Name: "cloudflare main", TokenEnc: []byte("sealed-token")}
	if err := db.CreateDNSCredential(ctx, c); err != nil {
		t.Fatalf("CreateDNSCredential: %v", err)
	}
	if c.ID == "" || c.Provider != DNSProviderCloudflare || c.CreatedAt.IsZero() || !c.UpdatedAt.Equal(c.CreatedAt) {
		t.Errorf("defaults not applied: %+v", c)
	}
	got, err := db.DNSCredentialByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("DNSCredentialByID: %v", err)
	}
	if got.Name != c.Name || string(got.TokenEnc) != "sealed-token" || got.UsedBy != 0 || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Errorf("read back %+v, want %+v", got, c)
	}

	// Used by a proxy: counted, and not deletable.
	n := mustNode(t, db, "n1")
	l := mustListener(t, db, n.ID, 443)
	p := mustProxy(t, db, n.ID, l.ID, "p1")
	p.DNSCredentialID = c.ID
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListDNSCredentials(ctx)
	if err != nil {
		t.Fatalf("ListDNSCredentials: %v", err)
	}
	if len(list) != 1 || list[0].UsedBy != 1 {
		t.Errorf("list = %+v, want one credential used by one proxy", list)
	}
	nodes, err := db.NodesUsingDNSCredential(ctx, c.ID)
	if err != nil || len(nodes) != 1 || nodes[0] != n.ID {
		t.Errorf("NodesUsingDNSCredential = %v, %v; want [%s]", nodes, err, n.ID)
	}
	if err := db.DeleteDNSCredential(ctx, c.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("DeleteDNSCredential of a used credential = %v, want ErrConflict", err)
	}

	// A new token and name.
	c.Name, c.TokenEnc = "renamed", []byte("sealed-token-2")
	if err := db.UpdateDNSCredential(ctx, c); err != nil {
		t.Fatalf("UpdateDNSCredential: %v", err)
	}
	got, err = db.DNSCredentialByID(ctx, c.ID)
	if err != nil || got.Name != "renamed" || string(got.TokenEnc) != "sealed-token-2" || got.UpdatedAt.Before(got.CreatedAt) {
		t.Errorf("after update: %+v, %v", got, err)
	}

	// Free again: deletable, once.
	p.DNSCredentialID = ""
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteDNSCredential(ctx, c.ID); err != nil {
		t.Fatalf("DeleteDNSCredential: %v", err)
	}
	if err := db.DeleteDNSCredential(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteDNSCredential = %v, want ErrNotFound", err)
	}
	if _, err := db.DNSCredentialByID(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("DNSCredentialByID after delete = %v, want ErrNotFound", err)
	}
	if err := db.UpdateDNSCredential(ctx, c); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateDNSCredential after delete = %v, want ErrNotFound", err)
	}
}
