package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func hashOf(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestJoinTokens(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	n := mustNode(t, db, "edge-1")
	other := mustNode(t, db, "edge-2")
	now := time.Now()

	if _, err := db.JoinTokenByHash(ctx, hashOf("a")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("JoinTokenByHash before any = %v, want ErrNotFound", err)
	}
	if err := db.PutJoinToken(ctx, &JoinToken{NodeID: "nope", TokenHash: hashOf("x"), ExpiresAt: now}); !errors.Is(err, ErrNotFound) {
		t.Errorf("PutJoinToken for a missing node = %v, want ErrNotFound", err)
	}

	tok := &JoinToken{NodeID: n.ID, TokenHash: hashOf("a"), ExpiresAt: now.Add(time.Hour)}
	if err := db.PutJoinToken(ctx, tok); err != nil {
		t.Fatalf("PutJoinToken: %v", err)
	}
	got, err := db.JoinTokenByHash(ctx, hashOf("a"))
	if err != nil {
		t.Fatalf("JoinTokenByHash: %v", err)
	}
	if got.NodeID != n.ID || got.Used() || got.UsedKey != nil || !got.ExpiresAt.Equal(tok.ExpiresAt) || got.CreatedAt.IsZero() {
		t.Errorf("token = %+v", got)
	}
	if err := db.PutJoinToken(ctx, &JoinToken{NodeID: other.ID, TokenHash: hashOf("a"), ExpiresAt: now}); !errors.Is(err, ErrConflict) {
		t.Errorf("a hash another node has = %v, want ErrConflict", err)
	}

	// Mark used: only with the right hash, once, before expiry.
	key := hashOf("key")
	if err := db.MarkJoinTokenUsed(ctx, n.ID, hashOf("b"), key, now); !errors.Is(err, ErrConflict) {
		t.Errorf("mark with another hash = %v, want ErrConflict", err)
	}
	if err := db.MarkJoinTokenUsed(ctx, n.ID, hashOf("a"), key, now.Add(2*time.Hour)); !errors.Is(err, ErrConflict) {
		t.Errorf("mark after expiry = %v, want ErrConflict", err)
	}
	if err := db.MarkJoinTokenUsed(ctx, n.ID, hashOf("a"), key, now); err != nil {
		t.Fatalf("MarkJoinTokenUsed: %v", err)
	}
	if err := db.MarkJoinTokenUsed(ctx, n.ID, hashOf("a"), key, now); !errors.Is(err, ErrConflict) {
		t.Errorf("mark twice = %v, want ErrConflict", err)
	}
	got, _ = db.JoinTokenOf(ctx, n.ID)
	if !got.Used() || !bytes.Equal(got.UsedKey, key) || !got.SameKey(key) || got.SameKey(hashOf("other")) {
		t.Errorf("used token = %+v", got)
	}

	// A new token replaces the old one, used or not.
	if err := db.PutJoinToken(ctx, &JoinToken{NodeID: n.ID, TokenHash: hashOf("c"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("PutJoinToken again: %v", err)
	}
	if _, err := db.JoinTokenByHash(ctx, hashOf("a")); !errors.Is(err, ErrNotFound) {
		t.Errorf("the replaced token is still there: %v", err)
	}
	if got, _ := db.JoinTokenOf(ctx, n.ID); got.Used() || len(got.UsedKey) != 0 {
		t.Errorf("the new token = %+v, want unused", got)
	}
	if c := count(t, db, `SELECT count(*) FROM node_join_tokens`); c != 1 {
		t.Errorf("%d rows, want 1", c)
	}

	// Deleting the node deletes its token.
	if err := db.DeleteNode(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if c := count(t, db, `SELECT count(*) FROM node_join_tokens`); c != 0 {
		t.Errorf("%d rows after the node was deleted, want 0", c)
	}
}

func TestApplyJoin(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	tests := []struct {
		name, mgmt, link, joinHost string
		wantMgmt, wantLink         string
	}{
		{"fills an empty address", "", "", "198.51.100.7", "198.51.100.7", "198.51.100.7"},
		{"keeps a link host", "", "edge.example.com", "198.51.100.7", "198.51.100.7", "edge.example.com"},
		{"keeps an address", "192.0.2.1", "192.0.2.1", "198.51.100.7", "192.0.2.1", "192.0.2.1"},
		{"no address to fill", "", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newTestDB(t)
			n := &Node{Name: "edge", MgmtHost: tt.mgmt, LinkHost: tt.link, CertPEM: "old", CertFingerprint: "old", KeyEnc: []byte{1, 2}}
			if err := db.CreateNode(ctx, n); err != nil {
				t.Fatal(err)
			}
			if err := db.PutJoinToken(ctx, &JoinToken{NodeID: n.ID, TokenHash: hashOf("t"), ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			j := NodeJoin{NodeID: n.ID, TokenHash: hashOf("t"), UsedKey: hashOf("k"), At: now,
				CertPEM: "new", CertFingerprint: "fp", MgmtHost: tt.joinHost}
			out, err := db.ApplyJoin(ctx, j)
			if err != nil {
				t.Fatalf("ApplyJoin: %v", err)
			}
			got, _ := db.NodeByID(ctx, n.ID)
			for _, g := range []*Node{out, got} {
				if g.CertPEM != "new" || g.CertFingerprint != "fp" || g.KeyEnc != nil || g.MgmtHost != tt.wantMgmt || g.LinkHost != tt.wantLink {
					t.Errorf("node = cert %q fp %q key %v mgmt %q link %q", g.CertPEM, g.CertFingerprint, g.KeyEnc, g.MgmtHost, g.LinkHost)
				}
			}
			if tok, _ := db.JoinTokenOf(ctx, n.ID); !tok.SameKey(hashOf("k")) {
				t.Errorf("token = %+v, want used by the key", tok)
			}
			// The token is consumed: a second join changes nothing.
			j.CertPEM = "newer"
			if _, err := db.ApplyJoin(ctx, j); !errors.Is(err, ErrConflict) {
				t.Errorf("second ApplyJoin = %v, want ErrConflict", err)
			}
			if got, _ := db.NodeByID(ctx, n.ID); got.CertPEM != "new" {
				t.Errorf("cert = %q after a refused join", got.CertPEM)
			}
		})
	}
}
