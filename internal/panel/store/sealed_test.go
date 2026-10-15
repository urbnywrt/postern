package store

import (
	"context"
	"testing"
)

// HasSealedData is what stops the panel from making a new master key when it
// has lost the old one: every kind of value that the key seals has to count.
func TestHasSealedData(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		make func(t *testing.T, db *DB)
		want bool
	}{
		{"an empty database", func(*testing.T, *DB) {}, false},
		{"an admin without TOTP", func(t *testing.T, db *DB) { mustAdmin(t, db, "alice") }, false},
		{"an admin with TOTP", func(t *testing.T, db *DB) {
			a := &Admin{Username: "alice", PasswordHash: "hash", TOTPSecretEnc: []byte("sealed-totp")}
			if err := db.CreateAdmin(ctx, a); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"an admin whose TOTP was turned off again", func(t *testing.T, db *DB) {
			a := &Admin{Username: "alice", PasswordHash: "hash", TOTPSecretEnc: []byte("sealed-totp")}
			if err := db.CreateAdmin(ctx, a); err != nil {
				t.Fatal(err)
			}
			a.TOTPSecretEnc = nil
			if err := db.UpdateAdmin(ctx, a); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"the CA", func(t *testing.T, db *DB) {
			if err := db.PutSetting(ctx, "pki.ca", map[string]string{"cert_pem": "pem"}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"the client certificate of the panel", func(t *testing.T, db *DB) {
			if err := db.PutSetting(ctx, "pki.panel_client", map[string]string{"cert_pem": "pem"}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"settings that hold nothing sealed", func(t *testing.T, db *DB) {
			for _, key := range []string{"auth.totp_step.01ADMIN", "pki", "pki.ca.old", "other.pki.ca"} {
				if err := db.PutSetting(ctx, key, 1); err != nil {
					t.Fatal(err)
				}
			}
		}, false},
		{"a node without a key", func(t *testing.T, db *DB) { mustNode(t, db, "n1") }, false},
		{"a node with a key", func(t *testing.T, db *DB) {
			n := &Node{Name: "n1", KeyEnc: []byte("sealed-key")}
			if err := db.CreateNode(ctx, n); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a proxy", func(t *testing.T, db *DB) {
			n := mustNode(t, db, "n1")
			l := mustListener(t, db, n.ID, 443)
			mustProxy(t, db, n.ID, l.ID, "p1")
		}, true},
		{"an egress without parameters", func(t *testing.T, db *DB) {
			mustExec(t, db, `INSERT INTO egresses (id, name, kind, created_at, updated_at) VALUES ('e1', 'direct', 'direct', 1, 1)`)
		}, false},
		{"an egress with parameters", func(t *testing.T, db *DB) {
			mustExec(t, db, `INSERT INTO egresses (id, name, kind, params_enc, created_at, updated_at) VALUES ('e1', 'socks', 'socks5', x'01', 1, 1)`)
		}, true},
		{"a dns credential", func(t *testing.T, db *DB) {
			if err := db.CreateDNSCredential(ctx, &DNSCredential{Name: "cf", TokenEnc: []byte("sealed-token")}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"an SSH target without credentials", func(t *testing.T, db *DB) {
			n := mustNode(t, db, "n1")
			if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root",
				HostKey: "SHA256:made-up"}); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"an SSH target with remembered credentials", func(t *testing.T, db *DB) {
			n := mustNode(t, db, "n1")
			if err := db.PutSSHTarget(ctx, &SSHTarget{NodeID: n.ID, Host: "192.0.2.10", Port: 22, User: "root",
				AuthKind: SSHAuthPassword, SecretEnc: []byte("sealed-password")}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a node that is not the first thing there", func(t *testing.T, db *DB) {
			mustAdmin(t, db, "alice")
			mustNode(t, db, "n1")
			n := &Node{Name: "n2", KeyEnc: []byte("sealed-key")}
			if err := db.CreateNode(ctx, n); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a sealed token for the GitHub API", func(t *testing.T, db *DB) {
			if err := db.PutSealedSetting(ctx, SettingGitHubToken, []byte("sealed-token")); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a sealed token of the release source", func(t *testing.T, db *DB) {
			if err := db.PutSealedSetting(ctx, SettingSourceToken, []byte("sealed-token")); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a sealed token that was removed again", func(t *testing.T, db *DB) {
			if err := db.PutSealedSetting(ctx, SettingGitHubToken, []byte("sealed-token")); err != nil {
				t.Fatal(err)
			}
			if err := db.PutSealedSetting(ctx, SettingGitHubToken, nil); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"the release source, which holds nothing sealed", func(t *testing.T, db *DB) {
			if err := db.PutReleaseSource(ctx, ReleaseSource{Kind: "gitea", BaseURL: "https://git.example.com", Repo: "me/postern"}); err != nil {
				t.Fatal(err)
			}
			if err := db.PutSetting(ctx, SettingDefaultChannel, ChannelLatest); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := newTestDB(t)
			c.make(t, db)
			got, err := db.HasSealedData(ctx)
			if err != nil {
				t.Fatalf("HasSealedData: %v", err)
			}
			if got != c.want {
				t.Errorf("HasSealedData = %v, want %v", got, c.want)
			}
		})
	}
}

func TestHasSealedDataOfAClosedDatabase(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := db.HasSealedData(context.Background()); err == nil {
		t.Errorf("HasSealedData on a closed database = %v, nil; want an error, not an answer that lets a key be made", got)
	}
}
