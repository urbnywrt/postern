package selfupdate

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

func TestSourceDefaultsToGitHub(t *testing.T) {
	ctx := context.Background()
	host := newFakeHost(t)
	r := &Releases{DB: openDB(t), Key: testKey(t), HTTP: host.srv.Client(), APIBase: host.url("/gh"), Log: discard()}
	src, err := r.Source(ctx)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if src.Kind != "github" || src.Repo != "urbnywrt/postern" || src.APIBase != host.url("/gh") || src.Token != "" || src.Prereleases {
		t.Errorf("default source: %+v", src)
	}
	host.put("/gh/repos/urbnywrt/postern/releases", []byte(`[`+
		`{"tag_name":"v0.5.0","prerelease":false,"assets":[]},`+
		`{"tag_name":"v0.6.0-rc.1","prerelease":true,"assets":[]},`+
		`{"tag_name":"engines-stable","prerelease":false,"assets":[]},`+
		`{"tag_name":"v0.5.1","prerelease":false,"assets":[]}]`))
	rels, err := src.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := tags(rels); got != "v0.5.1 v0.5.0" {
		t.Errorf("List without prereleases: %s", got)
	}
	// No token: no Authorization header went out.
	if got := host.authOf("/gh/repos/urbnywrt/postern/releases"); len(got) == 0 || got[0] != "" {
		t.Errorf("Authorization without a token: %q", got)
	}
	src.Prereleases = true
	rels, err = src.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := tags(rels); got != "v0.6.0-rc.1 v0.5.1 v0.5.0" {
		t.Errorf("List with prereleases: %s", got)
	}
}

func tags(rels []releases.FeedRelease) string {
	var out []string
	for _, r := range rels {
		out = append(out, r.Tag)
	}
	return strings.Join(out, " ")
}

// The token is sealed in the settings (the database holds no plaintext), and
// a Gitea source sends it to its host only.
func TestSourceTokenSealedAndSentToItsHostOnly(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := testKey(t)
	gitea := newFakeHost(t)
	other := newFakeHost(t)
	token := "secret-token-7f3a"

	if err := SetSource(ctx, db, key, store.ReleaseSource{Kind: "gitea", BaseURL: gitea.srv.URL, Repo: "o/r"}, true, &token, nil); err != nil {
		t.Fatalf("SetSource: %v", err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rows, err := raw.Query(`SELECT value FROM settings`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(v, token) {
			t.Fatalf("the database holds the token in plain text: %s", v)
		}
	}
	// Written with the AAD of the setting: another key or AAD cannot open it.
	sealed, ok, err := db.SealedSetting(ctx, store.SettingSourceToken)
	if err != nil || !ok {
		t.Fatalf("SealedSetting: %v %v", ok, err)
	}
	if _, err := seal.Open(key, sealed, []byte("setting:other")); err == nil {
		t.Error("the token opens under another AAD")
	}

	r := &Releases{DB: db, Key: key, HTTP: gitea.srv.Client(), Log: discard()}
	src, err := r.Source(ctx)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if src.Kind != "gitea" || src.Token != token || !src.Prereleases || src.APIBase != gitea.srv.URL {
		t.Errorf("source: kind %s token set %v prereleases %v base %s", src.Kind, src.Token != "", src.Prereleases, src.APIBase)
	}
	gitea.put("/api/v1/repos/o/r/releases", []byte(`[{"tag_name":"v0.5.0","assets":[`+
		`{"name":"postern-node-linux-amd64","browser_download_url":"`+other.url("/x/postern-node-linux-amd64")+`"},`+
		`{"name":"postern-node-linux-amd64.minisig","browser_download_url":"`+gitea.url("/a/postern-node-linux-amd64.minisig")+`"}]}]`))
	other.put("/x/postern-node-linux-amd64", []byte("bytes"))
	gitea.put("/a/postern-node-linux-amd64.minisig", []byte("sig"))
	rels, err := src.List(ctx)
	if err != nil || len(rels) != 1 {
		t.Fatalf("List: %v %d", err, len(rels))
	}
	if got := gitea.authOf("/api/v1/repos/o/r/releases"); len(got) == 0 || got[0] != "token "+token {
		t.Errorf("the API call did not carry the token: %q", got)
	}
	for _, a := range rels[0].Assets {
		if _, err := src.download(ctx, a.URL, 1<<20); err != nil {
			t.Fatalf("download %s: %v", a.Name, err)
		}
	}
	if got := gitea.authOf("/a/postern-node-linux-amd64.minisig"); len(got) == 0 || got[0] != "token "+token {
		t.Errorf("the download from the Gitea host did not carry the token: %q", got)
	}
	if got := other.authOf("/x/postern-node-linux-amd64"); len(got) == 0 || got[0] != "" {
		t.Errorf("the token went to another host: %q", got)
	}

	// Removing the token: the setting is gone.
	empty := ""
	if err := SetSource(ctx, db, key, store.ReleaseSource{Kind: "gitea", BaseURL: gitea.srv.URL, Repo: "o/r"}, true, &empty, nil); err != nil {
		t.Fatalf("SetSource: %v", err)
	}
	if _, ok, _ := db.SealedSetting(ctx, store.SettingSourceToken); ok {
		t.Error("the token was not removed")
	}
	// A GitHub token is sealed under its own key.
	gh := "ghp_x"
	if err := SetSource(ctx, db, key, store.DefaultReleaseSource(), false, nil, &gh); err != nil {
		t.Fatalf("SetSource: %v", err)
	}
	if _, ok, _ := db.SealedSetting(ctx, store.SettingGitHubToken); !ok {
		t.Error("the GitHub token was not stored")
	}
}

func TestValidateSource(t *testing.T) {
	for _, tc := range []struct {
		src store.ReleaseSource
		ok  bool
	}{
		{store.ReleaseSource{Kind: "github", Repo: "urbnywrt/postern"}, true},
		{store.ReleaseSource{Kind: "gitea", BaseURL: "https://git.example.com", Repo: "o/r"}, true},
		{store.ReleaseSource{Kind: "gitea", BaseURL: "http://git.example.com", Repo: "o/r"}, false},
		{store.ReleaseSource{Kind: "gitea", BaseURL: "http://127.0.0.1:8080", Repo: "o/r"}, true},
		{store.ReleaseSource{Kind: "gitea", BaseURL: "https://u:p@git.example.com", Repo: "o/r"}, false},
		{store.ReleaseSource{Kind: "gitea", BaseURL: "https://git.example.com/?x=1", Repo: "o/r"}, false},
		{store.ReleaseSource{Kind: "gitea", Repo: "o/r"}, false},
		{store.ReleaseSource{Kind: "gitlab", Repo: "o/r"}, false},
		{store.ReleaseSource{Kind: "github", Repo: "postern"}, false},
		{store.ReleaseSource{Kind: "github", Repo: "a/b/c"}, false},
		{store.ReleaseSource{Kind: "github", Repo: "../x"}, false},
		{store.ReleaseSource{Kind: "github", Repo: "o/r?x"}, false},
		{store.ReleaseSource{Kind: "github", BaseURL: "https://x", Repo: "o/r"}, false},
	} {
		err := ValidateSource(tc.src)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateSource(%+v): %v, want ok=%v", tc.src, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrBadSource) {
			t.Errorf("ValidateSource(%+v): %v is not ErrBadSource", tc.src, err)
		}
	}
}
