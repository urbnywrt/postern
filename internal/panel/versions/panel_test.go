package versions

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestReleaseSourceSettings(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t, true)
	admin := panelv1connect.NewVersionServiceClient(a.web, a.srv.URL)
	anon := panelv1connect.NewVersionServiceClient(a.anon, a.srv.URL)

	if _, err := anon.GetReleaseSource(ctx, connect.NewRequest(&panelv1.GetReleaseSourceRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("without a session: %v", err)
	}
	got, err := admin.GetReleaseSource(ctx, connect.NewRequest(&panelv1.GetReleaseSourceRequest{}))
	if err != nil {
		t.Fatalf("GetReleaseSource: %v", err)
	}
	if s := got.Msg.GetSource(); s.GetKind() != "github" || s.GetRepo() != "urbnywrt/postern" || s.GetHasToken() || s.GetHasGithubToken() || s.GetIncludePrereleases() {
		t.Errorf("default: %v", s)
	}

	// A bad source is refused before anything is written.
	_, err = admin.SetReleaseSource(ctx, connect.NewRequest(&panelv1.SetReleaseSourceRequest{Source: &panelv1.ReleaseSource{Kind: "gitea", BaseUrl: "http://git.example.com", Repo: "o/r"}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a Gitea without https: %v", err)
	}

	token, gh := "src-token-91", "gh-token-17"
	set, err := admin.SetReleaseSource(ctx, connect.NewRequest(&panelv1.SetReleaseSourceRequest{
		Source: &panelv1.ReleaseSource{Kind: "gitea", BaseUrl: "https://git.example.com", Repo: "o/r", IncludePrereleases: true},
		Token:  &token, GithubToken: &gh}))
	if err != nil {
		t.Fatalf("SetReleaseSource: %v", err)
	}
	if s := set.Msg.GetSource(); s.GetKind() != "gitea" || s.GetBaseUrl() != "https://git.example.com" || !s.GetHasToken() || !s.GetHasGithubToken() || !s.GetIncludePrereleases() {
		t.Errorf("after set: %v", s)
	}
	// The tokens are nowhere in plain text: not in the settings, not in the
	// audit log.
	raw, err := sql.Open("sqlite", a.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	audited := false
	for _, q := range []string{`SELECT value FROM settings`, `SELECT details FROM audit_log WHERE action = 'versions.release_source.set'`} {
		rows, err := raw.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(v, token) || strings.Contains(v, gh) {
				t.Errorf("%s holds a token in plain text: %s", q, v)
			}
			audited = audited || strings.Contains(v, `"token":"set"`)
		}
		_ = rows.Close()
	}
	if !audited {
		t.Error("the change was not audited with the token marked as set")
	}
	// A request without the tokens leaves them; an empty one removes one.
	empty := ""
	set, err = admin.SetReleaseSource(ctx, connect.NewRequest(&panelv1.SetReleaseSourceRequest{
		Source: &panelv1.ReleaseSource{Kind: "github", Repo: "urbnywrt/postern"}, GithubToken: &empty}))
	if err != nil {
		t.Fatalf("SetReleaseSource: %v", err)
	}
	if s := set.Msg.GetSource(); !s.GetHasToken() || s.GetHasGithubToken() || s.GetIncludePrereleases() {
		t.Errorf("after the second set: %v", s)
	}
}

func TestPanelVersionAndUpdate(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t, true)
	admin := panelv1connect.NewVersionServiceClient(a.web, a.srv.URL)
	anon := panelv1connect.NewVersionServiceClient(a.anon, a.srv.URL)
	if _, err := anon.GetPanelVersion(ctx, connect.NewRequest(&panelv1.GetPanelVersionRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("without a session: %v", err)
	}

	for _, v := range []string{"v99.1.0", "v99.2.0"} {
		if err := a.db.UpsertRelease(ctx, &store.Release{Engine: selfupdate.ComponentPostern, Version: v, Source: store.SourceUpload, Assets: map[string]store.ReleaseAsset{}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.db.PutSetting(ctx, store.SettingPanelLastUpdate, "updated from a to b"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	restarted := 0
	u := &selfupdate.Updater{DataDir: dir, DB: a.db, Version: "v99.0.0", ImageBin: filepath.Join(dir, "image"),
		Exec: func(context.Context, string, ...string) ([]byte, error) { return []byte("v98.0.0 (c, d)\n"), nil }}
	a.svc.SetUpdater(u, func() { restarted++ }, func() bool { return true })

	got, err := admin.GetPanelVersion(ctx, connect.NewRequest(&panelv1.GetPanelVersionRequest{}))
	if err != nil {
		t.Fatalf("GetPanelVersion: %v", err)
	}
	m := got.Msg
	if m.GetVersion() == "" || m.GetCommit() == "" || m.GetDate() == "" || m.GetImageVersion() != "v98.0.0" || !m.GetKitSigned() ||
		m.GetLastUpdate() != "updated from a to b" || m.GetCanUpdate() || !strings.Contains(m.GetCannotUpdateReason(), "launcher") {
		t.Errorf("GetPanelVersion: %v", m)
	}
	if len(m.GetReleases()) != 2 || m.GetReleases()[0].GetVersion() != "v99.2.0" {
		t.Errorf("releases: %v", m.GetReleases())
	}

	_, err = admin.UpdatePanel(ctx, connect.NewRequest(&panelv1.UpdatePanelRequest{Version: "v99.2.0"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "launcher") {
		t.Errorf("UpdatePanel without the launcher: %v", err)
	}
	_, err = admin.UpdatePanel(ctx, connect.NewRequest(&panelv1.UpdatePanelRequest{Version: "../x"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("UpdatePanel with a bad version: %v", err)
	}
	if restarted != 0 {
		t.Error("a refused update restarted the panel")
	}
}

// A saved release source drops the list of Postern releases that the panel
// keeps for a while: the next GetPanelVersion reads the source again, so a
// prerelease that the setting now allows shows at once.
func TestSavingTheReleaseSourceRereadsIt(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t, true)
	admin := panelv1connect.NewVersionServiceClient(a.web, a.srv.URL)
	a.host.put("/api/repos/urbnywrt/postern/releases", []byte(`[`+
		`{"tag_name":"v99.2.0-rc.1","prerelease":true,"assets":[]},`+
		`{"tag_name":"v99.1.0","prerelease":false,"assets":[]}]`))
	dir := t.TempDir()
	u := &selfupdate.Updater{DataDir: dir, DB: a.db, Version: "v99.0.0", ImageBin: filepath.Join(dir, "image"), Releases: a.svc.releases,
		Exec: func(context.Context, string, ...string) ([]byte, error) { return []byte("v99.0.0 (c, d)\n"), nil }}
	a.svc.SetUpdater(u, func() {}, func() bool { return true })

	newest := func() string {
		t.Helper()
		got, err := admin.GetPanelVersion(ctx, connect.NewRequest(&panelv1.GetPanelVersionRequest{}))
		if err != nil {
			t.Fatalf("GetPanelVersion: %v", err)
		}
		if len(got.Msg.GetReleases()) == 0 {
			return ""
		}
		return got.Msg.GetReleases()[0].GetVersion()
	}
	if v := newest(); v != "v99.1.0" {
		t.Fatalf("with prereleases off, the newest is %q", v)
	}
	if _, err := admin.SetReleaseSource(ctx, connect.NewRequest(&panelv1.SetReleaseSourceRequest{
		Source: &panelv1.ReleaseSource{Kind: "github", Repo: "urbnywrt/postern", IncludePrereleases: true}})); err != nil {
		t.Fatalf("SetReleaseSource: %v", err)
	}
	if v := newest(); v != "v99.2.0-rc.1" {
		t.Errorf("after prereleases were allowed, the newest is %q", v)
	}
}
