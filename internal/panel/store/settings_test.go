package store

import (
	"context"
	"encoding/base64"
	"reflect"
	"testing"
)

type testSetting struct {
	Cert string            `json:"cert"`
	Key  []byte            `json:"key"`
	Opts map[string]string `json:"opts"`
	N    int               `json:"n"`
}

func TestSettingRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	want := testSetting{Cert: "pem", Key: []byte{0, 1, 2, 255}, Opts: map[string]string{"a": "b"}, N: 7}
	if err := db.PutSetting(ctx, "pki.panel_client", want); err != nil {
		t.Fatalf("PutSetting: %v", err)
	}
	var got testSetting
	ok, err := db.GetSetting(ctx, "pki.panel_client", &got)
	if err != nil || !ok {
		t.Fatalf("GetSetting = %v, %v; want true, nil", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("setting = %+v, want %+v", got, want)
	}
}

func TestSettingScalarsAndLists(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := db.PutSetting(ctx, "s", "text"); err != nil {
		t.Fatal(err)
	}
	var s string
	if ok, err := db.GetSetting(ctx, "s", &s); err != nil || !ok || s != "text" {
		t.Errorf("string setting = %q, %v, %v", s, ok, err)
	}

	if err := db.PutSetting(ctx, "n", 42); err != nil {
		t.Fatal(err)
	}
	var n int
	if ok, err := db.GetSetting(ctx, "n", &n); err != nil || !ok || n != 42 {
		t.Errorf("int setting = %d, %v, %v", n, ok, err)
	}

	if err := db.PutSetting(ctx, "l", []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	var l []string
	if ok, err := db.GetSetting(ctx, "l", &l); err != nil || !ok || !reflect.DeepEqual(l, []string{"x", "y"}) {
		t.Errorf("list setting = %v, %v, %v", l, ok, err)
	}

	// Into an any, a JSON object arrives as a map.
	if err := db.PutSetting(ctx, "m", map[string]any{"k": true}); err != nil {
		t.Fatal(err)
	}
	var m any
	if ok, err := db.GetSetting(ctx, "m", &m); err != nil || !ok || !reflect.DeepEqual(m, map[string]any{"k": true}) {
		t.Errorf("map setting = %v, %v, %v", m, ok, err)
	}
}

func TestSettingMissing(t *testing.T) {
	db := newTestDB(t)
	got := "untouched"
	ok, err := db.GetSetting(context.Background(), "nope", &got)
	if err != nil || ok {
		t.Errorf("GetSetting = %v, %v; want false, nil", ok, err)
	}
	if got != "untouched" {
		t.Errorf("dst = %q, want it left alone", got)
	}
}

func TestSettingOverwrite(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, v := range []string{"first", "second"} {
		if err := db.PutSetting(ctx, "k", v); err != nil {
			t.Fatal(err)
		}
	}
	var got string
	if _, err := db.GetSetting(ctx, "k", &got); err != nil || got != "second" {
		t.Errorf("setting = %q, %v; want second", got, err)
	}
	if n := count(t, db, `SELECT count(*) FROM settings`); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

func TestSettingErrors(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := db.PutSetting(ctx, "bad", make(chan int)); err == nil {
		t.Error("PutSetting of a value that is not JSON succeeded")
	}
	if n := count(t, db, `SELECT count(*) FROM settings`); n != 0 {
		t.Errorf("a failed PutSetting left %d rows", n)
	}

	if err := db.PutSetting(ctx, "str", "text"); err != nil {
		t.Fatal(err)
	}
	var n int
	if ok, err := db.GetSetting(ctx, "str", &n); err == nil || ok {
		t.Errorf("GetSetting into the wrong type = %v, %v; want false and an error", ok, err)
	}
	if ok, err := db.GetSetting(ctx, "str", nil); err == nil || ok {
		t.Errorf("GetSetting into nil = %v, %v; want false and an error", ok, err)
	}
}

// The release source has a default, which a read does not write, and is stored
// as the JSON that the plan documents.
func TestReleaseSourceSetting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	got, err := db.ReleaseSource(ctx)
	if err != nil {
		t.Fatalf("ReleaseSource: %v", err)
	}
	want := ReleaseSource{Kind: "github", BaseURL: "", Repo: "urbnywrt/postern"}
	if got != want || DefaultReleaseSource() != want {
		t.Errorf("ReleaseSource of a new database = %+v (default %+v), want %+v", got, DefaultReleaseSource(), want)
	}
	if n := count(t, db, `SELECT count(*) FROM settings`); n != 0 {
		t.Errorf("a read wrote %d settings", n)
	}

	s := ReleaseSource{Kind: "gitea", BaseURL: "https://git.example.com", Repo: "me/postern"}
	if err := db.PutReleaseSource(ctx, s); err != nil {
		t.Fatalf("PutReleaseSource: %v", err)
	}
	if got, err := db.ReleaseSource(ctx); err != nil || got != s {
		t.Errorf("ReleaseSource = %+v, %v; want %+v", got, err, s)
	}
	var raw map[string]any
	if ok, err := db.GetSetting(ctx, SettingReleaseSource, &raw); err != nil || !ok {
		t.Fatalf("GetSetting(%s) = %v, %v", SettingReleaseSource, ok, err)
	}
	if want := map[string]any{"kind": "gitea", "base_url": "https://git.example.com", "repo": "me/postern"}; !reflect.DeepEqual(raw, want) {
		t.Errorf("stored as %v, want %v", raw, want)
	}
}

// A sealed setting keeps bytes that the store cannot read, as {"sealed":
// "<base64>"}; empty bytes remove it.
func TestSealedSetting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if v, ok, err := db.SealedSetting(ctx, SettingGitHubToken); err != nil || ok || v != nil {
		t.Fatalf("SealedSetting of a new database = %v, %v, %v; want nil, false, nil", v, ok, err)
	}
	sealed := []byte{0, 1, 2, 254, 255}
	if err := db.PutSealedSetting(ctx, SettingGitHubToken, sealed); err != nil {
		t.Fatalf("PutSealedSetting: %v", err)
	}
	if v, ok, err := db.SealedSetting(ctx, SettingGitHubToken); err != nil || !ok || !reflect.DeepEqual(v, sealed) {
		t.Errorf("SealedSetting = %v, %v, %v; want the bytes", v, ok, err)
	}
	var raw map[string]string
	if ok, err := db.GetSetting(ctx, SettingGitHubToken, &raw); err != nil || !ok {
		t.Fatalf("GetSetting = %v, %v", ok, err)
	}
	if want := map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)}; !reflect.DeepEqual(raw, want) {
		t.Errorf("stored as %v, want %v", raw, want)
	}

	// Another key is another value; a put replaces; empty removes.
	if err := db.PutSealedSetting(ctx, SettingSourceToken, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSealedSetting(ctx, SettingGitHubToken, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := db.SealedSetting(ctx, SettingGitHubToken); !ok || string(v) != "new" {
		t.Errorf("after a second put: %q, %v; want new", v, ok)
	}
	if err := db.PutSealedSetting(ctx, SettingGitHubToken, nil); err != nil {
		t.Fatalf("PutSealedSetting(nil): %v", err)
	}
	if v, ok, err := db.SealedSetting(ctx, SettingGitHubToken); err != nil || ok || v != nil {
		t.Errorf("after the removal: %v, %v, %v; want nil, false, nil", v, ok, err)
	}
	if n := count(t, db, `SELECT count(*) FROM settings WHERE key = ?`, SettingGitHubToken); n != 0 {
		t.Errorf("%d rows left for the removed key", n)
	}
	if v, ok, _ := db.SealedSetting(ctx, SettingSourceToken); !ok || string(v) != "other" {
		t.Errorf("the other key = %q, %v; want it untouched", v, ok)
	}

	// A setting that is not of that shape is an error, not an empty value.
	if err := db.PutSetting(ctx, "plain", "text"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.SealedSetting(ctx, "plain"); err == nil || ok {
		t.Errorf("SealedSetting of a plain setting = %v, %v; want an error", ok, err)
	}
}
