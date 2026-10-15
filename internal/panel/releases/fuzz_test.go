package releases

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// FuzzFetchReleases feeds bodies of both API shapes to the parsers: nothing
// panics, and what comes out has a valid tag and only well-formed digests.
func FuzzFetchReleases(f *testing.F) {
	f.Add([]byte(list(ghRelease("v1.0.0", false, false, "a.tar.gz"), ghRelease("v1.0.1-rc1", true, false))))
	f.Add([]byte(`[{"tag_name":"v1.2.0","assets":[{"name":"x","size":1,"created_at":"2026-10-02T00:00:00Z","browser_download_url":"https://example.com/x"},{"name":"x","created_at":"bad","browser_download_url":"https://example.com/y"}]}]`))
	f.Add([]byte(`[{"tag_name":"../x"},{"tag_name":"v1","draft":true}]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[`))
	f.Add([]byte(``))
	f.Add([]byte(`[{"tag_name":"v2.0.0","body":"\xff\xfe","assets":[{"name":"a","browser_download_url":"u","digest":"sha256:ZZ"}]}]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, parse := range []func([]byte) ([]FeedRelease, bool, error){parseGitHub, parseGitea} {
			rels, _, err := parse(body)
			if err != nil {
				continue
			}
			for _, r := range rels {
				if r.Tag == "" || len(r.Notes) > maxNotes {
					t.Fatalf("release %+v", r)
				}
				for _, a := range r.Assets {
					if a.Digest != "" && !hex64.MatchString(a.Digest) {
						t.Fatalf("digest %q", a.Digest)
					}
					if a.Name == "" || a.URL == "" {
						t.Fatalf("asset %+v", a)
					}
				}
			}
		}
	})
}

// FuzzExtract feeds archives of both kinds to the extractor: nothing panics,
// and nothing but the output file is ever written.
func FuzzExtract(f *testing.F) {
	bin := staticELF(f, "amd64", "x")
	f.Add(tarGz(f, member{name: "telemt", data: bin}), true)
	f.Add(tarGz(f, member{name: "../telemt", data: bin}, member{name: "telemt", data: bin}), true)
	f.Add(zipBytes(f, member{name: "telemt", data: bin}, member{name: "sub/telemt", data: bin}), false)
	f.Add(zipBytes(f, member{name: "/telemt", data: bin}), false)
	f.Add([]byte("not an archive"), true)
	f.Add([]byte("not an archive"), false)
	f.Add([]byte{0x1f, 0x8b, 8, 0}, true)
	f.Add([]byte("PK\x03\x04"), false)
	f.Fuzz(func(t *testing.T, data []byte, tar bool) {
		dir := t.TempDir()
		name := "a.zip"
		if tar {
			name = "a.tar.gz"
		}
		src := filepath.Join(dir, name)
		if err := os.WriteFile(src, data, 0o644); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "out")
		err := extractMember(context.Background(), src, name, "telemt", dst)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != name && e.Name() != "out" {
				t.Fatalf("wrote %q", e.Name())
			}
		}
		if _, serr := os.Stat(dst); (serr == nil) != (err == nil) {
			t.Fatalf("output exists=%v, err=%v", serr == nil, err)
		}
	})
}
