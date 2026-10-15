package site

import (
	"bytes"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func pages(files map[string][]byte) []string {
	var out []string
	for name := range files {
		if strings.HasSuffix(name, ".html") && name != NotFoundFile {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, b := Generate("01J9ZZ0000000000000000TEST"), Generate("01J9ZZ0000000000000000TEST")
	if !maps.EqualFunc(a, b, bytes.Equal) {
		t.Error("two generations of one seed differ")
	}
	if c := Generate("01J9ZZ0000000000000000OTHER"); maps.EqualFunc(a, c, bytes.Equal) {
		t.Error("two seeds gave the same site")
	}
}

var (
	hrefRE  = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*"([^"]*)"`)
	titleRE = regexp.MustCompile(`<title>([^<]*)</title>`)
	// handlerRE matches an event handler attribute, such as onclick=.
	handlerRE = regexp.MustCompile(`\son[a-z]+\s*=`)
)

// Every site has 3 to 5 pages besides its own 404, one external style sheet
// that every page uses, no inline script or style, and nothing that is
// fetched from anywhere but the site itself.
func TestGenerateShape(t *testing.T) {
	for i := range 40 {
		seed := fmt.Sprintf("seed-%02d", i)
		files := Generate(seed)
		ps := pages(files)
		if n := len(ps); n < 3 || n > 5 {
			t.Errorf("%s: %d pages %v, want 3 to 5", seed, n, ps)
		}
		if !slices.Contains(ps, IndexFile) {
			t.Errorf("%s: no %s", seed, IndexFile)
		}
		if _, ok := files[NotFoundFile]; !ok {
			t.Errorf("%s: no %s", seed, NotFoundFile)
		}
		css, ok := files[StyleFile]
		if !ok || len(css) < 200 || bytes.Contains(css, []byte("url(")) || bytes.Contains(css, []byte("@import")) {
			t.Errorf("%s: %s missing, tiny or fetching something: %d bytes", seed, StyleFile, len(css))
		}
		for name, data := range files {
			if !strings.HasSuffix(name, ".html") {
				continue
			}
			doc := string(data)
			lower := strings.ToLower(doc)
			switch {
			case !strings.HasPrefix(doc, "<!doctype html>"):
				t.Errorf("%s/%s: no doctype", seed, name)
			case strings.Contains(lower, "<script"), strings.Contains(lower, "<style"), strings.Contains(lower, " style="), handlerRE.MatchString(lower):
				t.Errorf("%s/%s: inline script, style or handler", seed, name)
			case !strings.Contains(doc, `<link rel="stylesheet" href="`+StyleFile+`">`):
				t.Errorf("%s/%s: does not use %s", seed, name, StyleFile)
			case !titleRE.MatchString(doc):
				t.Errorf("%s/%s: no title", seed, name)
			}
			for _, m := range hrefRE.FindAllStringSubmatch(doc, -1) {
				ref := m[2]
				if strings.Contains(ref, ":") || strings.HasPrefix(ref, "//") {
					t.Errorf("%s/%s: external reference %q", seed, name, ref)
					continue
				}
				target, _, _ := strings.Cut(ref, "#")
				if target != "" && target != "/" {
					if _, ok := files[strings.TrimPrefix(target, "/")]; !ok {
						t.Errorf("%s/%s: link to %q, which is not a file of the site", seed, name, ref)
					}
				}
			}
		}
	}
}

// Sites of different seeds look different: titles, page sets, style sheets and
// front pages vary.
func TestGenerateDiversity(t *testing.T) {
	titles, sets, styles, fronts := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	const n = 40
	for i := range n {
		files := Generate(fmt.Sprintf("proxy-%03d", i))
		titles[titleRE.FindStringSubmatch(string(files[IndexFile]))[1]] = true
		sets[strings.Join(pages(files), ",")] = true
		styles[string(files[StyleFile])] = true
		fronts[string(files[IndexFile])] = true
	}
	if len(titles) < n*3/4 {
		t.Errorf("%d distinct titles of %d sites", len(titles), n)
	}
	if len(sets) < 6 {
		t.Errorf("%d distinct page sets of %d sites, want at least 6", len(sets), n)
	}
	if len(styles) < n*3/4 {
		t.Errorf("%d distinct style sheets of %d sites", len(styles), n)
	}
	if len(fronts) != n {
		t.Errorf("%d distinct front pages of %d sites", len(fronts), n)
	}
}

func TestGenerateEscapesNothingOdd(t *testing.T) {
	// Seeds are proxy ids, but any string must give a well-formed site.
	for _, seed := range []string{"", "<script>", "a\x00b", strings.Repeat("x", 1000)} {
		files := Generate(seed)
		if strings.Contains(strings.ToLower(string(files[IndexFile])), "<script") {
			t.Errorf("seed %q leaks into the page", seed)
		}
	}
}

// Every placeholder of the material is substituted.
func TestGenerateLeavesNoPlaceholder(t *testing.T) {
	for i := range 60 {
		for name, data := range Generate(fmt.Sprintf("ph-%02d", i)) {
			if bytes.ContainsAny(data, "{}") && name != StyleFile {
				t.Errorf("seed ph-%02d: %s has a brace: a placeholder was not substituted", i, name)
			}
		}
	}
}
