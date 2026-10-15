package publicpage

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The page in both languages, against the goldens. The marked item has no
// link or parameter; the item without a link host is left out and logged;
// nothing of the panel but the link hosts shows; there is no QR code.
func TestPageGoldens(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()

	for _, lang := range []string{localeRU, localeEN} {
		t.Run(lang, func(t *testing.T) {
			page := e.page(lang)
			golden(t, "page_"+lang+".html", page)
			if !strings.Contains(page, `<html lang="`+lang+`">`) {
				t.Errorf("the page is not in %s", lang)
			}
			// The two available items have links and parameters; the marked one
			// has its name, its note and the label, and nothing else.
			if n := strings.Count(page, "tg://"); n != 2 {
				t.Errorf("%d tg:// links, want 2", n)
			}
			if n := strings.Count(page, "t.me/"); n != 2 {
				t.Errorf("%d t.me links, want 2", n)
			}
			if n := strings.Count(page, "<svg"); n != 0 {
				t.Errorf("%d QR codes, want none", n)
			}
			marked := rowOf(page, "Paused one")
			if marked == "" || !strings.Contains(marked, "Paused one") || !strings.Contains(marked, "Back soon") {
				t.Fatalf("no marked item with its name and note:\n%s", page)
			}
			for _, bad := range []string{"tg://", "t.me", "secret", "<svg", "<input", "value=", secretPaused, "paused.example.com", "443"} {
				if strings.Contains(strings.ToLower(marked), strings.ToLower(bad)) {
					t.Errorf("the marked item shows %q:\n%s", bad, marked)
				}
			}
			if !strings.Contains(marked, labelsOf(lang).Unavailable) {
				t.Errorf("the marked item does not say %q", labelsOf(lang).Unavailable)
			}
			// Nothing else of the panel.
			for _, bad := range []string{
				f.node.Name, f.node.ID, f.ghostNode.Name, f.ghostNode.ID, f.listener.ID, f.listener.NodeID,
				f.tls.ID, f.web.ID, f.paused.ID, f.ghost.ID, "admin-name", "admin note", "Ghost", secretPaused, secretGhost,
				"ghost.example.com", "198.51.100.1", "online", "offline",
			} {
				if strings.Contains(page, bad) {
					t.Errorf("the page shows %q", bad)
				}
			}
		})
	}
	// The item without a link host was logged, once.
	logs := e.logs.String()
	if n := strings.Count(logs, "left out because its links cannot be built"); n != 1 || !strings.Contains(logs, f.ghost.ID) {
		t.Errorf("the proxy without a link host was logged %d times (want once, with its id)", n)
	}
	e.assertNoSecretsLogged()
}

// The links on the page are the admin's links, byte for byte, and the
// parameters are the ones in them.
func TestLinksAreTheAdminsBytes(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	page := e.page(localeEN)

	// The rows link to tg://, the manual section to t.me.
	var got []string
	for _, re := range []string{`<li><a href="([^"]*)"`, `<a class="tme" href="([^"]*)"`} {
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(page, -1) {
			got = append(got, html.UnescapeString(m[1]))
		}
	}
	if len(got) != 4 {
		t.Fatalf("%d links, want 4", len(got))
	}
	got = []string{got[0], got[2], got[1], got[3]}
	tls, err := proxies.LinksOf(e.ctx, e.db, e.key, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	web, err := proxies.LinksOf(e.ctx, e.db, e.key, f.web)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{tls.TG, tls.HTTPS, web.TG, web.HTTPS}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %q, want %q", i, got[i], want[i])
		}
	}
	wantTG := links.FakeTLS{Host: "proxy.example.com", Port: 443, SecretHex: secretTLS, Domain: "www.example.com"}.TG()
	if got[0] != wantTG {
		t.Errorf("the tg link is %q, want %q", got[0], wantTG)
	}
	for _, param := range []string{
		`>proxy.example.com</code>`, `>443</code>`, `>` + links.FakeTLSSecret(secretTLS, "www.example.com") + `</code>`,
		`>web.example.com/telegram/web</code>`, `>` + web.Secret + `</code>`,
	} {
		if !strings.Contains(page, param) {
			t.Errorf("the page lacks the parameter %s", param)
		}
	}
}

// With unavailable = hide an unavailable item is left out altogether.
func TestHideLeavesTheItemOut(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	f.page.Unavailable = store.PublicUnavailableHide
	e.setPage(f.page)
	page := e.page("")
	for _, bad := range []string{"Paused one", "Back soon", "unavailable", labelsOf(localeRU).Unavailable} {
		if strings.Contains(page, bad) {
			t.Errorf("the hidden item shows %q", bad)
		}
	}
	if !strings.Contains(page, "Alpha") || !strings.Contains(page, "Web proxy") {
		t.Error("the available items are gone too")
	}
}

// A pause, an offline node, a probe that fails and an item that is removed
// show on the next request: nothing of the items is cached.
func TestAvailabilityIsPerRequest(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	alphaLinked := func() bool {
		t.Helper()
		page := e.page("")
		return strings.Contains(rowOf(page, "Alpha"), "tg://")
	}
	if !alphaLinked() {
		t.Fatal("Alpha is not linked to begin with")
	}

	e.setEnabled(f.tls.ID, false)
	if alphaLinked() {
		t.Error("a paused proxy is still linked")
	}
	e.setEnabled(f.tls.ID, true)
	if !alphaLinked() {
		t.Error("a resumed proxy is not linked")
	}

	e.setNodeStatus(f.node.ID, store.NodeStatusOffline)
	if alphaLinked() {
		t.Error("a proxy of an offline node is still linked")
	}
	e.setNodeStatus(f.node.ID, store.NodeStatusOnline)
	if !alphaLinked() {
		t.Error("a proxy of a node that is back is not linked")
	}

	e.setDown(f.tls.ID, true)
	if alphaLinked() {
		t.Error("a proxy whose probes fail is still linked")
	}
	e.setDown(f.tls.ID, false)
	if !alphaLinked() {
		t.Error("a proxy whose probes pass again is not linked")
	}

	// A paused proxy is marked, not hidden, and the page still says so.
	e.setEnabled(f.tls.ID, false)
	if page := e.page(""); !strings.Contains(page, "Alpha") {
		t.Error("a paused proxy is gone from the page, want it marked")
	}
	e.setEnabled(f.tls.ID, true)

	// A removed item is gone at once.
	f.page.Items = f.page.Items[1:]
	e.setPage(f.page)
	if page := e.page(""); strings.Contains(page, "Alpha") || strings.Contains(page, secretTLS) {
		t.Error("a removed item is still on the page")
	}

	// A deleted proxy is gone at once, too.
	if err := e.db.DeleteProxy(e.ctx, f.web.ID); err != nil {
		t.Fatal(err)
	}
	if page := e.page(""); strings.Contains(page, "Web proxy") {
		t.Error("a deleted proxy is still on the page")
	}
	e.assertNoSecretsLogged()
}

// ?lang= first, then Accept-Language, then the default locale of the page.
func TestLanguageOfTheRequest(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	langOf := func(path string, header map[string]string) string {
		t.Helper()
		resp, body := e.get(http.MethodGet, path, publicHost, header)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		m := regexp.MustCompile(`<html lang="(\w+)">`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no lang on the page")
		}
		return m[1]
	}
	if got := langOf("/", nil); got != "ru" {
		t.Errorf("the default is %q, want ru", got)
	}
	if got := langOf("/", map[string]string{"Accept-Language": "en-US,en;q=0.9,ru;q=0.5"}); got != "en" {
		t.Errorf("Accept-Language en: %q", got)
	}
	if got := langOf("/", map[string]string{"Accept-Language": "de, fr;q=0.9"}); got != "ru" {
		t.Errorf("Accept-Language with nothing the page has: %q, want the default", got)
	}
	if got := langOf("/?lang=en", map[string]string{"Accept-Language": "ru"}); got != "en" {
		t.Errorf("?lang=en with Accept-Language ru: %q", got)
	}
	if got := langOf("/?lang=xx", map[string]string{"Accept-Language": "en"}); got != "en" {
		t.Errorf("?lang=xx falls back to Accept-Language: %q", got)
	}
	f.page.DefaultLocale = localeEN
	e.setPage(f.page)
	if got := langOf("/", nil); got != "en" {
		t.Errorf("the default locale en: %q", got)
	}
	if got := langOf("/?lang=ru", nil); got != "ru" {
		t.Errorf("?lang=ru: %q", got)
	}
}

// An empty page says so and serves no item; a title is escaped.
func TestEmptyPageAndEscaping(t *testing.T) {
	e := newEnv(t)
	e.setPage(panelv1PageWith(`<b>Title</b> & "quotes"`))
	page := e.page(localeEN)
	if !strings.Contains(page, labelsOf(localeEN).Empty) {
		t.Error("an empty page does not say so")
	}
	if !strings.Contains(page, `<title>&lt;b&gt;Title&lt;/b&gt; &amp; &#34;quotes&#34;</title>`) {
		t.Errorf("the title is not escaped:\n%s", page)
	}
	if strings.Contains(page, "<b>Title") {
		t.Error("the title is raw HTML")
	}
}
