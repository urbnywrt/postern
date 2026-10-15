package publicpage

import (
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// rowOf returns the row of the board that holds name, "" when there is none.
func rowOf(page, name string) string {
	rows := regexp.MustCompile(`(?s)<ol class="rows">.*?</ol>`).FindString(page)
	for line := range strings.SplitSeq(rows, "\n") {
		if strings.HasPrefix(line, "<li") && strings.Contains(line, ">"+name+"<") {
			return line
		}
	}
	return ""
}

// manualOf returns the section "enter manually" of the page.
func manualOf(page string) string {
	return regexp.MustCompile(`(?s)<details class="manual">.*?</details>`).FindString(page)
}

// The title has one line, all of it plain, or two, the second in the accent
// colour; the <title> joins them with a space.
func TestBoardTitleLines(t *testing.T) {
	e := newEnv(t)
	e.setPage(panelv1PageWith("Our proxies"))
	page := e.page(localeEN)
	if !strings.Contains(page, "<h1>Our proxies</h1>") || !strings.Contains(page, "<title>Our proxies</title>") {
		t.Errorf("one line:\n%s", page)
	}
	e.setPage(panelv1PageWith("Pick\nа direction"))
	page = e.page(localeEN)
	if !strings.Contains(page, "<h1>Pick<span>а direction</span></h1>") || !strings.Contains(page, "<title>Pick а direction</title>") {
		t.Errorf("two lines:\n%s", page)
	}
	if !strings.Contains(page, `<p class="eyebrow">MTProto · <b>Telegram</b></p>`) {
		t.Errorf("no eyebrow:\n%s", page)
	}
	// Escaped, both lines.
	e.setPage(panelv1PageWith("<i>one</i>\n<b>two</b> & \"q\""))
	page = e.page(localeEN)
	if !strings.Contains(page, "<h1>&lt;i&gt;one&lt;/i&gt;<span>&lt;b&gt;two&lt;/b&gt; &amp; &#34;q&#34;</span></h1>") {
		t.Errorf("the title is not escaped:\n%s", page)
	}
}

// Without a text and a footer of its own the page has the defaults of its
// locale; with them, its own, the footer escaped and its line breaks kept.
func TestBoardDefaultLedeAndFooter(t *testing.T) {
	e := newEnv(t)
	e.setPage(panelv1PageWith("t"))
	for lang, want := range map[string][2]string{
		localeRU: {"Нажми на строку. Telegram откроется и предложит подключить прокси. Через него пойдёт только Telegram, остальной трафик останется как был.",
			"Если прокси не открывается, попробуй соседний: блокировки работают по адресам, и обычно падает не всё сразу."},
		localeEN: {"Tap a row. Telegram opens and offers to add the proxy. Only Telegram goes through it; the rest of your traffic stays as it is.",
			"If a proxy does not open, try the next one: blocks go by address, and seldom hit all of them at once."},
	} {
		page := e.page(lang)
		if !strings.Contains(page, `<p class="lede">`+want[0]+`</p>`) {
			t.Errorf("%s: no default lede:\n%s", lang, page)
		}
		if !strings.Contains(page, "<footer>"+want[1]+"</footer>") {
			t.Errorf("%s: no default footer:\n%s", lang, page)
		}
	}
	p := panelv1PageWith("t")
	p.BodyMd = "Hello **there**"
	p.Footer = "line <one>\nline & two"
	e.setPage(p)
	page := e.page(localeRU)
	if !strings.Contains(page, `<div class="lede">`+"\n<p>Hello <strong>there</strong></p>\n</div>") {
		t.Errorf("the text is not the lede:\n%s", page)
	}
	if !strings.Contains(page, "<footer>line &lt;one&gt;<br>line &amp; two</footer>") {
		t.Errorf("the footer:\n%s", page)
	}
}

// A row has the code of the item, or else the country of the server: of the
// address of the link when it is an IP, else of the node's public IP; or
// nothing. Its name, note and address; the whole row links to tg://.
func TestBoardRows(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	e.setPublicIPs(f.node.ID, "203.0.113.10")
	e.setCountry("203.0.113.10", "NL")
	e.setCountry("192.0.2.7", "DE")

	page := e.page(localeEN)
	alpha := rowOf(page, "Alpha")
	if !strings.Contains(alpha, `<a href="tg://proxy?server=proxy.example.com&amp;port=443&amp;secret=`) ||
		!strings.Contains(alpha, `<span class="code">NL</span>`) ||
		!strings.Contains(alpha, `<span class="city">Alpha</span><span class="note">Fast and stable</span><span class="addr">proxy.example.com:443</span>`) ||
		!strings.Contains(alpha, `<span class="go" aria-hidden="true">→</span>`) {
		t.Errorf("the row of Alpha:\n%s", alpha)
	}
	web := rowOf(page, "Web proxy")
	if !strings.Contains(web, `<a href="tg://webproxy?`) || !strings.Contains(web, `<span class="code">NL</span>`) ||
		!strings.Contains(web, `<span class="addr">web.example.com/telegram/web</span>`) || strings.Contains(web, `class="note"`) {
		t.Errorf("the row of the WEB proxy:\n%s", web)
	}

	// A code of its own wins; an IP as the link host gives its country.
	f.page.Items[1].Code = "ws"
	e.setPage(f.page)
	if _, err := e.db.ModifyNode(e.ctx, f.node.ID, func(n *store.Node) error { n.LinkHost = "192.0.2.7"; return nil }); err != nil {
		t.Fatal(err)
	}
	page = e.page(localeEN)
	if row := rowOf(page, "Alpha"); !strings.Contains(row, `<span class="code">DE</span>`) || !strings.Contains(row, `<span class="addr">192.0.2.7:443</span>`) {
		t.Errorf("the row of Alpha on an IP:\n%s", row)
	}
	if row := rowOf(page, "Web proxy"); !strings.Contains(row, `<span class="code">WS</span>`) {
		t.Errorf("the row with a code:\n%s", row)
	}

	// No answer: no code, the column kept.
	e.setCountry("192.0.2.7", "")
	e.setCountry("203.0.113.10", "")
	if row := rowOf(e.page(localeEN), "Alpha"); !strings.Contains(row, `<span class="code"></span>`) {
		t.Errorf("the row without a country:\n%s", row)
	}
}

// A marked item is a muted row without a link or an address, which says that
// it is unavailable; it is not in the manual section.
func TestBoardUnavailableRow(t *testing.T) {
	e := newEnv(t)
	e.fixture()
	for lang, word := range map[string]string{localeRU: "недоступен", localeEN: "unavailable"} {
		page := e.page(lang)
		row := rowOf(page, "Paused one")
		if !strings.HasPrefix(row, `<li class="off">`) || strings.Contains(row, "<a") || strings.Contains(row, "tg://") ||
			!strings.Contains(row, `<span class="go">`+word+`</span>`) || !strings.Contains(row, `<span class="note">Back soon</span>`) ||
			strings.Contains(row, "addr") {
			t.Errorf("%s: the marked row:\n%s", lang, row)
		}
		if strings.Contains(manualOf(page), "Paused one") {
			t.Errorf("%s: the marked item is in the manual section", lang)
		}
	}
}

// "Enter manually" is closed, has the hint, and for every available item its
// code and name, its parameters with the copy action and its t.me link. There
// is no QR code on the page.
func TestBoardManual(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	f.page.Items[0].Code = "ru"
	e.setPage(f.page)
	for lang, want := range map[string][3]string{
		localeRU: {"Ввести вручную", "Настройки → Данные и память → Прокси → Добавить прокси → MTProto.", "Открыть через t.me"},
		localeEN: {"Enter manually", "Settings → Data and Storage → Proxy → Add Proxy → MTProto.", "Open via t.me"},
	} {
		page := e.page(lang)
		m := manualOf(page)
		if !strings.HasPrefix(m, `<details class="manual"><summary>`+want[0]+`</summary>`) || !strings.Contains(m, "<p>"+want[1]+"</p>") {
			t.Errorf("%s: the manual section:\n%s", lang, m)
		}
		if n := strings.Count(m, `<a class="tme" href="https://t.me/`); n != 2 || strings.Count(m, ">"+want[2]+"</a>") != 2 {
			t.Errorf("%s: %d t.me links in the manual section, want 2:\n%s", lang, n, m)
		}
		l := labelsOf(lang)
		copyAttrs := ` data-copy="` + l.Copy + `" data-copied="` + l.Copied + `"`
		for _, s := range []string{"<b>RU · Alpha</b>", "<b>Web proxy</b>",
			"<code" + copyAttrs + ">proxy.example.com</code>", "<code" + copyAttrs + ">443</code>",
			"<code" + copyAttrs + ">web.example.com/telegram/web</code>"} {
			if !strings.Contains(m, s) {
				t.Errorf("%s: the manual section lacks %s:\n%s", lang, s, m)
			}
		}
		if strings.Count(m, "<code") != 5 {
			t.Errorf("%s: %d copyable values, want 5 (server, port, secret; server, secret)", lang, strings.Count(m, "<code"))
		}
		if strings.Contains(m, "<details open") {
			t.Errorf("%s: the manual section is open", lang)
		}
		for _, bad := range []string{"<svg", "qr code", "qr-код", "<figure", "<input", "<img"} {
			if strings.Contains(strings.ToLower(page), bad) {
				t.Errorf("%s: the page has %q", lang, bad)
			}
		}
	}
}

// An empty page says so under the header, and has no rows and no manual
// section.
func TestBoardEmpty(t *testing.T) {
	e := newEnv(t)
	e.setPage(panelv1PageWith("t"))
	page := e.page(localeRU)
	if !regexp.MustCompile(`(?s)</h1>\n<p class="lede">.*</p>\n<p class="empty">` + labelsOf(localeRU).Empty + `</p>`).MatchString(page) {
		t.Errorf("the empty page:\n%s", page)
	}
	if strings.Contains(page, `class="rows"`) || strings.Contains(page, "<details") {
		t.Errorf("the empty page has rows or a manual section:\n%s", page)
	}
}

// Names and notes are escaped in the rows and in the manual section.
func TestBoardEscaping(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	f.page.Items[0].PublicName = `<script>x</script>`
	f.page.Items[0].PublicNote = `"a" & <b>`
	e.setPage(f.page)
	page := e.page(localeEN)
	if strings.Contains(page, "<script>x") || strings.Contains(page, "<b>\"") {
		t.Fatalf("raw HTML on the page:\n%s", page)
	}
	if strings.Count(page, "&lt;script&gt;x&lt;/script&gt;") != 2 || !strings.Contains(page, `<span class="note">&#34;a&#34; &amp; &lt;b&gt;</span>`) {
		t.Errorf("not escaped:\n%s", page)
	}
}

// The code, the footer and the title are checked; the code is stored in upper
// case. The answers carry the country that the page shows for an item without
// a code, and an update ignores it.
func TestBoardValidation(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	withItem := func(code string) *panelv1.PublicPage {
		return &panelv1.PublicPage{Items: []*panelv1.PublicPageItem{{ProxyId: f.tls.ID, PublicName: "a", Code: code}}}
	}
	for _, c := range []struct {
		name string
		page *panelv1.PublicPage
		msg  string
	}{
		{"a code of 5", withItem("ABCDE"), "item 1: code has more than 4"},
		{"a code with a hyphen", withItem("R-U"), "item 1: code must be letters and digits"},
		{"a code in Cyrillic", withItem("РУ"), "item 1: code must be letters and digits"},
		{"a code with a space inside", withItem("R U"), "item 1: code must be letters and digits"},
		{"a footer of 301 bytes", &panelv1.PublicPage{Footer: strings.Repeat("a", 301)}, "footer has more than 300 bytes"},
		{"a footer of 301 bytes in Cyrillic", &panelv1.PublicPage{Footer: strings.Repeat("я", 150) + "a"}, "footer has more than 300 bytes"},
		{"a footer with a control character", &panelv1.PublicPage{Footer: "a\x01"}, "footer must not contain control characters"},
		{"a title of three lines", &panelv1.PublicPage{Title: "a\nb\nc"}, "title has more than one line break"},
		{"a title with an empty line inside", &panelv1.PublicPage{Title: "a\n\nb"}, "title has more than one line break"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.admin.UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: c.page}))
			if ce := wantCode(t, err, connect.CodeInvalidArgument); !strings.Contains(ce.Message(), c.msg) {
				t.Errorf("message %q, want it to say %q", ce.Message(), c.msg)
			}
		})
	}

	e.setPublicIPs(f.node.ID, "203.0.113.10")
	e.setCountry("203.0.113.10", "NL")
	got := e.setPage(&panelv1.PublicPage{
		Title: " Pick \n a direction ", Footer: strings.Repeat("я", 150) + "\n",
		Items: []*panelv1.PublicPageItem{
			{ProxyId: f.tls.ID, PublicName: "a", Code: " r2d ", Country: "XX"},
			{ProxyId: f.web.ID, PublicName: "b", Country: "XX"},
		},
	})
	if got.GetTitle() != "Pick\na direction" || got.GetFooter() != strings.Repeat("я", 150) {
		t.Errorf("title %q, footer %q", got.GetTitle(), got.GetFooter())
	}
	if it := got.GetItems(); it[0].GetCode() != "R2D" || it[0].GetCountry() != "NL" || it[1].GetCode() != "" || it[1].GetCountry() != "NL" {
		t.Errorf("items = %v", it)
	}
	stored, err := e.db.PublicPage(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Items[0].Code != "R2D" || stored.Items[1].Code != "" || stored.Footer != strings.Repeat("я", 150) {
		t.Errorf("stored %+v", stored)
	}
	resp, err := e.admin.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if it := resp.Msg.GetPage().GetItems(); it[1].GetCountry() != "NL" {
		t.Errorf("GetPublicPage items = %v", it)
	}
}
