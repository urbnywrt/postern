package publicpage

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// markdownFixture holds everything the renderer has to neutralise, and what it
// has to keep.
const markdownFixture = `# Heading one

Some *text* with a [plain link](https://example.com/page?a=1&b=2) and a
[Telegram link](tg://proxy?server=proxy.example.com&port=443&secret=ee00) to keep.

<script>alert(1)</script>

[x](javascript:alert(1))
[x](javascript&colon;alert(1))
[x](JaVaScRiPt:alert(1))
[x](&#106;avascript:alert(1))
[x](&#x6A;avascript:alert(1))
[x](java&Tab;script:alert(1))
[x](vbscript:msgbox(1))
[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)
<javascript:alert(1)>
<https://example.com/auto>

![an image](https://example.com/i.png "title")
![](javascript:alert(1))

<img src=x onerror=alert(1)>
<a href="javascript:alert(1)">raw</a>
inline <b onmouseover=alert(1)>raw</b> html

## Heading two

###### Heading six

> quoted

- one
- two

` + "```go\ncode <here>\n```\n"

func TestMarkdownGolden(t *testing.T) {
	golden(t, "markdown.html", string(renderMarkdown(markdownFixture)))
}

func TestMarkdownRules(t *testing.T) {
	out := string(renderMarkdown(markdownFixture))
	lower := strings.ToLower(out)

	// Dangerous schemes are gone from every href, entity-encoded or not (the
	// text of such a link stays, as text); raw HTML is gone; tg: and https: stay.
	for _, bad := range []string{"<script", "<img", "onerror", "onmouseover", "<b ", "<a href=\"javascript", "<a href=\"\""} {
		if strings.Contains(lower, bad) {
			t.Errorf("the output contains %q:\n%s", bad, out)
		}
	}
	for _, m := range hrefPattern.FindAllStringSubmatch(lower, -1) {
		for _, bad := range []string{"javascript", "vbscript", "data:", "file:"} {
			if strings.Contains(m[1], bad) {
				t.Errorf("an href contains %q: %q", bad, m[0])
			}
		}
	}
	for _, good := range []string{
		`<a href="https://example.com/page?a=1&amp;b=2" rel="nofollow noopener noreferrer">plain link</a>`,
		`<a href="tg://proxy?server=proxy.example.com&amp;port=443&amp;secret=ee00" rel="nofollow noopener noreferrer">Telegram link</a>`,
		`<a href="https://example.com/auto" rel="nofollow noopener noreferrer">https://example.com/auto</a>`,
		"<!-- raw HTML omitted -->",
		"<h2>Heading one</h2>", "<h3>Heading two</h3>", "<h6>Heading six</h6>",
		"an image",
		"<blockquote>", "<ul>", "<li>one</li>", `<pre><code class="language-go">code &lt;here&gt;`,
	} {
		if !strings.Contains(out, good) {
			t.Errorf("the output lacks %q:\n%s", good, out)
		}
	}
	if strings.Contains(out, "<h1") {
		t.Error("the Markdown made an h1; the title is the only one")
	}
	// A dangerous link is its text alone, with no anchor around it.
	if n := strings.Count(out, "<a "); n != 3 {
		t.Errorf("%d anchors, want 3 (the plain link, the Telegram link and the autolink)", n)
	}
	if n := strings.Count(out, "x\n"); n != 8 {
		t.Errorf("%d refused links left as their text, want 8:\n%s", n, out)
	}
	checkMarkdownOutput(t, markdownFixture, out)
}

// safeDestination decodes before it looks, strips what browsers ignore, and
// knows four schemes.
func TestSafeDestination(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"https://example.com/a?b=1&c=2", "https://example.com/a?b=1&c=2", true},
		{"HTTP://example.com", "HTTP://example.com", true},
		{"tg://proxy?server=x&port=1&secret=ee00", "tg://proxy?server=x&port=1&secret=ee00", true},
		{"mailto:someone@example.com", "mailto:someone@example.com", true},
		{"/relative/path", "/relative/path", true},
		{"relative?x=javascript:1", "relative?x=javascript:1", true},
		{"#fragment", "#fragment", true},
		{"//example.com/x", "//example.com/x", true},
		{"a/b:c", "a/b:c", true},
		{"", "", true},
		{"javascript:alert(1)", "javascript:alert(1)", false},
		{"JaVaScRiPt:alert(1)", "JaVaScRiPt:alert(1)", false},
		{"javascript&colon;alert(1)", "javascript:alert(1)", false},
		{"&#106;avascript:alert(1)", "javascript:alert(1)", false},
		{"&#x6A;avascript:alert(1)", "javascript:alert(1)", false},
		{"java&Tab;script:alert(1)", "javascript:alert(1)", false},
		{"java\tscript:alert(1)", "javascript:alert(1)", false},
		{" \x01javascript:alert(1)", "javascript:alert(1)", false},
		{"java script:alert(1)", "javascript:alert(1)", false},
		{"vbscript:msgbox(1)", "vbscript:msgbox(1)", false},
		{"data:text/html,x", "data:text/html,x", false},
		{"data:image/png;base64,AAAA", "data:image/png;base64,AAAA", false},
		{"file:///etc/passwd", "file:///etc/passwd", false},
		{"ftp://example.com", "ftp://example.com", false},
		{"ssh+git://x", "ssh+git://x", false},
		{"\\javascript:alert(1)", "\\javascript:alert(1)", true}, // relative: a backslash is not a scheme byte
	} {
		got, ok := safeDestination([]byte(c.in))
		if string(got) != c.want || ok != c.ok {
			t.Errorf("safeDestination(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// The tags and attributes that the renderer may emit. Anything else in the
// output is raw HTML that got through.
var (
	allowedTags  = regexp.MustCompile(`^(p|a|em|strong|code|pre|blockquote|ul|ol|li|h[2-6]|hr|br)$`)
	tagPattern   = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
	attrsPattern = regexp.MustCompile(`^(\s+(href|rel|class|start)="[^"<>]*")*\s*/?$`)
	hrefPattern  = regexp.MustCompile(`href="([^"]*)"`)
)

// dangerousHref reports whether an href, HTML-unescaped and lower-cased, has
// a scheme that runs code or loads a file: javascript:, vbscript:, file:, and
// data: other than an image, after any leading whitespace or control bytes.
func dangerousHref(href string) bool {
	href = strings.TrimLeftFunc(href, func(r rune) bool { return r <= ' ' || r == 0x7f })
	for _, scheme := range []string{"javascript:", "vbscript:", "file:"} {
		if strings.HasPrefix(href, scheme) {
			return true
		}
	}
	if !strings.HasPrefix(href, "data:") {
		return false
	}
	for _, img := range []string{"data:image/png;", "data:image/gif;", "data:image/jpeg;", "data:image/webp;"} {
		if strings.HasPrefix(href, img) {
			return false
		}
	}
	return true
}

// checkMarkdownOutput checks the properties that every rendering has to have,
// whatever the input: only the tags and attributes of the renderer, no
// on...= handler, no <script or <img, and no href with a dangerous scheme.
func checkMarkdownOutput(t *testing.T, input, out string) {
	t.Helper()
	lower := strings.ToLower(out)
	if strings.Contains(lower, "<script") || strings.Contains(lower, "<img") {
		t.Fatalf("the output has a <script or an <img:\ninput %q\noutput %q", input, out)
	}
	stripped := strings.ReplaceAll(out, "<!-- raw HTML omitted -->", "")
	if strings.Contains(stripped, "<!--") {
		t.Fatalf("the output has a comment of the input:\ninput %q\noutput %q", input, out)
	}
	tags := tagPattern.FindAllStringSubmatch(stripped, -1)
	if strings.Count(stripped, "<") != len(tags) {
		t.Fatalf("the output has a < that is not a tag of the renderer:\ninput %q\noutput %q", input, out)
	}
	for _, m := range tags {
		if !allowedTags.MatchString(m[2]) {
			t.Fatalf("the output has a <%s> tag:\ninput %q\noutput %q", m[2], input, out)
		}
		if m[1] == "/" && strings.TrimSpace(m[3]) != "" {
			t.Fatalf("a closing tag has attributes:\ninput %q\noutput %q", input, out)
		}
		if !attrsPattern.MatchString(m[3]) {
			t.Fatalf("the output has a tag with other attributes than href, rel, class and start: %q\ninput %q\noutput %q", m[0], input, out)
		}
		if strings.Contains(strings.ToLower(m[3]), " on") {
			t.Fatalf("the output has an on... attribute: %q\ninput %q", m[0], input)
		}
	}
	for _, m := range hrefPattern.FindAllStringSubmatch(out, -1) {
		if dangerousHref(strings.ToLower(html.UnescapeString(m[1]))) {
			t.Fatalf("the output has an href with a dangerous scheme: %q\ninput %q", m[1], input)
		}
	}
}
