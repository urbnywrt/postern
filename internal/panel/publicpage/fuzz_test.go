package publicpage

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func FuzzHostOf(f *testing.F) {
	for _, s := range []string{
		"", "proxies.example.test", "Proxies.Example.Test.:8443", "[2001:db8::1]:443", "[2001:db8::1]", "2001:db8::1",
		"example.com:", ":443", "..", "a..", "ExAmPlE.COM.", "\xff\xfe:1", "[", "]:1", "a]b:c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		got := HostOf(&http.Request{Host: host})
		if len(got) > len(host) {
			t.Fatalf("HostOf(%q) = %q, longer than the input", host, got)
		}
		if strings.ContainsFunc(got, func(r rune) bool { return 'A' <= r && r <= 'Z' }) {
			t.Fatalf("HostOf(%q) = %q has an upper-case letter", host, got)
		}
		// A host:port as net reads it loses its port and its one trailing dot.
		// (net strips the brackets of an IPv6 address, HostOf keeps them: a
		// bracketed host is never a DNS name, so it is left out here.)
		if h, _, err := net.SplitHostPort(host); err == nil && !strings.HasPrefix(host, "[") {
			want := lowerASCII(strings.TrimSuffix(h, "."))
			if got != want {
				t.Fatalf("HostOf(%q) = %q, want %q", host, got, want)
			}
		}
		// The result compares equal to itself when sent again, with one exception:
		// a second trailing dot is dropped only then.
		if again := HostOf(&http.Request{Host: got}); again != got && !strings.HasSuffix(got, ".") {
			t.Fatalf("HostOf(%q) = %q, but HostOf of that is %q", host, got, again)
		}
	})
}

func FuzzLanguage(f *testing.F) {
	for _, c := range [][3]string{
		{"", "", ""}, {"en", "", "ru"}, {"", "en-US,en;q=0.9,ru;q=0.8", "ru"}, {"", "ru;q=0,en;q=0.1", "ru"},
		{"de", "fr, *;q=0.5", "en"}, {"", ";;;,,,q=", ""}, {"", "en;q=nan,ru;q=inf", ""}, {"EN", "", ""},
	} {
		f.Add(c[0], c[1], c[2])
	}
	f.Fuzz(func(t *testing.T, query, accept, fallback string) {
		got := languageOf(query, accept, fallback)
		if got != localeRU && got != localeEN {
			t.Fatalf("languageOf(%q, %q, %q) = %q", query, accept, fallback, got)
		}
		if l, ok := knownLocale(query); ok && got != l {
			t.Fatalf("languageOf(%q, %q, %q) = %q, but ?lang= says %q", query, accept, fallback, got, l)
		}
		if _, ok := labelsByLocale[got]; !ok {
			t.Fatalf("no labels for %q", got)
		}
	})
}

func FuzzMarkdown(f *testing.F) {
	for _, s := range []string{
		markdownFixture, "", "plain", "[x](javascript&colon;alert(1))", "[x](&#x6A;avascript:alert(1))",
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "[x](data:text/html,<script>)",
		"<svg onload=alert(1)>", "[x](\x00javascript:alert(1))", "[x](java\tscript:alert(1))", "[x](java&Tab;script:alert(1))",
		"<a href='javascript:alert(1)'>x</a>", "<https://example.com>", "![x](x) # not a heading\n# heading",
		"[x]: javascript:alert(1)\n[x]", "<!-- comment -->", "&lt;script&gt;", "<iframe src=x>", "<style>*{}</style>",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > maxBodyBytes {
			t.Skip()
		}
		checkMarkdownOutput(t, src, string(renderMarkdown(src)))
	})
}
