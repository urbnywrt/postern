package panelurl

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for in, want := range map[string]string{
		"https://panel.example.com":       "https://panel.example.com",
		"https://panel.example.com/":      "https://panel.example.com",
		"HTTPS://Panel.Example.COM:8443/": "https://panel.example.com:8443",
		"https://192.0.2.10":              "https://192.0.2.10",
		"https://[2001:DB8::1]:443":       "https://[2001:db8::1]:443",
		"http://localhost:8080":           "http://localhost:8080",
		"http://LOCALHOST":                "http://localhost",
		"http://127.0.0.1:8080/":          "http://127.0.0.1:8080",
		"http://127.1.2.3":                "http://127.1.2.3",
		"http://[::1]:8080":               "http://[::1]:8080",
	} {
		got, err := Check(in)
		if err != nil || got != want {
			t.Errorf("Check(%q) = %q, %v; want %q", in, got, err, want)
		}
		if strings.ContainsAny(got, "'\" \\\t\n$`#?&;|<>(){}*!") {
			t.Errorf("Check(%q) = %q has a character that is not safe in quotes", in, got)
		}
	}
	for _, in := range []string{
		"",
		"panel.example.com",
		"//panel.example.com",
		"ftp://panel.example.com",
		"http://panel.example.com",
		"http://192.0.2.10",
		"http://[::ffff:127.0.0.1]",
		"http://128.0.0.1",
		"https://panel.example.com/admin",
		"https://panel.example.com/api",
		"https://panel.example.com//",
		"https://panel.example.com?x=1",
		"https://panel.example.com/?",
		"https://panel.example.com#frag",
		"https://panel.example.com#",
		"https://user@panel.example.com",
		"https://user:pass@panel.example.com",
		"https://panel.example.com:0",
		"https://panel.example.com:65536",
		"https://panel.example.com:080",
		"https://panel.example.com:",
		"https://pa nel.example.com",
		"https://panel'.example.com",
		`https://panel".example.com`,
		`https://panel\.example.com`,
		"https://panel_x.example.com",
		"https://-panel.example.com",
		"https://[fe80::1%25eth0]",
		"https://панель.example",
		"https:panel.example.com",
	} {
		got, err := Check(in)
		if err == nil {
			t.Errorf("Check(%q) = %q, want an error", in, got)
			continue
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Errorf("Check(%q): the error %q quotes the input", in, err)
		}
	}
}
