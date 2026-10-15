package publicpage

import (
	"strconv"
	"strings"
)

// labels are the words of the page in one language.
type labels struct {
	Lede        string // under the title, when the page has no text of its own
	Footer      string // the footer, when the page has none of its own
	Manual      string // the summary of the section "enter manually"
	ManualHint  string // where Telegram takes the parameters
	Fallback    string // the https://t.me/... link
	Server      string
	Port        string
	Secret      string
	Unavailable string // where the arrow of a row is
	Empty       string // no item on the page
	Copy        string // the copy button that copy.js adds
	Copied      string
}

var labelsByLocale = map[string]labels{
	localeRU: { //nolint:gosec // G101 takes the label "Secret" for a credential: these are the words of the page
		Lede:        "Нажми на строку. Telegram откроется и предложит подключить прокси. Через него пойдёт только Telegram, остальной трафик останется как был.",
		Footer:      "Если прокси не открывается, попробуй соседний: блокировки работают по адресам, и обычно падает не всё сразу.",
		Manual:      "Ввести вручную",
		ManualHint:  "Настройки → Данные и память → Прокси → Добавить прокси → MTProto.",
		Fallback:    "Открыть через t.me",
		Server:      "Сервер",
		Port:        "Порт",
		Secret:      "Секрет",
		Unavailable: "недоступен",
		Empty:       "Пока нет ни одного прокси.",
		Copy:        "Копировать",
		Copied:      "Скопировано",
	},
	localeEN: {
		Lede:        "Tap a row. Telegram opens and offers to add the proxy. Only Telegram goes through it; the rest of your traffic stays as it is.",
		Footer:      "If a proxy does not open, try the next one: blocks go by address, and seldom hit all of them at once.",
		Manual:      "Enter manually",
		ManualHint:  "Settings → Data and Storage → Proxy → Add Proxy → MTProto.",
		Fallback:    "Open via t.me",
		Server:      "Server",
		Port:        "Port",
		Secret:      "Secret",
		Unavailable: "unavailable",
		Empty:       "No proxies yet.",
		Copy:        "Copy",
		Copied:      "Copied",
	},
}

// labelsOf returns the labels of a locale that languageOf gave.
func labelsOf(locale string) labels {
	if l, ok := labelsByLocale[locale]; ok {
		return l
	}
	return labelsByLocale[localeRU]
}

// languageOf picks the language of the page: ?lang= when it names one,
// otherwise the language of Accept-Language with the highest q among those
// the page has, otherwise fallback (the default locale of the page), and ru
// when that names none either.
func languageOf(query, accept, fallback string) string {
	if l, ok := knownLocale(query); ok {
		return l
	}
	best, bestQ := "", 0.0
	for part := range strings.SplitSeq(accept, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		l, ok := knownLocale(strings.TrimSpace(tag))
		if !ok {
			continue
		}
		q := 1.0
		for param := range strings.SplitSeq(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		if q > bestQ {
			best, bestQ = l, q
		}
	}
	if best != "" {
		return best
	}
	if l, ok := knownLocale(fallback); ok {
		return l
	}
	return localeRU
}

// knownLocale returns the locale of a language tag whose primary subtag is one
// of the page's: "en-GB" is en, "RU" is ru.
func knownLocale(tag string) (string, bool) {
	primary, _, _ := strings.Cut(tag, "-")
	switch lowerASCII(primary) {
	case localeRU:
		return localeRU, true
	case localeEN:
		return localeEN, true
	}
	return "", false
}
