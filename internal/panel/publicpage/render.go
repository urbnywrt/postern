package publicpage

import (
	"bytes"
	"context"
	_ "embed"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

//go:embed templates/page.html.tmpl
var pageTemplateText string

// pageTemplate is the page. html/template escapes every value for where it
// stands; the only values that are not escaped are of the types template.HTML
// (the Markdown that goldmark rendered) and template.URL (the links that
// internal/links built, which the template still escapes for the attribute
// they stand in; the type only lets the tg: scheme through, which the URL
// filter would otherwise refuse).
var pageTemplate = template.Must(template.New("page").Parse(pageTemplateText))

// pageData is what the template is given.
type pageData struct {
	Lang string
	// Title is the <title>: the lines of the title joined with a space.
	// Title1 is the first line of the h1, Title2 the second, in the accent
	// colour, "" when there is one line.
	Title, Title1, Title2 string
	Body                  template.HTML // "": the default lede of the locale
	Footer                []string      // the lines of the footer, the default when it is empty
	NoIndex               bool
	CSS, JS               string // the paths of the assets
	L                     labels
	Items                 []itemView
	Manual                bool // an item is available: the section "enter manually" has something
}

// An itemView is one item as the page shows it. An item that is not available
// has a code, a name, a note and nothing else (R6-4).
type itemView struct {
	Code       string // the code of the item, or else the country of the server, or ""
	Name, Note string
	Available  bool
	TG, HTTPS  template.URL
	Addr       string // server:port, or the server of a WEB proxy, as the link has it
	Server     string
	Port       string // "" for a WEB proxy
	Secret     string
}

// servePage renders the page for the request: the chrome of cfg, and the
// items, their links and their availability as they are now.
func (s *Service) servePage(w http.ResponseWriter, r *http.Request, cfg *config) {
	lang := languageOf(r.URL.Query().Get("lang"), r.Header.Get("Accept-Language"), cfg.DefaultLocale)
	items, err := s.items(r.Context(), cfg)
	if err != nil {
		if r.Context().Err() == nil {
			s.log.Error("the public page could not be built", "err", err)
		}
		plain(w, r, http.StatusInternalServerError, "the page cannot be shown right now")
		return
	}
	l := labelsOf(lang)
	footer := cfg.Footer
	if footer == "" {
		footer = l.Footer
	}
	data := pageData{
		Lang:    lang,
		Title:   strings.TrimSpace(cfg.title1 + " " + cfg.title2),
		Title1:  cfg.title1,
		Title2:  cfg.title2,
		Body:    cfg.body,
		Footer:  strings.Split(footer, "\n"),
		NoIndex: cfg.NoIndex,
		CSS:     cssAsset.path,
		JS:      jsAsset.path,
		L:       l,
		Items:   items,
	}
	for _, it := range items {
		data.Manual = data.Manual || it.Available
	}
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		s.log.Error("the public page could not be rendered", "err", err)
		plain(w, r, http.StatusInternalServerError, "the page cannot be shown right now")
		return
	}
	h := w.Header()
	noStore(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	write(w, r, http.StatusOK, buf.Bytes())
}

// items builds the items of the page as they are now: the proxies read again,
// their availability decided, their links built. An item whose proxy is gone
// is left out; one that is unavailable is left out or marked as cfg says; one
// whose links cannot be built (no link host, a secret that does not open) is
// left out and logged, once per reason.
//
// Every request lists every proxy and every node and builds the links of each
// available item (two reads of the listener and the node, the secret opened),
// and of an unavailable one the link host (a read of the listener) for its
// country. That is the cost that R6-10 accepts for a page
// that never shows a stale item: a pause, an offline node or a failing probe
// shows at once. The cap of maxInFlight requests bounds it.
func (s *Service) items(ctx context.Context, cfg *config) ([]itemView, error) {
	if len(cfg.Items) == 0 {
		return nil, nil
	}
	all, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.Proxy, len(all))
	for _, p := range all {
		byID[p.ID] = p
	}
	nodes, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	nodeByID := make(map[string]*store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}

	out := make([]itemView, 0, len(cfg.Items))
	for _, it := range cfg.Items {
		p := byID[it.ProxyID]
		if p == nil {
			continue
		}
		node := nodeByID[p.NodeID]
		v := itemView{Code: it.Code, Name: it.PublicName, Note: it.PublicNote, Available: s.available(p, node)}
		if !v.Available {
			if cfg.Unavailable == store.PublicUnavailableHide {
				continue
			}
			if v.Code == "" && s.country != nil {
				host, err := s.linkHost(ctx, p, node)
				if err != nil {
					return nil, err
				}
				v.Code = s.countryOf(p, node, host)
			}
			out = append(out, v)
			continue
		}
		lk, err := proxies.LinksOf(ctx, s.db, s.key, p)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			s.linksFailed(p.ID, err)
			continue
		}
		s.linksBuilt(p.ID)
		// The type lets the tg: scheme past the URL filter of html/template,
		// which knows http, https and mailto only; the template still escapes
		// the value for the attribute it stands in. The links come from
		// internal/links, built from stored values and percent-encoded.
		v.TG, v.HTTPS = template.URL(lk.TG), template.URL(lk.HTTPS) //nolint:gosec // see above: not user input, and attribute-escaped by the template
		v.Server, v.Port, v.Secret = lk.Server, lk.Port, lk.Secret
		v.Addr = lk.Server
		if lk.Port != "" {
			v.Addr = net.JoinHostPort(lk.Server, lk.Port)
		}
		if v.Code == "" {
			v.Code = s.countryOf(p, node, lk.Server)
		}
		out = append(out, v)
	}
	return out, nil
}

// linksFailed logs why the links of a proxy could not be built, once per
// reason, and leaves the proxy off the page.
func (s *Service) linksFailed(proxyID string, err error) {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	if s.failed[proxyID] == err.Error() {
		return
	}
	s.failed[proxyID] = err.Error()
	s.log.Warn("a proxy of the public page is left out because its links cannot be built", "proxy", proxyID, "err", err)
}

// linksBuilt forgets the failure of a proxy, so that the next one is logged.
func (s *Service) linksBuilt(proxyID string) {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	delete(s.failed, proxyID)
}
