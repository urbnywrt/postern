// Package publicpage is the public page of the panel: a page on a domain of its
// own that lists the proxies an admin chose, as rows that link to them, so
// that the owner can hand out one address (spec §8.5). It is internet-facing,
// and the rest of the panel is never served on its host.
//
//   - Service is the PublicPageService of the panel API (admins configure the
//     page) and the HTTP handler of the page itself.
//   - The configuration is kept in memory and replaced on every update. Only
//     the chrome (the title and the Markdown, rendered) is prepared ahead; the
//     items, their links and their availability are built for every request,
//     so that a pause, an offline node, a failing probe or a removed item shows
//     at once.
//   - The page is served for exactly one Host. A request for that host goes to
//     [Service.Handler] and nowhere else, also while the page is disabled (then
//     everything there is a 404). [Service.Serves] tells the server which
//     requests those are; [Service.RecordAdminHosts] remembers the names the
//     admin pages were served on, which the page is refused as its host.
//
// Wiring, in the panel:
//
//	public := publicpage.NewService(db, key, log)
//	// in the admin chain, inside the auth middleware:
//	auth.Middleware(public.RecordAdminHosts(adminMux))
//	// ahead of the admin chain:
//	if public.Serves(r) { public.Handler().ServeHTTP(w, r) }
package publicpage

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// The limits of the configuration.
const (
	maxHostBytes   = 253
	maxLabelBytes  = 63
	maxTitleBytes  = 120
	maxBodyBytes   = 16 << 10
	maxFooterBytes = 300
	maxCodeBytes   = 4
	maxItems       = 100
	maxNameChars   = 64
	maxNoteChars   = 280

	// loadTimeout bounds the read of the configuration at start.
	loadTimeout = 10 * time.Second
	// writeTimeout bounds the end of an update, which runs to the end once it
	// starts: a change that is written has to be served.
	writeTimeout = 30 * time.Second
)

// The locales of the page.
const (
	localeRU = "ru"
	localeEN = "en"
)

// errInternal is all that a caller is told of an error of the panel itself.
// What it was is in the log.
var errInternal = errors.New("internal error")

// errAdminHost is the refusal of a public host that the admin pages are served
// on: the host of the request that saves it, or one an admin request used
// before.
var errAdminHost = errors.New("the admin pages are served on this name")

// An Option changes how [NewService] makes the service.
type Option func(*Service)

// WithProbeDown sets the function that says whether the probes of a proxy
// fail, by its id: such a proxy is unavailable on the page. nil, the default,
// is never down. The panel's probes (Task 8) wire it.
func WithProbeDown(down func(proxyID string) bool) Option {
	return func(s *Service) { s.probeDown = down }
}

// WithCountry sets the GeoIP lookup that gives the code of an item without
// one: the country of the server, "" when it is not known (geodb.Manager's
// Country). nil, the default, knows no country.
func WithCountry(country func(ip netip.Addr) string) Option {
	return func(s *Service) { s.country = country }
}

// Service is the PublicPageService of the panel and the handler of the page.
//
// Every procedure needs an admin: the auth middleware refuses calls without a
// session, and the service checks again, so that it is safe however it is
// mounted. The page itself is public.
type Service struct {
	db        *store.DB
	key       seal.Key
	log       *slog.Logger
	probeDown func(proxyID string) bool
	country   func(ip netip.Addr) string // nil knows none
	now       func() time.Time           // tests replace it

	// What CheckPublicPage uses: the resolver (nil is the system's alone);
	// tests replace the system resolver, the dialer and the roots (nil are
	// the system's).
	resolver    Resolver
	sysResolver Resolver
	checkDial   func(ctx context.Context, network, addr string) (net.Conn, error)
	checkRoots  *x509.CertPool

	// cfg is the configuration that the page serves, nil until it is loaded
	// (then the page is off). It is replaced as a whole by every update.
	cfg atomic.Pointer[config]
	// sem has a slot for every request that the public host may have in
	// flight at a time.
	sem chan struct{}

	// hostsMu guards hostSeen: the names the admin pages were served on, by
	// name, and when they were last written to the database.
	hostsMu  sync.Mutex
	hostSeen map[string]time.Time

	// failedMu guards failed: the proxies whose links could not be built, by
	// id, with the reason that was logged last, so that a page that is built
	// for every request logs each reason once.
	failedMu sync.Mutex
	failed   map[string]string
}

var _ panelv1connect.PublicPageServiceHandler = (*Service)(nil)

// config is the configuration of the page as the handler uses it: the stored
// page, and the chrome prepared from it.
type config struct {
	store.PublicPage
	body template.HTML // BodyMD, rendered
	// The lines of the title: the first, shown plain, and the second, shown
	// in the accent colour, "" when the title has one line.
	title1, title2 string
}

// NewService returns the service on the database. key opens the proxy secrets,
// which the links carry. The configuration is loaded now; if it cannot be, the
// page is off until an update, and the log says so. A nil log discards the
// log.
func NewService(db *store.DB, key seal.Key, log *slog.Logger, opts ...Option) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		db:       db,
		key:      key,
		log:      log,
		now:      time.Now,
		sem:      make(chan struct{}, maxInFlight),
		hostSeen: map[string]time.Time{},
		failed:   map[string]string{},
	}
	for _, opt := range opts {
		opt(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()
	if err := s.load(ctx); err != nil {
		log.Error("the public page could not read its configuration, so it is off until an admin saves it", "err", err)
	}
	return s
}

// load reads the configuration and makes it the one that is served.
func (s *Service) load(ctx context.Context) error {
	p, err := s.db.PublicPage(ctx)
	if err != nil {
		return err
	}
	s.apply(p)
	return nil
}

// apply makes p the configuration that is served, chrome prepared.
func (s *Service) apply(p *store.PublicPage) {
	t1, t2, _ := strings.Cut(p.Title, "\n")
	s.cfg.Store(&config{PublicPage: *p, body: renderMarkdown(p.BodyMD), title1: t1, title2: t2})
}

// requireAdmin returns the admin of the request, or the error to answer with.
func requireAdmin(ctx context.Context) (*store.Admin, error) {
	a, ok := auth.AdminFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return a, nil
}

// fail turns an error of the panel itself into the error that a caller gets,
// and logs it. A request that is gone or has run out of time says so, since
// that is not a fault.
func (s *Service) fail(what string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the request was canceled"))
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the request took too long"))
	}
	s.log.Error(what, "err", err)
	return connect.NewError(connect.CodeInternal, errInternal)
}

func invalid(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// GetPublicPage returns the configuration of the page, items included.
func (s *Service) GetPublicPage(ctx context.Context, _ *connect.Request[panelv1.GetPublicPageRequest]) (*connect.Response[panelv1.GetPublicPageResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.PublicPage(ctx)
	if err != nil {
		return nil, s.fail("could not read the public page", err)
	}
	countries, err := s.countries(ctx, p)
	if err != nil {
		return nil, s.fail("could not read the proxies of the public page", err)
	}
	return connect.NewResponse(&panelv1.GetPublicPageResponse{Page: pageProto(p, countries)}), nil
}

// UpdatePublicPage replaces the whole configuration of the page. It is
// audited, and the page serves the new configuration as soon as it is stored.
func (s *Service) UpdatePublicPage(ctx context.Context, req *connect.Request[panelv1.UpdatePublicPageRequest]) (*connect.Response[panelv1.UpdatePublicPageResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	p, err := s.checkPage(ctx, req.Msg.GetPage())
	if err != nil {
		return nil, err
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	switch err := s.db.UpdatePublicPage(wctx, p); {
	case errors.Is(err, store.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, errors.New("an item names a proxy that does not exist"))
	case errors.Is(err, store.ErrConflict):
		return nil, invalid("an item names a proxy twice")
	case err != nil:
		return nil, s.fail("could not store the public page", err)
	}
	// What was written is what is served, whether or not it can be read back.
	s.apply(p)
	s.audit(wctx, admin.ID, p)
	s.log.Info("public page updated", "enabled", p.Enabled, "host", p.Host, "items", len(p.Items), "admin", admin.ID)
	// The countries are a hint for the form; the page is stored either way.
	countries, err := s.countries(wctx, p)
	if err != nil {
		s.log.Warn("the countries of the items of the public page could not be found", "err", err)
	}
	return connect.NewResponse(&panelv1.UpdatePublicPageResponse{Page: pageProto(p, countries)}), nil
}

// audit records the update. A failure is logged and does not fail the call:
// what it records has happened.
func (s *Service) audit(ctx context.Context, adminID string, p *store.PublicPage) {
	entry := &store.AuditEntry{
		AdminID: adminID, Action: "public_page.update", Target: "public_page",
		Details: map[string]string{
			"enabled": fmt.Sprint(p.Enabled), "host": p.Host, "items": fmt.Sprint(len(p.Items)),
			"unavailable": p.Unavailable, "allow_indexing": fmt.Sprint(!p.NoIndex),
		},
	}
	if err := s.db.AppendAudit(ctx, entry); err != nil {
		s.log.Error("could not write the audit log", "action", entry.Action, "err", err)
	}
}

// checkPage checks every value of a page that is to be stored and returns it
// in its stored form: the host canonical, texts trimmed, the defaults filled
// in. The host is refused when the admin pages are served on it: on the host
// of this request, or on one an admin request used before.
func (s *Service) checkPage(ctx context.Context, msg *panelv1.PublicPage) (*store.PublicPage, error) {
	p := &store.PublicPage{
		Enabled: msg.GetEnabled(),
		// S6-3: the wire says whether indexing is allowed, so that a client
		// that leaves the field out keeps noindex on.
		NoIndex:       !msg.GetAllowIndexing(),
		Unavailable:   msg.GetUnavailable(),
		DefaultLocale: msg.GetDefaultLocale(),
	}
	var err error
	if p.Host, err = checkHost(msg.GetHost()); err != nil {
		return nil, err
	}
	if p.Enabled && p.Host == "" {
		return nil, invalid("enabling the page needs a host")
	}
	if p.Title, err = checkTitle(msg.GetTitle()); err != nil {
		return nil, err
	}
	if p.Footer, err = checkText("footer", msg.GetFooter(), maxFooterBytes, false, true); err != nil {
		return nil, err
	}
	if len(msg.GetBodyMd()) > maxBodyBytes {
		return nil, invalid("body_md has more than %d bytes", maxBodyBytes)
	}
	if !utf8.ValidString(msg.GetBodyMd()) {
		return nil, invalid("body_md is not valid UTF-8")
	}
	p.BodyMD = msg.GetBodyMd()
	switch p.Unavailable {
	case "":
		p.Unavailable = store.PublicUnavailableMark
	case store.PublicUnavailableHide, store.PublicUnavailableMark:
	default:
		return nil, invalid("unavailable must be %q or %q", store.PublicUnavailableHide, store.PublicUnavailableMark)
	}
	switch p.DefaultLocale {
	case "":
		p.DefaultLocale = localeRU
	case localeRU, localeEN:
	default:
		return nil, invalid("default_locale must be %q or %q", localeRU, localeEN)
	}

	items := msg.GetItems()
	if len(items) > maxItems {
		return nil, invalid("at most %d items, not %d", maxItems, len(items))
	}
	if len(items) > 0 {
		known, err := s.proxyIDs(ctx)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for i, it := range items {
			id := strings.TrimSpace(it.GetProxyId())
			if !known[id] {
				return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("item %d: no such proxy", i+1))
			}
			if seen[id] {
				return nil, invalid("item %d names a proxy that an item before it names", i+1)
			}
			seen[id] = true
			item := store.PublicPageItem{ProxyID: id}
			if item.PublicName, err = checkText(fmt.Sprintf("item %d: public_name", i+1), it.GetPublicName(), maxNameChars, true, false); err != nil {
				return nil, err
			}
			if item.PublicNote, err = checkText(fmt.Sprintf("item %d: public_note", i+1), it.GetPublicNote(), maxNoteChars, true, true); err != nil {
				return nil, err
			}
			if item.Code, err = checkCode(fmt.Sprintf("item %d: code", i+1), it.GetCode()); err != nil {
				return nil, err
			}
			p.Items = append(p.Items, item)
		}
	}

	if p.Host != "" {
		if err := s.checkNotAdminHost(ctx, p.Host); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// proxyIDs returns the ids of every proxy.
func (s *Service) proxyIDs(ctx context.Context) (map[string]bool, error) {
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, s.fail("could not list the proxies", err)
	}
	ids := make(map[string]bool, len(ps))
	for _, p := range ps {
		ids[p.ID] = true
	}
	return ids, nil
}

// checkNotAdminHost refuses host when the admin pages are served on it.
func (s *Service) checkNotAdminHost(ctx context.Context, host string) error {
	if host == requestHostOf(ctx) {
		return connect.NewError(connect.CodeInvalidArgument, errAdminHost)
	}
	hosts, err := s.db.AdminHosts(ctx)
	if err != nil {
		return s.fail("could not read the names the admin pages were served on", err)
	}
	for _, h := range hosts {
		if h.Host == host {
			return connect.NewError(connect.CodeInvalidArgument, errAdminHost)
		}
	}
	return nil
}

// checkHost returns the host in its canonical form (lower case), if it is a DNS
// name of at least two labels of 1 to 63 letters, digits and hyphens, at most
// 253 bytes, not an IP address and without a port. Empty is no host.
func checkHost(s string) (string, error) {
	host := lowerASCII(strings.TrimSpace(s))
	if host == "" {
		return "", nil
	}
	bad := func() (string, error) {
		return "", invalid("host must be a DNS name such as proxies.example.com: labels of letters, digits and hyphens, " +
			"at least one dot, not an IP address, no port")
	}
	if len(host) > maxHostBytes || !strings.Contains(host, ".") {
		return bad()
	}
	if _, err := netip.ParseAddr(host); err == nil || strings.HasPrefix(host, "[") {
		return bad()
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > maxLabelBytes {
			return bad()
		}
		for i := 0; i < len(label); i++ {
			if !isLabelByte(label[i]) {
				return bad()
			}
		}
	}
	return host, nil
}

// isLabelByte reports whether c may stand in a label of a host that is in
// lower case: a letter, a digit or a hyphen.
func isLabelByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

// checkText returns a text without the spaces around it. The limit is in bytes,
// or in characters when chars is set. Control characters are refused, the line
// break too unless newlines is set.
func checkText(field, s string, limit int, chars, newlines bool) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", invalid("%s is not valid UTF-8", field)
	}
	unit := "bytes"
	n := len(s)
	if chars {
		unit, n = "characters", utf8.RuneCountInString(s)
	}
	if n > limit {
		return "", invalid("%s has more than %d %s", field, limit, unit)
	}
	for _, r := range s {
		if r == '\n' && newlines {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", invalid("%s must not contain control characters", field)
		}
	}
	return s, nil
}

// checkTitle returns the title in its stored form: one line, or two separated
// by one line break, each without the spaces around it, at most maxTitleBytes
// in all.
func checkTitle(s string) (string, error) {
	t, err := checkText("title", s, maxTitleBytes, false, true)
	if err != nil {
		return "", err
	}
	first, second, two := strings.Cut(t, "\n")
	if !two {
		return t, nil
	}
	if strings.Contains(second, "\n") {
		return "", invalid("title has more than one line break")
	}
	return strings.TrimSpace(first) + "\n" + strings.TrimSpace(second), nil
}

// checkCode returns the code of an item in upper case, if it has at most
// maxCodeBytes ASCII letters and digits. Empty is no code.
func checkCode(field, s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxCodeBytes {
		return "", invalid("%s has more than %d characters", field, maxCodeBytes)
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case 'a' <= c && c <= 'z':
			b[i] = c - ('a' - 'A')
		case 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		default:
			return "", invalid("%s must be letters and digits, at most %d", field, maxCodeBytes)
		}
	}
	return string(b), nil
}

// lowerASCII lowers the ASCII letters of s and leaves every other byte as it
// is, unlike strings.ToLower, which replaces bytes that are not UTF-8.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// pageProto is the API form of the page; countries are those of the items, by
// proxy id.
func pageProto(p *store.PublicPage, countries map[string]string) *panelv1.PublicPage {
	out := &panelv1.PublicPage{
		Enabled:       p.Enabled,
		Host:          p.Host,
		Title:         p.Title,
		BodyMd:        p.BodyMD,
		Footer:        p.Footer,
		Unavailable:   p.Unavailable,
		AllowIndexing: !p.NoIndex,
		DefaultLocale: p.DefaultLocale,
		Items:         make([]*panelv1.PublicPageItem, 0, len(p.Items)),
	}
	for _, it := range p.Items {
		out.Items = append(out.Items, &panelv1.PublicPageItem{ProxyId: it.ProxyID, PublicName: it.PublicName, PublicNote: it.PublicNote,
			Code: it.Code, Country: countries[it.ProxyID]})
	}
	return out
}
