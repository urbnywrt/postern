package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

const (
	// userAgent names the manager in its requests to the ACME server; lego
	// adds its own name.
	userAgent = "postern"
	// dialTimeout bounds the connection to one address of a server.
	dialTimeout = 10 * time.Second
)

// issued is what an issuance brings: the chain as the CA returned it, leaf
// first, and the key of the certificate, both PEM.
type issued struct {
	fullchain []byte
	key       []byte
}

var (
	legoOnce sync.Once
	// legoLogger is where the log of lego goes: the log of the manager that
	// was set up last (there is one per agent).
	legoLogger atomic.Pointer[slog.Logger]
)

// setupLego sets what lego keeps in package variables, once per process.
//
// Its log goes to slog, at the debug level: the manager logs the steps of an
// issuance itself.
//
// Its own DNS client is left without nameservers. Unless told otherwise
// through the environment, lego follows a CNAME record of _acme-challenge
// names, and checks the propagation of the record, by asking the nameservers
// of /etc/resolv.conf over UDP port 53, which is blocked on some nodes: a
// query without nameservers fails at once, without a packet. The CNAME is not
// followed (the DNS provider writes the record at _acme-challenge.<domain>
// itself, and the check asks there), and the check is the manager's, over
// DNS-over-HTTPS (precheck). The nameservers are a package variable of lego,
// which the option sets whatever challenge it is given to.
func setupLego() {
	legoOnce.Do(func() {
		legolog.Logger = legoLog{}
		_ = dns01.NewChallenge(nil, nil, nil, dns01.AddRecursiveNameservers(nil))
	})
}

// legoLog is lego's log as slog lines.
type legoLog struct{}

func (legoLog) print(msg string) {
	if l := legoLogger.Load(); l != nil {
		l.Debug(strings.TrimSpace(msg), "from", "lego")
	}
}

func (l legoLog) Print(args ...any)                 { l.print(fmt.Sprint(args...)) }
func (l legoLog) Println(args ...any)               { l.print(fmt.Sprintln(args...)) }
func (l legoLog) Printf(format string, args ...any) { l.print(fmt.Sprintf(format, args...)) }

// The fatal calls end the process, as those of the standard log do; lego
// makes none of them outside its command.
func (l legoLog) Fatal(args ...any)                 { l.Print(args...); os.Exit(1) }
func (l legoLog) Fatalln(args ...any)               { l.Println(args...); os.Exit(1) }
func (l legoLog) Fatalf(format string, args ...any) { l.Printf(format, args...); os.Exit(1) }

// obtainLego issues a certificate for domain with lego: the TXT records that
// earlier attempts left at _acme-challenge.<domain> go first, then the account
// is registered (or found again) and the certificate ordered, the challenge
// record written through the DNS provider, checked over DNS-over-HTTPS, and
// deleted when the CA has looked. It ends soon after ctx does.
func (m *Manager) obtainLego(ctx context.Context, domain, email string, cred Credential) (*issued, error) {
	provider, err := m.provider(cred)
	if err != nil {
		return nil, err
	}
	if err := provider.RemoveStale(ctx, domain); err != nil {
		return nil, fmt.Errorf("removing the stale TXT records: %w", err)
	}
	key, err := m.accountKey()
	if err != nil {
		return nil, err
	}
	directory := m.directory()
	client, err := lego.NewClient(&lego.Config{
		CADirURL:   directory,
		User:       &acmeUser{email: email, key: key},
		UserAgent:  userAgent,
		HTTPClient: m.acmeClient(ctx),
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.EC256,
			Timeout: HTTPTimeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("reading the ACME directory: %w", err)
	}
	timeout := orDefault(m.propagationTimeout, PropagationTimeout)
	firstPoll := orDefault(m.firstPoll, FirstPollAfter)
	interval := orDefault(m.pollInterval, PollInterval)
	dns := &legoDNS{
		ctx:      ctx,
		provider: provider,
		log:      m.log(),
		// lego gives up waiting for the record after this; the check of the
		// manager gives up first, with an error that says why.
		timeout:  timeout + firstPoll + 4*interval + 30*time.Second,
		interval: interval,
	}
	check := m.checker.precheck(ctx, timeout, firstPoll, dns.writtenAt)
	if err := client.Challenge.SetDNS01Provider(dns, dns01.WrapPreCheck(check)); err != nil {
		return nil, err
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering the ACME account: %w", err)
	}
	if err := m.noteAccount(directory, reg); err != nil {
		m.log().Warn("acme: the account could not be noted in data/acme/account.json", "err", err)
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{domain}, Bundle: true})
	if err != nil {
		return nil, err
	}
	return &issued{fullchain: res.Certificate, key: res.PrivateKey}, nil
}

// directory is the URL of the ACME directory the manager uses.
func (m *Manager) directory() string {
	switch {
	case m.Directory != "":
		return m.Directory
	case m.Staging:
		return LetsEncryptStaging
	}
	return LetsEncrypt
}

// provider returns the DNS provider for cred.
func (m *Manager) provider(cred Credential) (DNSProvider, error) {
	if m.DNS != nil {
		return m.DNS(cred)
	}
	base := m.cloudflareAPI
	if base == "" {
		base = cloudflareAPI
	}
	return newCloudflare(cred, m.httpClient(), base), nil
}

// txtValue is the value of the TXT record of a challenge for a key
// authorization (RFC 8555 8.4): its SHA-256 digest, base64url without padding.
func txtValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// legoDNS is a DNSProvider as lego wants one (challenge.Provider and
// challenge.ProviderTimeout), for one issuance.
type legoDNS struct {
	ctx               context.Context
	provider          DNSProvider
	log               *slog.Logger
	timeout, interval time.Duration

	mu      sync.Mutex
	written map[string]time.Time // by domain: when Present wrote its record
}

func (d *legoDNS) Present(domain, _, keyAuth string) error {
	if err := d.provider.Present(d.ctx, domain, txtValue(keyAuth)); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.written == nil {
		d.written = map[string]time.Time{}
	}
	d.written[domain] = time.Now()
	return nil
}

// writtenAt is when Present wrote the record of domain; zero before.
func (d *legoDNS) writtenAt(domain string) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.written[domain]
}

// CleanUp deletes the record also when the issuance was cut short: it is the
// manager's to delete. A record that cannot be deleted is removed by the next
// issuance of the domain.
func (d *legoDNS) CleanUp(domain, _, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(d.ctx), HTTPTimeout)
	defer cancel()
	err := d.provider.CleanUp(ctx, domain, txtValue(keyAuth))
	if err != nil {
		d.log.Warn("acme: the TXT record of the challenge could not be deleted; the next issuance removes it",
			"domain", domain, "err", err)
	}
	return err
}

func (d *legoDNS) Timeout() (timeout, interval time.Duration) { return d.timeout, d.interval }

// newTransport is the transport of the manager's HTTP clients: TLS 1.2 at
// least, verified against RootCAs (nil: the roots of the system), never the
// proxies of the environment, and host names resolved by lookupIP.
func (m *Manager) newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil, // never the proxies of the environment
		DialContext:            m.dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: m.RootCAs},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    HTTPTimeout,
		ResponseHeaderTimeout:  HTTPTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
	}
}

// httpClient is the client of the Cloudflare API: every request within
// HTTPTimeout, no redirect followed.
func (m *Manager) httpClient() *http.Client {
	return &http.Client{Transport: m.transport, Timeout: HTTPTimeout, CheckRedirect: noRedirects}
}

// acmeClient is the client of lego for one issuance: as httpClient, and every
// request ends when ctx does. lego makes its requests without a context, and
// its waits for the CA last minutes.
func (m *Manager) acmeClient(ctx context.Context) *http.Client {
	return &http.Client{Transport: &ctxTransport{base: m.transport, ctx: ctx}, Timeout: HTTPTimeout, CheckRedirect: noRedirects}
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ctxTransport makes a request end when ctx ends, as well as when its own
// context does. Every request registers a function on ctx, the context of the
// issuance, which lives for minutes; the registration goes as soon as the
// request is done with, whichever comes first: when it fails, when its answer
// has no body (lego never closes the bodies of its HEAD requests), when its
// body is read to its end or closed, or when the request's own context ends
// (the timeout of the client).
type ctxTransport struct {
	base http.RoundTripper
	ctx  context.Context
	// live is the number of requests whose registration is in place, for the
	// tests.
	live atomic.Int64
}

func (t *ctxTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	stop := context.AfterFunc(t.ctx, func() { cancel(context.Cause(t.ctx)) })
	t.live.Add(1)
	var once sync.Once
	release := func() {
		once.Do(func() {
			stop() // gone, whether it ran or not
			t.live.Add(-1)
			cancel(nil)
		})
	}
	// The end of the request's own context releases it as well; release
	// cancels ctx, so this registration never outlives the request.
	context.AfterFunc(ctx, release)
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		release()
		return nil, err
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		release() // nothing more of the request is read
		return resp, nil
	}
	// The body is read after RoundTrip returns: the context lives until it is
	// read to its end or closed.
	resp.Body = &releasingBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// releasingBody calls release when it is read to its end (or fails) and when
// it is closed; release runs once.
type releasingBody struct {
	io.ReadCloser
	release func()
}

func (b *releasingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.release()
	}
	return n, err
}

func (b *releasingBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// dial connects to addr for the HTTP clients. A host name is resolved with
// lookupIP (DNS-over-HTTPS unless LookupIP says otherwise), never with the
// resolver of the system, and its addresses are tried in turn.
func (m *Manager) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		if addrs, err = m.lookupIP(ctx, host); err != nil {
			return nil, fmt.Errorf("looking up %s: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("looking up %s: no address", host)
		}
	}
	d := net.Dialer{Timeout: dialTimeout}
	var errs []error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}
