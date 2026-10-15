package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/urbnywrt/postern/internal/doh"
)

// defaultPropagationEndpoints are the providers at which the TXT record of a
// challenge must be visible, at both, before the CA is asked to look at it
// (Global Constraints): Cloudflare and Google, by the DNS-over-HTTPS endpoints
// of their two addresses each. Each provider is asked through a client of its
// own, which goes to the second address of the provider when the first fails
// (internal/doh: an error, not an answer that the name or the value is not
// there), and never to the other provider: "visible at both" keeps its
// meaning, and a node that cannot reach one address of a provider still
// checks. A new copy each time: nothing can change them.
func defaultPropagationEndpoints() [][]string {
	return [][]string{
		{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"},
		{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"},
	}
}

const (
	// PropagationTimeout is how long the TXT record of a challenge may take to
	// be visible at every resolver, from the moment it was written.
	PropagationTimeout = 120 * time.Second
	// FirstPollAfter is how long after the record was written the resolvers
	// are asked first: a resolver that asks before the authoritative servers
	// of the zone all have the record keeps the answer that there is no such
	// name for the negative TTL of the zone (the minimum of its SOA), which
	// can be longer than the whole wait.
	FirstPollAfter = 10 * time.Second
	// PollInterval is how often they are asked after that.
	PollInterval = 5 * time.Second
)

// resolver is a resolver at which the record must be visible, and its name in
// messages.
type resolver struct {
	name string
	// lookup returns the TXT records of a name: (*doh.Client).LookupTXT.
	lookup func(ctx context.Context, name string) ([]string, error)
}

// checker tells whether every one of its resolvers sees a TXT value. They are
// asked at the same time. It never asks the resolver of the system.
type checker struct {
	resolvers []resolver
}

// newChecker returns the checker of providers, each a group of DNS-over-HTTPS
// endpoints asked through a client of its own, named by the hosts of its
// endpoints. Their certificates are verified against roots, nil being the
// roots of the system.
func newChecker(groups [][]string, roots *x509.CertPool) *checker {
	c := &checker{}
	for _, group := range groups {
		var cl *doh.Client
		if roots == nil {
			cl = doh.New(group)
		} else {
			cl = doh.NewWithRoots(group, roots)
		}
		names := make([]string, len(group))
		for i, ep := range group {
			names[i] = endpointName(ep)
		}
		c.resolvers = append(c.resolvers, resolver{name: strings.Join(names, "/"), lookup: cl.LookupTXT})
	}
	return c
}

// endpointName is what a message calls an endpoint: its host.
func endpointName(ep string) string {
	if u, err := url.Parse(ep); err == nil && u.Host != "" {
		return u.Host
	}
	return ep
}

// notVisible is the answer of the resolvers that do not see the value yet:
// one error for each, in the order of the resolvers.
type notVisible []error

func (e notVisible) Error() string {
	parts := make([]string, len(e))
	for i, err := range e {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

func (e notVisible) Unwrap() []error { return e }

// visible returns nil when every resolver has value among the TXT records of
// name, and otherwise a notVisible that says, for each resolver that does not,
// why.
func (c *checker) visible(ctx context.Context, name, value string) error {
	errs := make([]error, len(c.resolvers))
	var wg sync.WaitGroup
	for i, r := range c.resolvers {
		wg.Go(func() { errs[i] = r.sees(ctx, name, value) })
	}
	wg.Wait()
	var nv notVisible
	for _, err := range errs {
		if err != nil {
			nv = append(nv, err)
		}
	}
	if len(nv) == 0 {
		return nil
	}
	return nv
}

// sees returns nil when the resolver has value among the TXT records of name.
// A name that does not exist yet is not an error of the resolver: the record
// is not visible there yet.
func (r resolver) sees(ctx context.Context, name, value string) error {
	txts, err := r.lookup(ctx, name)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return fmt.Errorf("%s: no record at %s yet", r.name, name)
	case err != nil:
		return fmt.Errorf("%s: %w", r.name, err)
	case slices.Contains(txts, value):
		return nil
	case len(txts) == 0:
		return fmt.Errorf("%s: no TXT record at %s yet", r.name, name)
	default:
		return fmt.Errorf("%s: the TXT records at %s do not hold the value yet", r.name, name)
	}
}

// precheck is the propagation check of one issuance for lego (it replaces
// lego's own, which asks nameservers over UDP port 53): it asks the resolvers
// of the checker whether they see the value at _acme-challenge.<domain>, where
// the DNS provider wrote it. Its first call waits until firstPoll after the
// record was written, as written tells it (zero: unknown, from the first
// call); lego calls it again every PollInterval until it says stop. It says
// stop when the value is visible, when ctx ends (with the error of ctx), and
// when the value was not visible within timeout from the writing of the
// record (with the error of that).
func (c *checker) precheck(ctx context.Context, timeout, firstPoll time.Duration, written func(domain string) time.Time) dns01.WrapPreCheckFunc {
	var start time.Time // lego calls the check from one goroutine, one call after the other
	return func(domain, _, value string, _ dns01.PreCheckFunc) (bool, error) {
		if start.IsZero() {
			if written != nil {
				start = written(domain)
			}
			if start.IsZero() {
				start = time.Now()
			}
			if !sleep(ctx, time.Until(start.Add(firstPoll))) {
				return true, ctx.Err()
			}
		}
		deadline := start.Add(timeout)
		if err := ctx.Err(); err != nil {
			return true, err
		}
		name := challengeName(domain)
		err := c.visible(ctx, name, value)
		switch {
		case err == nil:
			return true, nil
		case ctx.Err() != nil:
			return true, ctx.Err()
		case !time.Now().Before(deadline):
			return true, fmt.Errorf("the TXT record %s was not visible at every resolver within %s: %w", name, timeout, err)
		}
		return false, err
	}
}

// challengeName is the name of the TXT record of a DNS-01 challenge for
// domain (RFC 8555 8.4).
func challengeName(domain string) string { return "_acme-challenge." + domain }
