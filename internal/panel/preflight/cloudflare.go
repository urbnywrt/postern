package preflight

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/webrules"
)

// The published lists of the addresses of Cloudflare.
const (
	CloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	CloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
)

// embeddedCloudflare are the ranges as published when this version was
// built: the answer of CloudflareIPv4URL and CloudflareIPv6URL. Refresh
// replaces them with the current lists.
var embeddedCloudflare = webrules.CloudflareRanges

// maxList bounds what Refresh reads of a list.
const maxList = 64 * 1024

// refreshTimeout bounds a whole refresh; minRanges is the fewest ranges that a
// refreshed list may have (Cloudflare publishes about twenty).
const (
	refreshTimeout = 30 * time.Second
	minRanges      = 5
)

// CloudflareRanges are the addresses of Cloudflare's proxy: a domain that
// resolves to one of them is behind the orange cloud. They start as the
// embedded list and can be refreshed from the published one.
type CloudflareRanges struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
}

// DefaultCloudflareRanges returns the embedded ranges.
func DefaultCloudflareRanges() *CloudflareRanges {
	ps, err := parsePrefixes(strings.NewReader(strings.Join(embeddedCloudflare, "\n")))
	if err != nil {
		panic("preflight: embedded cloudflare ranges: " + err.Error()) // a constant of this file
	}
	return &CloudflareRanges{prefixes: ps}
}

// Contains reports whether addr is in the ranges.
func (r *CloudflareRanges) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Len is how many prefixes there are.
func (r *CloudflareRanges) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.prefixes)
}

// Refresh fetches the lists at urls (CloudflareIPv4URL and CloudflareIPv6URL
// by default) with client and replaces the ranges with what they say. A list
// that cannot be fetched or read, or that is empty, leaves the ranges as they
// were, with an error.
func (r *CloudflareRanges) Refresh(ctx context.Context, client *http.Client, urls ...string) error {
	if len(urls) == 0 {
		urls = []string{CloudflareIPv4URL, CloudflareIPv6URL}
	}
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	var all []netip.Prefix
	for _, u := range urls {
		ps, err := fetchPrefixes(ctx, client, u)
		if err != nil {
			return fmt.Errorf("preflight: refresh the cloudflare ranges: %w", err)
		}
		all = append(all, ps...)
	}
	if len(all) < minRanges {
		return fmt.Errorf("preflight: refresh the cloudflare ranges: only %d ranges, at least %d expected", len(all), minRanges)
	}
	r.set(all)
	return nil
}

// set replaces the ranges.
func (r *CloudflareRanges) set(ps []netip.Prefix) {
	r.mu.Lock()
	r.prefixes = ps
	r.mu.Unlock()
}

// strings returns the ranges as text, for the settings store.
func (r *CloudflareRanges) strings() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.prefixes))
	for i, p := range r.prefixes {
		out[i] = p.String()
	}
	return out
}

func fetchPrefixes(ctx context.Context, client *http.Client, u string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	sameHost := *client
	prev := sameHost.CheckRedirect
	sameHost.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Host != via[0].URL.Host {
			return errors.New("the list redirects to another host")
		}
		if prev != nil {
			return prev(r, via)
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	resp, err := sameHost.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxList+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	if len(data) > maxList {
		return nil, fmt.Errorf("%s: the list is larger than %d bytes", u, maxList)
	}
	ps, err := parsePrefixes(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	return ps, nil
}

// parsePrefixes reads one prefix per line; blank lines are skipped, any other
// line that is no prefix fails the whole list. An empty list is an error.
func parsePrefixes(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %.40q is not a prefix", line)
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
			return nil, fmt.Errorf("line %.40q is implausibly wide for a Cloudflare range", line)
		}
		out = append(out, p.Masked())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the list is empty")
	}
	return out, nil
}
