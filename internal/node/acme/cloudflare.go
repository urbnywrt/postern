package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// cloudflareAPI is the base URL of version 4 of the Cloudflare API.
const cloudflareAPI = "https://api.cloudflare.com/client/v4"

const (
	// TXTTTL is the TTL of the TXT records of the challenges, in seconds: a
	// resolver that saw the record of an earlier
	// attempt forgets it within a minute.
	TXTTTL = 60
	// maxCloudflareBody bounds an answer of the API.
	maxCloudflareBody = 1 << 20
	// maxCloudflareErrors and maxCloudflareMessage bound what an error quotes
	// of an answer of the API.
	maxCloudflareErrors  = 3
	maxCloudflareMessage = 160
	// cloudflarePageSize is the page of a listing of records, and
	// maxCloudflarePages how many pages are read at the most.
	cloudflarePageSize = 100
	maxCloudflarePages = 100
)

// DNSProvider writes the TXT records of the DNS-01 challenges of domains. Its
// errors never hold the credential it was made with.
type DNSProvider interface {
	// RemoveStale deletes every TXT record at _acme-challenge.<domain>: what
	// earlier attempts left there. It deletes nothing else.
	RemoveStale(ctx context.Context, domain string) error
	// Present writes the TXT record _acme-challenge.<domain> with value.
	Present(ctx context.Context, domain, value string) error
	// CleanUp deletes the record Present wrote for domain and value, and
	// nothing else; without one it does nothing.
	CleanUp(ctx context.Context, domain, value string) error
}

// cloudflare is the DNSProvider of Cloudflare, through its API, with an API
// token that has the permission Zone:DNS:Edit. The zone of a domain is the one named by the longest suffix
// of the domain that the token sees: the domain itself, then the domain
// without its first label, and so on down to two labels. It is looked up once
// per provider, and the provider is made for one issuance.
type cloudflare struct {
	cred   Credential
	base   string // the base URL of the API, without the slash at its end
	client *http.Client

	mu      sync.Mutex
	zones   map[string]string   // domain → the ID of its zone
	records map[string][]string // domain and value → the IDs of the records Present made
}

func newCloudflare(cred Credential, client *http.Client, base string) *cloudflare {
	return &cloudflare{
		cred:    cred,
		base:    strings.TrimSuffix(base, "/"),
		client:  client,
		zones:   map[string]string{},
		records: map[string][]string{},
	}
}

// cfRecord is a DNS record as the API has it.
type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
}

// cfZone is a zone as the API has it.
type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// cfEnvelope is an answer of the API.
type cfEnvelope struct {
	Success *bool           `json:"success"`
	Errors  []cfMessage     `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// cfMessage is an error the API reports.
type cfMessage struct {
	Code       int         `json:"code"`
	Message    string      `json:"message"`
	ErrorChain []cfMessage `json:"error_chain"`
}

func (c *cloudflare) RemoveStale(ctx context.Context, domain string) error {
	zone, err := c.zone(ctx, domain)
	if err != nil {
		return err
	}
	name := challengeName(domain)
	// Every page first, then the deletions: deleting while paging would move
	// records to pages already read.
	var recs []cfRecord
	for page := 1; ; page++ {
		if page > maxCloudflarePages {
			return fmt.Errorf("cloudflare: listing the TXT records: more than %d pages", maxCloudflarePages)
		}
		var batch []cfRecord
		q := url.Values{"type": {"TXT"}, "name": {name}, "per_page": {strconv.Itoa(cloudflarePageSize)}, "page": {strconv.Itoa(page)}}
		if err := c.do(ctx, "listing the TXT records", http.MethodGet, "/zones/"+zone+"/dns_records", q, nil, &batch); err != nil {
			return err
		}
		recs = append(recs, batch...)
		if len(batch) < cloudflarePageSize { // a short page is the last one
			break
		}
	}
	for _, r := range recs {
		// The API filters by type and name already; the record is looked at
		// all the same: no record but a TXT record at that very name is ever
		// deleted.
		if !strings.EqualFold(r.Type, "TXT") || !sameName(r.Name, name) {
			continue
		}
		if err := c.deleteRecord(ctx, zone, r.ID); err != nil {
			return err
		}
	}
	return nil
}

func (c *cloudflare) Present(ctx context.Context, domain, value string) error {
	zone, err := c.zone(ctx, domain)
	if err != nil {
		return err
	}
	var rec cfRecord
	// The content in quotes, as lego writes it: Cloudflare stores the value
	// as one string, the one the CA reads.
	body := cfRecord{Type: "TXT", Name: challengeName(domain), Content: `"` + value + `"`, TTL: TXTTTL}
	if err := c.do(ctx, "creating the TXT record", http.MethodPost, "/zones/"+zone+"/dns_records", nil, body, &rec); err != nil {
		return err
	}
	if !validID(rec.ID) {
		return errors.New("cloudflare: creating the TXT record: the answer has no record ID")
	}
	c.mu.Lock()
	k := recordKey(domain, value)
	c.records[k] = append(c.records[k], rec.ID)
	c.mu.Unlock()
	return nil
}

func (c *cloudflare) CleanUp(ctx context.Context, domain, value string) error {
	k := recordKey(domain, value)
	c.mu.Lock()
	ids := c.records[k]
	delete(c.records, k)
	zone := c.zones[domain]
	c.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := c.deleteRecord(ctx, zone, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// zone returns the ID of the zone of domain.
func (c *cloudflare) zone(ctx context.Context, domain string) (string, error) {
	c.mu.Lock()
	id, ok := c.zones[domain]
	c.mu.Unlock()
	if ok {
		return id, nil
	}
	labels := strings.Split(domain, ".")
	for i := 0; i+2 <= len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		var zones []cfZone
		q := url.Values{"name": {name}, "per_page": {"50"}}
		if err := c.do(ctx, "looking for the zone", http.MethodGet, "/zones", q, nil, &zones); err != nil {
			return "", err
		}
		// Only an active zone answers for its names: a pending or moved one
		// of the same name does not, and neither does it for a shorter suffix.
		var active []cfZone
		for _, z := range zones {
			if sameName(z.Name, name) && strings.EqualFold(z.Status, "active") {
				active = append(active, z)
			}
		}
		switch {
		case len(active) == 0:
			continue
		case len(active) > 1:
			return "", fmt.Errorf("cloudflare: the token sees %d active zones named %s; it must see one", len(active), name)
		case !validID(active[0].ID):
			return "", fmt.Errorf("cloudflare: the zone %s has no valid ID", name)
		}
		c.mu.Lock()
		c.zones[domain] = active[0].ID
		c.mu.Unlock()
		return active[0].ID, nil
	}
	return "", fmt.Errorf("cloudflare: no active zone that the token sees holds %s", domain)
}

// deleteRecord deletes a record of a zone by its ID. A record that is gone
// already is fine.
func (c *cloudflare) deleteRecord(ctx context.Context, zone, id string) error {
	if !validID(zone) || !validID(id) {
		return errors.New("cloudflare: deleting a TXT record: not a valid zone or record ID")
	}
	err := c.do(ctx, "deleting a TXT record", http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil, nil)
	var se *cfStatusError
	if errors.As(err, &se) && se.status == http.StatusNotFound {
		return nil
	}
	return err
}

// cfStatusError is an answer of the API that is not a success.
type cfStatusError struct {
	op     string
	status int
	detail string
}

func (e *cfStatusError) Error() string {
	msg := "cloudflare: " + e.op + ": HTTP " + strconv.Itoa(e.status)
	if e.detail != "" {
		msg += ": " + e.detail
	}
	return msg
}

// do makes a request to the API and decodes the result of its answer into
// result, unless that is nil. Its errors name the operation op, never the URL,
// and never hold the token: what the API says is quoted with the token taken
// out.
func (c *cloudflare) do(ctx context.Context, op, method, path string, query url.Values, body, result any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cloudflare: %s: %w", op, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("cloudflare: %s: not a URL of the API", op)
	}
	req.Header.Set("Authorization", "Bearer "+c.cred.token())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		// The *url.Error of the client quotes the URL: only what it wraps is kept.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("cloudflare: %s: %s", op, c.cred.scrub(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudflareBody+1))
	if err != nil {
		return fmt.Errorf("cloudflare: %s: reading the answer: %s", op, c.cred.scrub(err.Error()))
	}
	if len(raw) > maxCloudflareBody {
		return fmt.Errorf("cloudflare: %s: the answer is longer than %d bytes", op, maxCloudflareBody)
	}
	var env cfEnvelope
	jsonErr := json.Unmarshal(raw, &env)
	if resp.StatusCode/100 != 2 || (jsonErr == nil && env.Success != nil && !*env.Success) {
		return &cfStatusError{op: op, status: resp.StatusCode, detail: env.describe(c.cred)}
	}
	if jsonErr != nil {
		return fmt.Errorf("cloudflare: %s: the answer is not JSON", op)
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(env.Result, result); err != nil {
		return fmt.Errorf("cloudflare: %s: the result is not what was asked for", op)
	}
	return nil
}

// describe is what the errors of an answer say: their codes and messages, on
// one line, without the credential (taken out before a message is shortened,
// so that no part of it is left), shortened.
func (e cfEnvelope) describe(cred Credential) string {
	text := func(m cfMessage) string {
		return strconv.Itoa(m.Code) + " " + oneLine(cred.scrub(m.Message), maxCloudflareMessage)
	}
	var parts []string
	for _, m := range e.Errors {
		if len(parts) == maxCloudflareErrors {
			break
		}
		s := text(m)
		for i, link := range m.ErrorChain {
			if i == maxCloudflareErrors {
				break
			}
			s += "; " + text(link)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// recordKey is the key of the records of a domain and a value.
func recordKey(domain, value string) string { return domain + "\x00" + value }

// sameName reports whether two DNS names are the same, in any case and with
// or without the dot at the end.
func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// validID reports whether s can be the ID of a zone or a record in the path of
// a URL: Cloudflare's are 32 hexadecimal digits.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
