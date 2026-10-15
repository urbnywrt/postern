package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers"
)

// The subscriptions of the XRAY_SUBSCRIPTION egresses (Global Constraints):
// the agent fetches one when its egress is needed and it has none from the URL
// of the egress, when the panel asks for it (Egress.refresh_nonce, Ruling
// S2-17), and then every six hours; first directly, then through each member
// of the node's default chain that the edge reports up. A fetch that fails
// keeps what the cache has and is tried again after a while. The body is
// cached as it came in the directory of the egress (subscription.txt, 0600,
// the agent's alone), and read with egressuri.ParseSubscription.
//
// A fetch holds the reconcile worker, so it is bounded: the direct route and
// three members of the default chain at the most, 15 s each and a minute in
// all, and a newer desired state cuts it short between two routes.

const (
	subscriptionFile = "subscription.txt"
	// subscriptionEvery is how often a subscription is fetched again.
	subscriptionEvery = 6 * time.Hour
	// subscriptionRetryAfter is how long a subscription whose fetch failed is
	// not fetched again, from the end of the fetch.
	subscriptionRetryAfter = 10 * time.Minute
	// maxSubscriptionBody bounds a subscription.
	maxSubscriptionBody = 1 << 20

	// fetchTimeout bounds a fetch of the agent's own: a subscription or a
	// middle-proxy list, by one route.
	fetchTimeout = 15 * time.Second
	// defaultFetchBudget bounds a fetch by all its routes.
	defaultFetchBudget = time.Minute
	// fetchMembers is how many members of the default chain a fetch tries at
	// the most, after the direct route.
	fetchMembers = 3
	// fetchUserAgent is what the agent's fetches say they are.
	fetchUserAgent = "Mozilla/5.0"
	// maxRedirects bounds the redirects of a fetch.
	maxRedirects = 5
)

// Event kinds of the subscriptions.
const (
	evSubscriptionRefreshed = "subscription_refreshed"
	evSubscriptionFailed    = "subscription_failed"
)

// dialFunc makes a connection, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// subKey is what a failed fetch of a subscription is remembered by: the
// egress, the hash of its URL and its refresh nonce. A corrected URL, or a new
// request of the operator, is fetched at once.
type subKey struct {
	id, url string
	nonce   uint64
}

// refreshLists fetches what is due of the lists the agent keeps: the
// middle-proxy addresses and the subscriptions of the needed egresses. A list
// that cannot be fetched is reported and the pass goes on; it returns only the
// interruption of the pass, by a newer state or the end of the agent.
func (p *pass) refreshLists() error {
	if err := p.refreshMEAddrs(); err != nil {
		return err
	}
	needed := neededEgresses(p.st)
	current := map[subKey]bool{}
	for _, id := range slices.Sorted(maps.Keys(needed)) {
		e := needed[id]
		if e.GetKind() != nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION {
			continue
		}
		params, err := state.ParseSubscriptionParams(e.GetParamsJson())
		if err != nil {
			continue // the state validates: cannot happen
		}
		key := subKey{id: id, url: urlHash(params.URL), nonce: e.GetRefreshNonce()}
		current[key] = true
		if err := p.refreshSubscription(e, params, key); err != nil {
			return err
		}
	}
	for key := range p.r.subRetry {
		if !current[key] {
			delete(p.r.subRetry, key)
		}
	}
	return nil
}

func (p *pass) subscriptionPath(id string) string {
	return filepath.Join(p.r.Store.Paths.EgressDir(id), subscriptionFile)
}

// urlHash is how the record knows a URL that may hold a token.
func urlHash(u string) string {
	sum := sha256.Sum256([]byte(u))
	return hex.EncodeToString(sum[:])
}

// refreshSubscription fetches the subscription of an egress when it is due: it
// has none from its URL, the panel asked for a refresh (another refresh nonce
// than the one of the last fetch), or the one it has is six hours old; not
// while a failure of the same URL and nonce is recent. A subscription fetched
// is in the runtime record at once, whatever becomes of the pass. It returns
// only the interruption of the pass.
func (p *pass) refreshSubscription(e *nodev1.Egress, params state.SubscriptionParams, key subKey) error {
	id := e.GetId()
	rec := p.rt.Egresses[id]
	_, statErr := os.Stat(p.subscriptionPath(id))
	cached := statErr == nil && rec.SubscriptionURL == key.url
	if cached && rec.SubscriptionNonce == key.nonce && p.r.now().Sub(rec.SubscriptionFetched) < subscriptionEvery {
		return nil
	}
	if next, ok := p.r.subRetry[key]; ok && p.r.now().Before(next) {
		return nil
	}

	fail := func(reason string) {
		p.r.subRetry[key] = p.r.now().Add(subscriptionRetryAfter) // from the end of the fetch
		have := "the egress has no servers yet"
		if cached {
			have = "the servers fetched before stay"
		}
		if p.r.problem("sub:"+id, reason) {
			p.r.event(evSubscriptionFailed, sevWarning, "",
				fmt.Sprintf("egress %s: the subscription could not be fetched: %s; %s", id, reason, have),
				map[string]string{"egress": id})
		}
	}
	body, err := p.fetch(params.URL, maxSubscriptionBody)
	if p.cutShort(err) {
		return err
	}
	if err != nil {
		fail(err.Error())
		return nil
	}
	servers, lineErrs := egressuri.ParseSubscription(body)
	if len(servers) == 0 {
		fail(fmt.Sprintf("no server could be read from it (%d lines failed)", len(lineErrs)))
		return nil
	}
	if err := ensurePrivateDir(p.r.Store.Paths.EgressDir(id)); err != nil {
		fail("caching it: " + err.Error())
		return nil
	}
	if err := state.WriteFileAtomic(p.subscriptionPath(id), body, 0o600); err != nil {
		fail("caching it: " + err.Error())
		return nil
	}
	delete(p.r.subRetry, key)
	p.r.clearProblem("sub:" + id)
	rec.SubscriptionFetched, rec.SubscriptionURL, rec.SubscriptionNonce = p.r.now(), key.url, key.nonce
	p.rt.Egresses[id] = rec
	if err := p.saveRuntime(); err != nil {
		// The pass saves the record again when it ends.
		p.r.log().Warn("the runtime record cannot be saved", "err", err)
	}
	p.r.event(evSubscriptionRefreshed, sevInfo, "",
		fmt.Sprintf("egress %s: subscription fetched: %d servers, %d lines that could not be read", id, len(servers), len(lineErrs)),
		map[string]string{"egress": id, "servers": strconv.Itoa(len(servers)), "failed_lines": strconv.Itoa(len(lineErrs))})
	return nil
}

// subscriptionMembers are the members of an XRAY_SUBSCRIPTION egress: the
// servers of its cached subscription that its selection takes, in its order,
// each once.
func (p *pass) subscriptionMembers(e *nodev1.Egress) ([]providers.Member, error) {
	params, err := state.ParseSubscriptionParams(e.GetParamsJson())
	if err != nil {
		return nil, err
	}
	rec := p.rt.Egresses[e.GetId()]
	if rec.SubscriptionURL != urlHash(params.URL) {
		return nil, errors.New("the subscription has not been fetched yet")
	}
	body, err := os.ReadFile(p.subscriptionPath(e.GetId()))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("the subscription has not been fetched yet")
	}
	if err != nil {
		return nil, fmt.Errorf("the cached subscription: %w", err)
	}
	servers, _ := egressuri.ParseSubscription(body)
	var picked []*egressuri.Server
	for _, s := range servers {
		if params.Select.Matches(s.Name) {
			picked = append(picked, s)
			if params.Select.Mode == state.SelectFirst {
				break
			}
		}
	}
	members := serversToMembers(picked)
	if len(members) == 0 {
		return nil, fmt.Errorf("no server of the subscription is selected (select %s)", selectText(params.Select))
	}
	return members, nil
}

func selectText(s state.Select) string {
	if s.Mode == state.SelectName {
		return fmt.Sprintf("name:%.40q", s.Name)
	}
	return s.Mode
}

// ---- fetching -----------------------------------------------------------------

// fetchRoute is a way for the agent to fetch something: directly, or through a
// member of a chain.
type fetchRoute struct {
	name string
	dial dialFunc
}

// cutShort reports whether err is the end of a fetch that the pass cut short:
// a newer state waits, or the agent stops. That is no failure of what was
// fetched.
func (p *pass) cutShort(err error) bool {
	return err != nil && (errors.Is(err, errInterrupted) || p.ctx.Err() != nil)
}

// fetch gets rawURL (http or https) by the first route that works: directly,
// then through the members of the node's default chain that the edge reports
// up, in the order of the chain, three at the most; a route has 15 s and all
// of them a minute. Before each route it takes a newer state (boundary), which
// ends the fetch with errInterrupted. It returns a body of at most max bytes
// of an answer 2xx. No error holds the URL, which may hold a token.
func (p *pass) fetch(rawURL string, max int64) ([]byte, error) {
	budget := orDefault(p.r.fetchBudget, defaultFetchBudget)
	ctx, cancel := context.WithTimeout(p.ctx, budget)
	defer cancel()
	var errs []string
	for _, rt := range p.fetchRoutes() {
		if err := p.boundary(); err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			errs = append(errs, fmt.Sprintf("%s: not tried, the fetch had its %v", rt.name, budget))
			break
		}
		body, err := p.r.get(ctx, rt.dial, rawURL, max)
		if err == nil {
			return body, nil
		}
		if p.ctx.Err() != nil {
			return nil, p.ctx.Err()
		}
		errs = append(errs, rt.name+": "+err.Error())
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// fetchRoutes are the routes of a fetch: directly first, then the members of
// the default chain that are up, as the edge has them now, fetchMembers of
// them at the most.
func (p *pass) fetchRoutes() []fetchRoute {
	routes := []fetchRoute{{name: "directly", dial: p.r.directDialer()}}
	def := p.st.GetSettings().GetDefaultChainId()
	if def == "" {
		return routes
	}
	up := map[string]bool{}
	for _, h := range p.r.egressHealth() {
		if h.GetChainId() == def && h.GetStatus() == "up" {
			up[h.GetMemberKey()] = true
		}
	}
	var chain *edgev1.Chain
	for _, c := range buildEdgeConfig(p.st, p.rt, p.edgeGen, nil).GetChains() {
		if c.GetId() == def {
			chain = c
		}
	}
	for _, m := range chain.GetMembers() {
		if len(routes) > fetchMembers {
			break
		}
		if !up[m.GetKey()] {
			continue
		}
		d, err := egress.NewMemberDialerWithResolver(m, fetchTimeout, p.r.Resolver)
		if err != nil {
			continue
		}
		routes = append(routes, fetchRoute{name: "through " + m.GetKey(), dial: d.DialContext})
	}
	return routes
}

// directDialer is how the agent connects by itself: with its resolver, which
// asks the edge's DNS forwarder while it runs, and to public addresses only
// (publicDialer): a subscription's server, its redirect or its DNS cannot send
// the agent to loopback, the metadata service or the provider's LAN.
func (r *Reconciler) directDialer() dialFunc {
	if r.dialDirect != nil {
		return r.dialDirect
	}
	return r.publicDialer(fetchTimeout, r.fetchAllowDial).DialContext
}

// errFetchURL refuses a redirect of a fetch to a url that is not http(s) or
// that carries credentials.
var errFetchURL = errors.New("a fetch follows http and https urls without credentials only")

// get makes one GET of rawURL through dial and returns the body of a 2xx
// answer of at most max bytes, in 15 s at the most. The client takes no proxy
// from the environment, follows a few redirects, and says it is Mozilla/5.0.
// No error holds the URL.
func (r *Reconciler) get(ctx context.Context, dial dialFunc, rawURL string, max int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: fetchTimeout,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return checkURL(req.URL.String(), true, errFetchURL)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("not a URL that can be fetched")
	}
	req.Header.Set("User-Agent", fetchUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fetchError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading the answer: %w", fetchError(err))
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("the answer is larger than %d bytes", max)
	}
	return body, nil
}

// fetchError is err without the URL that a *url.Error names: the URL of a
// subscription may hold a token.
func fetchError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
