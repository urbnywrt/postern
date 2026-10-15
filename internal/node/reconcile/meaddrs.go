package reconcile

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The addresses of Telegram's middle proxies (F3, Global Constraints). telemt
// does not tag its connections to them, so the edge tells them by their
// address and port (EdgeConfig.me_addrs, "ip:port") and gives them the scope
// "me". The agent reads them from getProxyConfig and getProxyConfigV6 (lines
// "proxy_for <dc> <ip>:<port>;") at its start and every six hours, and keeps
// the last good list of each in data/state/me-addrs.json: a list that cannot
// be fetched, or reads as no address, keeps the last good one. Only these
// addresses and ports are taken for middle proxies, never a datacenter's: some
// middle proxies are on the address of a datacenter, at port 8888, and a
// connection to the datacenter at its own port is not one of them.

// DefaultMEConfigURLs are the lists of Telegram's middle proxies, over IPv4
// and over IPv6.
var DefaultMEConfigURLs = []string{
	"https://core.telegram.org/getProxyConfig",
	"https://core.telegram.org/getProxyConfigV6",
}

const (
	// meEvery is how often the lists are fetched again.
	meEvery = 6 * time.Hour
	// meRetryAfter is how long a list that failed is not fetched again, from
	// the end of the fetch.
	meRetryAfter = 15 * time.Minute
	// meFirstRetryAfter is the wait instead after the first failure of a list
	// while the agent knows no middle proxy at all, a fresh node say (the
	// engines that use the middle proxy go out through the default chain of
	// their proxy until it knows them); it doubles with every failure of the
	// list, up to meRetryAfter.
	meFirstRetryAfter = time.Minute
	// maxMEBody bounds a list.
	maxMEBody = 256 << 10
)

// Event kinds of the middle-proxy lists.
const (
	evMEAddrsRefreshed = "me_addrs_refreshed"
	evMEAddrsFailed    = "me_addrs_failed"
)

// meLists is what the agent knows of the middle proxies: the addresses of each
// list ("ip:port"), by its URL, as it was last read with success, and when;
// this is the file.
type meLists struct {
	Lists   map[string][]string  `json:"lists"`
	Fetched map[string]time.Time `json:"fetched"`
}

// meListName is the name of a list in a message: the last element of its path
// (getProxyConfig), or its URL.
func meListName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return cmp.Or(path.Base(u.Path), rawURL)
}

// meState is the reconciler's memory of the lists.
type meState struct {
	loaded bool
	lists  meLists
	next   map[string]time.Time // when a list is due again
	// backoff is the wait after the next failure of a list while no middle
	// proxy is known: meFirstRetryAfter when it has none.
	backoff map[string]time.Duration
}

// addrs is every address of every list, each once, sorted: the me_addrs of the
// edge, "ip:port" (an IPv6 address in brackets).
func (m *meState) addrs() []string {
	set := map[netip.AddrPort]bool{}
	for _, list := range m.lists.Lists {
		for _, s := range list {
			if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
				set[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for _, ap := range slices.SortedFunc(maps.Keys(set), netip.AddrPort.Compare) {
		out = append(out, ap.String())
	}
	if len(out) > egress.MaxMEAddrs {
		out = out[:egress.MaxMEAddrs]
	}
	return out
}

// meURLs are the lists of the middle proxies the agent reads: MEConfigURLs, or
// DefaultMEConfigURLs when it is nil.
func (r *Reconciler) meURLs() []string {
	if r.MEConfigURLs != nil {
		return r.MEConfigURLs
	}
	return DefaultMEConfigURLs
}

// loadME reads the last good lists from the disk, once per agent process. A
// file that cannot be read is logged and taken for none.
func (r *Reconciler) loadME() {
	if r.me.loaded {
		return
	}
	r.me.loaded = true
	r.me.lists = meLists{Lists: map[string][]string{}, Fetched: map[string]time.Time{}}
	r.me.next = map[string]time.Time{}
	r.me.backoff = map[string]time.Duration{}
	data, err := os.ReadFile(r.Store.Paths.MEAddrsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var l meLists
	if err == nil {
		err = json.Unmarshal(data, &l)
	}
	if err != nil {
		r.log().Warn("the last list of the middle proxies cannot be read; it is fetched anew", "err", err)
		return
	}
	for name, list := range l.Lists {
		r.me.lists.Lists[name] = list
	}
	for name, at := range l.Fetched {
		r.me.lists.Fetched[name] = at
	}
}

// meAddrs is what the edge gets as me_addrs.
func (r *Reconciler) meAddrs() []string {
	r.loadME()
	return r.me.addrs()
}

// saveME keeps the lists on disk; a failure is logged; the lists stay in
// memory.
func (r *Reconciler) saveME() {
	data, err := json.MarshalIndent(r.me.lists, "", "  ")
	if err == nil {
		if err = os.MkdirAll(r.Store.Paths.StateDir(), 0o700); err == nil {
			err = state.WriteFileAtomic(r.Store.Paths.MEAddrsPath(), append(data, '\n'), 0o600)
		}
	}
	if err != nil {
		r.log().Warn("the list of the middle proxies cannot be kept on disk", "err", err)
	}
}

// refreshMEAddrs fetches the lists that are due: at the start of the agent,
// six hours after the last success, and fifteen minutes after the end of a
// failed fetch (while the agent knows no middle proxy at all, a minute after
// the first failure of a list, then twice as long each time). A list read
// with success is kept on disk at once. It returns only the interruption of
// the pass (a newer state, the end of the agent), which a fetch that is cut
// short gives: that is no failure of the list, which is fetched again by the
// next pass.
func (p *pass) refreshMEAddrs() error {
	r := p.r
	r.loadME()
	var fetched []string
	changed := false
	defer func() {
		if len(fetched) == 0 {
			return
		}
		all := r.me.addrs()
		r.event(evMEAddrsRefreshed, sevInfo, "",
			fmt.Sprintf("the lists of the middle proxies were read (%s): %d addresses", strings.Join(fetched, ", "), len(all)),
			map[string]string{"lists": strings.Join(fetched, ","), "addresses": strconv.Itoa(len(all)), "changed": strconv.FormatBool(changed)})
	}()
	for _, src := range r.meURLs() {
		if next, ok := r.me.next[src]; ok && r.now().Before(next) {
			continue
		}
		name := meListName(src)
		addrs, err := p.fetchME(src)
		if p.cutShort(err) {
			return err
		}
		now := r.now() // the fetch may have taken a while
		if err != nil {
			retry := meRetryAfter
			if len(r.me.addrs()) == 0 {
				retry = cmp.Or(r.me.backoff[src], meFirstRetryAfter)
				r.me.backoff[src] = min(2*retry, meRetryAfter)
			}
			r.me.next[src] = now.Add(retry)
			if r.problem("me:"+src, err.Error()) {
				r.event(evMEAddrsFailed, sevWarning, "",
					fmt.Sprintf("the list of the middle proxies %s could not be read: %v; the last good list stays", name, err),
					map[string]string{"list": name})
			}
			continue
		}
		r.clearProblem("me:" + src)
		delete(r.me.backoff, src)
		r.me.next[src] = now.Add(meEvery)
		if !slices.Equal(r.me.lists.Lists[src], addrs) {
			changed = true
		}
		r.me.lists.Lists[src] = addrs
		r.me.lists.Fetched[src] = now
		r.saveME()
		fetched = append(fetched, name)
	}
	return nil
}

// fetchME fetches a list and reads its addresses; one that reads as none is
// an error.
func (p *pass) fetchME(src string) ([]string, error) {
	body, err := p.fetch(src, maxMEBody)
	if err != nil {
		return nil, err
	}
	addrs, skipped := parseProxyConfig(body)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address of a middle proxy in it (%d lines could not be read)", skipped)
	}
	return addrs, nil
}

// parseProxyConfig reads the addresses of the middle proxies of a list of
// Telegram's (getProxyConfig): the lines "proxy_for <dc> <ip>:<port>;", an
// IPv6 address in brackets. It returns each address and port once, sorted, as
// "ip:port", and the number of proxy_for lines it could not read (an address
// that cannot be a middle proxy's, the loopback say, among them). Other lines
// are no business of it.
func parseProxyConfig(body []byte) (addrs []string, skipped int) {
	set := map[netip.AddrPort]bool{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 4096), maxMEBody)
	for sc.Scan() {
		f := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(f) == 0 || f[0] != "proxy_for" {
			continue
		}
		ap, ok := proxyForAddr(f)
		if !ok {
			skipped++
			continue
		}
		set[ap] = true
	}
	for _, ap := range slices.SortedFunc(maps.Keys(set), netip.AddrPort.Compare) {
		addrs = append(addrs, ap.String())
	}
	return addrs, skipped
}

// proxyForAddr reads the address and port of a proxy_for line, split into
// fields.
func proxyForAddr(f []string) (netip.AddrPort, bool) {
	// "proxy_for <dc> <ip>:<port>;", the semicolon at the address or apart.
	if len(f) != 3 && (len(f) != 4 || f[3] != ";") {
		return netip.AddrPort{}, false
	}
	if _, err := strconv.ParseInt(f[1], 10, 16); err != nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(strings.TrimSuffix(f[2], ";"))
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	a := ap.Addr().Unmap()
	if a.Zone() != "" || !a.IsGlobalUnicast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, ap.Port()), true
}
