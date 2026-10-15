package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/release"
)

// The commands of the job of the stable list (.github/workflows/stable.yml,
// scripts/stable.sh, docs/releasing.md): candidates finds the upstream
// releases that the end-to-end tests are to try, stable-add puts those that
// passed into the list, stable-sign dates and signs it. The list is
// engines-stable.json (Global Constraints): the components and, for each, the
// versions that passed, with the file and the SHA-256 of each architecture.

const (
	envGitHubAPI   = "POSTERN_GITHUB_API" // the API of GitHub that candidates reads; its default when empty
	envGitHubToken = "GITHUB_TOKEN"       //nolint:gosec // G101: the name of the variable that holds a token for the API, optional

	stableSchema     = 1
	componentStable  = "engines-stable"
	maxStableList    = 1 << 20   // the list, as the panel reads it
	maxSumsFile      = 64 << 10  // a checksum file
	maxArchive       = 200 << 20 // a release archive
	candidateTimeout = 30 * time.Minute
)

// stableList is engines-stable.json.
type stableList struct {
	Schema      int                      `json:"schema"`
	GeneratedAt int64                    `json:"generated_at"`
	Components  map[string][]stableEntry `json:"components"`
}

// stableEntry is one version of a component in the list.
type stableEntry struct {
	Version string                 `json:"version"`
	Assets  map[string]stableAsset `json:"assets"`
}

// stableAsset is the file of a version for one architecture.
type stableAsset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// candidate is an upstream release that passed the checks of candidates: what
// stable-add takes once the end-to-end tests passed on it.
type candidate struct {
	Component string `json:"component"`
	stableEntry
}

// skipped is a release newer than the stable ones that failed a check.
type skipped struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
}

// candidatesFile is what candidates writes.
type candidatesFile struct {
	Candidates []candidate `json:"candidates"`
	Skipped    []skipped   `json:"skipped"`
}

// readStableList reads the list at path; a path of "" or a file that is not
// there is the empty list (the job before its first list).
func readStableList(path string) (*stableList, error) {
	l := &stableList{Schema: stableSchema, Components: map[string][]stableEntry{}}
	if path == "" || !present(path) {
		return l, nil
	}
	data, err := readSmall(path, maxStableList)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, l); err != nil {
		return nil, fmt.Errorf("%s is not a stable list: %w", path, err)
	}
	if l.Schema != stableSchema {
		return nil, fmt.Errorf("%s is a stable list of schema %d, not %d", path, l.Schema, stableSchema)
	}
	if l.Components == nil {
		l.Components = map[string][]stableEntry{}
	}
	return l, nil
}

// marshal returns the list as the job publishes it: indented, with a newline.
func (l *stableList) marshal() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// newestStable returns the newest stable version of the component: of the
// versions built into the panel and those of the list.
func newestStable(l *stableList, component string) string {
	newest := ""
	consider := func(v string) {
		if newest == "" || release.Compare(v, newest) > 0 {
			newest = v
		}
	}
	for _, b := range releases.Builtins() {
		if b.Component == component {
			consider(b.Version)
		}
	}
	for _, e := range l.Components[component] {
		consider(e.Version)
	}
	return newest
}

// checkEntry checks a version of a component as the list holds it: a valid
// version, and a file and a SHA-256 for every architecture.
func checkEntry(component string, e stableEntry) error {
	if _, ok := releases.ComponentOf(component); !ok {
		return fmt.Errorf("%.40q is no component of the panel", component)
	}
	if !release.ValidVersion(e.Version) {
		return fmt.Errorf("%s %.40q is not a version", component, e.Version)
	}
	for _, arch := range arches {
		a, ok := e.Assets[arch]
		switch {
		case !ok:
			return fmt.Errorf("%s %s has no asset for %s", component, e.Version, arch)
		case !plainName(a.File):
			return fmt.Errorf("%s %s: the file %.70q of %s is not a plain name", component, e.Version, a.File, arch)
		case len(a.SHA256) != 64 || !isHex(a.SHA256, 64, 64) || strings.ToLower(a.SHA256) != a.SHA256:
			return fmt.Errorf("%s %s: the SHA-256 of %s is not 64 lower-case hex digits", component, e.Version, arch)
		}
	}
	if len(e.Assets) != len(arches) {
		return fmt.Errorf("%s %s has assets of other architectures than %s", component, e.Version, strings.Join(arches, " and "))
	}
	return nil
}

// ---- candidates ---------------------------------------------------------------

// candidates finds, for each component, the newest upstream release that is
// newer than its newest stable version and passes the checks: see usageText.
func (c *cli) candidates(args []string) error {
	set := flags("candidates")
	stable := set.String("stable", "", "")
	out := set.String("out", "", "")
	var only listFlag
	set.Var(&only, "component", "")
	if _, err := parse(set, args, 0); err != nil {
		return err
	}
	if *out == "" {
		return usagef("--out is missing")
	}
	for _, name := range only {
		if _, ok := releases.ComponentOf(name); !ok {
			return usagef("--component %q: the components are %s", name, componentNames())
		}
	}
	list, err := readStableList(*stable)
	if err != nil {
		return err
	}
	api := cmp.Or(strings.TrimSpace(c.getenv(envGitHubAPI)), releases.DefaultGitHubAPI)
	ctx, cancel := context.WithTimeout(context.Background(), candidateTimeout)
	defer cancel()
	tmp, err := os.MkdirTemp("", "postern-candidates-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	f := candidatesFile{Candidates: []candidate{}, Skipped: []skipped{}}
	hc := releases.NewHTTPClient()
	lim := releases.NewLimiter(nil)
	for _, comp := range releases.Components {
		if len(only) > 0 && !slices.Contains(only, comp.Name) || comp.Pinned {
			// A pinned component (psiphon-core) publishes no releases: its
			// versions are pinned by hand.
			continue
		}
		floor := newestStable(list, comp.Name)
		src := releases.FeedSource{Kind: releases.SourceGitHub, APIBase: api, Repo: comp.Repo, Token: c.getenv(envGitHubToken)}
		rels, _, _, _, err := releases.FetchReleases(ctx, hc, lim, src, "", true)
		if err != nil {
			return fmt.Errorf("the releases of %s: %w", comp.Name, err)
		}
		rels = slices.DeleteFunc(rels, func(r releases.FeedRelease) bool {
			return r.Prerelease || floor != "" && release.Compare(r.Tag, floor) <= 0
		})
		slices.SortStableFunc(rels, func(a, b releases.FeedRelease) int { return release.Compare(b.Tag, a.Tag) })
		found := false
		for _, r := range rels {
			entry, err := checkCandidate(ctx, hc, comp, r, filepath.Join(tmp, comp.Name, r.Tag))
			if err != nil {
				f.Skipped = append(f.Skipped, skipped{Component: comp.Name, Version: r.Tag, Reason: err.Error()})
				_, _ = fmt.Fprintf(c.stdout, "skipped %s %s: %v\n", comp.Name, r.Tag, err)
				continue
			}
			f.Candidates = append(f.Candidates, candidate{Component: comp.Name, stableEntry: entry})
			_, _ = fmt.Fprintf(c.stdout, "candidate %s %s\n", comp.Name, r.Tag)
			found = true
			break
		}
		if !found {
			_, _ = fmt.Fprintf(c.stderr, "candidates: %s: no usable release newer than %s\n", comp.Name, cmp.Or(floor, "none"))
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(*out, append(data, '\n'), 0o644)
}

// checkCandidate checks the assets of an upstream release for every
// architecture, in dir: the download has the SHA-256 that the checksum rules
// expect (releases.UpstreamSHA: the digest of the API, the checksum file of
// the release), the binary comes out of the archive by the rules of the
// catalog (releases.ExtractBinary), and it is a static program of its
// architecture (release.CheckStaticELF). It returns the entry of the list.
func checkCandidate(ctx context.Context, hc *http.Client, comp releases.Component, r releases.FeedRelease, dir string) (stableEntry, error) {
	if !release.ValidVersion(r.Tag) {
		return stableEntry{}, fmt.Errorf("%.40q is not a version", r.Tag)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return stableEntry{}, err
	}
	assets := map[string]releases.FeedAsset{}
	for _, a := range r.Assets {
		assets[a.Name] = a
	}
	entry := stableEntry{Version: r.Tag, Assets: map[string]stableAsset{}}
	for _, arch := range arches {
		file := comp.AssetName(r.Tag, arch)
		a, ok := assets[file]
		if !ok {
			return stableEntry{}, fmt.Errorf("no asset %s for %s", file, arch)
		}
		sums := ""
		if comp.Sums.File != "" {
			if s, ok := assets[comp.SumsFile(r.Tag, file)]; ok {
				data, err := download(ctx, hc, s.URL, maxSumsFile, nil)
				if err != nil {
					return stableEntry{}, fmt.Errorf("the checksum file of %s: %w", file, err)
				}
				sum, err := release.SumFor(file, data, comp.Sums.Format)
				switch {
				case errors.Is(err, release.ErrNoSum):
				case err != nil:
					return stableEntry{}, fmt.Errorf("the checksum file of %s: %w", file, err)
				default:
					sums = sum
				}
			}
		}
		want, source, err := releases.UpstreamSHA(a.Digest, sums)
		if err != nil {
			return stableEntry{}, fmt.Errorf("%s: %w", file, err)
		}
		archive := filepath.Join(dir, arch+"-"+file)
		af, err := os.Create(archive)
		if err != nil {
			return stableEntry{}, err
		}
		h := sha256.New()
		_, err = download(ctx, hc, a.URL, maxArchive, io.MultiWriter(af, h))
		if cerr := af.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return stableEntry{}, fmt.Errorf("%s: %w", file, err)
		}
		got := hex.EncodeToString(h.Sum(nil))
		if want != "" && got != want {
			return stableEntry{}, fmt.Errorf("%s has another SHA-256 than the %s one", file, source)
		}
		bin := filepath.Join(dir, arch+"-"+comp.Binary)
		if err := releases.ExtractBinary(ctx, archive, file, comp.MemberPath(r.Tag, arch), bin); err != nil {
			return stableEntry{}, fmt.Errorf("%s: %w", file, err)
		}
		if err := checkStatic(bin, arch); err != nil {
			return stableEntry{}, fmt.Errorf("%s: %w", file, err)
		}
		entry.Assets[arch] = stableAsset{File: file, SHA256: got}
	}
	return entry, nil
}

// checkStatic checks that the file at path is a static program for linux/arch.
func checkStatic(path, arch string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return release.CheckStaticELF(f, arch)
}

// download fetches u, at most limit bytes, into w, or returns it when w is nil.
func download(ctx context.Context, hc *http.Client, u string, limit int64, w io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "postern-stable-job")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	if w == nil {
		w = &buf
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return buf.Bytes(), nil
}

// componentNames lists the components of the panel.
func componentNames() string {
	var names []string
	for _, comp := range releases.Components {
		names = append(names, comp.Name)
	}
	return strings.Join(names, ", ")
}

// listFlag is a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// ---- stable-add -------------------------------------------------------------------

// stableAdd adds candidates that passed to the list and drops versions from
// it: see usageText.
func (c *cli) stableAdd(args []string) error {
	set := flags("stable-add")
	listPath := set.String("list", "", "")
	from := set.String("from", "", "")
	out := set.String("out", "", "")
	var drops listFlag
	set.Var(&drops, "drop", "")
	passed, err := parse(set, args, -2)
	if err != nil {
		return err
	}
	switch {
	case *out == "":
		return usagef("--out is missing")
	case len(passed) > 0 && *from == "":
		return usagef("--from is missing: the candidates that passed are taken from it")
	}
	list, err := readStableList(*listPath)
	if err != nil {
		return err
	}
	var cands candidatesFile
	if *from != "" {
		data, err := readSmall(*from, maxStableList)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &cands); err != nil {
			return fmt.Errorf("%s is not a file of candidates: %w", *from, err)
		}
	}
	for _, d := range drops {
		component, ver, err := componentVersion("--drop", d)
		if err != nil {
			return err
		}
		entries := list.Components[component]
		i := slices.IndexFunc(entries, func(e stableEntry) bool { return e.Version == ver })
		if i < 0 {
			return fmt.Errorf("--drop %s: the list has no %s %s", d, component, ver)
		}
		list.Components[component] = slices.Delete(entries, i, i+1)
		if len(list.Components[component]) == 0 {
			delete(list.Components, component)
		}
		_, _ = fmt.Fprintf(c.stdout, "dropped %s %s\n", component, ver)
	}
	for _, p := range passed {
		component, ver, err := componentVersion("a candidate", p)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(cands.Candidates, func(c candidate) bool { return c.Component == component && c.Version == ver })
		if i < 0 {
			return fmt.Errorf("%s is not a candidate of %s", p, *from)
		}
		cand := cands.Candidates[i]
		if err := checkEntry(cand.Component, cand.stableEntry); err != nil {
			return fmt.Errorf("%s: %w", *from, err)
		}
		entries := list.Components[component]
		if j := slices.IndexFunc(entries, func(e stableEntry) bool { return e.Version == ver }); j >= 0 {
			if !maps.Equal(entries[j].Assets, cand.Assets) {
				return fmt.Errorf("%s is in the list with other files or SHA-256: a stable version never changes", p)
			}
			_, _ = fmt.Fprintf(c.stdout, "kept %s %s: in the list already\n", component, ver)
			continue
		}
		list.Components[component] = append(entries, cand.stableEntry)
		_, _ = fmt.Fprintf(c.stdout, "added %s %s\n", component, ver)
	}
	for name, entries := range list.Components {
		for _, e := range entries {
			if err := checkEntry(name, e); err != nil {
				return fmt.Errorf("the list: %w", err)
			}
		}
		slices.SortFunc(entries, func(a, b stableEntry) int {
			return cmp.Or(release.Compare(a.Version, b.Version), strings.Compare(a.Version, b.Version))
		})
	}
	data, err := list.marshal()
	if err != nil {
		return err
	}
	return writeAtomic(*out, data, 0o644)
}

// componentVersion splits <component>@<version>.
func componentVersion(what, s string) (component, ver string, err error) {
	component, ver, ok := strings.Cut(s, "@")
	if !ok || component == "" || ver == "" {
		return "", "", usagef("%s %q is not <component>@<version>", what, s)
	}
	return component, ver, nil
}

// ---- stable-sign ------------------------------------------------------------------

// stableSign dates the list now and signs it: see usageText.
func (c *cli) stableSign(args []string) error {
	set := flags("stable-sign")
	key := set.String("key", "", "")
	files, err := parse(set, args, 1)
	if err != nil {
		return err
	}
	if *key == "" {
		return usagef("--key is missing")
	}
	path := files[0]
	if !present(path) {
		return fmt.Errorf("%s: no such list", path)
	}
	list, err := readStableList(path)
	if err != nil {
		return err
	}
	priv, err := c.openKey(*key)
	if err != nil {
		return err
	}
	// Once the binaries trust production stable keys, only one of them is
	// worth a signature: the panels refuse any other, a release key above all.
	if prod := productionKeys(release.StableKeys); len(prod) > 0 &&
		!slices.ContainsFunc(prod, func(k minisign.PublicKey) bool { return k.Equal(publicKey(priv)) }) {
		return fmt.Errorf("the key %016X is not one of the production stable keys: the panels would refuse the list", priv.ID())
	}
	// A panel takes a list only when it is newer than the one it applied.
	list.GeneratedAt = max(time.Now().Unix(), list.GeneratedAt+1)
	data, err := list.marshal()
	if err != nil {
		return err
	}
	want := release.Signed{Component: componentStable, Version: strconv.FormatInt(list.GeneratedAt, 10)}
	sig, err := release.Sign(bytes.NewReader(data), priv, want)
	if err != nil {
		return err
	}
	if err := release.VerifyWith(bytes.NewReader(data), sig, want, []minisign.PublicKey{publicKey(priv)}); err != nil {
		return fmt.Errorf("the new signature does not verify: %w", err)
	}
	if err := writeAtomic(path, data, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(path+sigSuffix, sig, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.stderr, "stable-sign: %s%s: %s (key %016X)\n", path, sigSuffix, want.TrustedComment(), priv.ID())
	_, _ = fmt.Fprintln(c.stdout, list.GeneratedAt)
	return nil
}
