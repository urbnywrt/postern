package reconcile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
)

// The cache of Psiphon (Ruling S2-18). Psiphon's client keeps what it learns,
// its server list and a bbolt database that one process at a time may open, in
// its data root, which makes a new start much faster. (warp-plus, which ran
// PSIPHON egresses before, kept its WARP identity there too: such a cache is
// not copied, and its device is deleted with it, psiphondevice.go.) Each
// provider generation of a PSIPHON egress has a cache directory of its own,
// cache-g<N> in the directory of the egress, which its container mounts: that
// of a new generation is a copy of the canonical cache, made as it starts,
// while the generation it replaces may still run. The canonical cache is the
// symlink "cache" to the cache directory of a generation: once a generation
// serves alone, the one it replaced removed, its cache becomes the canonical
// one by the atomic rename of a new symlink over the old one, and the caches of
// the generations that are gone go. So no two Psiphon processes ever open
// the same file, and the cache outlives the generations, also those of an
// egress that no chain takes for a while.
//
// A cache is written by the container, as 65534, and copied by the agent, as
// root: the copy takes regular files and directories only, never leaves the
// cache it copies (os.Root), opens nothing in a way that can block, reads
// directories in batches, and is bounded. A file that changes while it is
// copied, twice in a row, is left out. A cache that cannot be copied is not:
// the new generation starts with an empty one, which only takes longer.

const (
	// cacheLink is the canonical cache, a symlink in the directory of the
	// egress to the cache directory of a generation.
	cacheLink = "cache"
	// cacheGenPrefix and a generation are the name of the cache directory of
	// the generation.
	cacheGenPrefix = "cache-g"
	// maxCacheBytes and maxCacheEntries bound the copy of a cache.
	maxCacheBytes   = 256 << 20
	maxCacheEntries = 4096
)

// cacheGenDir is the cache directory of a generation of an egress.
func (p *pass) cacheGenDir(id string, gen uint64) string {
	return filepath.Join(p.r.Store.Paths.EgressDir(id), cacheGenPrefix+genString(gen))
}

// cacheGeneration reads the name of a cache directory, cache-g<N>.
func cacheGeneration(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, cacheGenPrefix)
	if !ok {
		return 0, false
	}
	gen, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || gen == 0 || digits != genString(gen) {
		return 0, false
	}
	return gen, true
}

// canonicalCache is the generation whose cache is the canonical one of an
// egress, 0 for none.
func (p *pass) canonicalCache(id string) uint64 {
	target, err := os.Readlink(filepath.Join(p.r.Store.Paths.EgressDir(id), cacheLink))
	if err != nil {
		return 0
	}
	gen, _ := cacheGeneration(target)
	return gen
}

// seedCache makes the cache directory of a new generation, which its container
// writes as 65534 (0700): a copy of the canonical cache, or an empty one when
// there is none or it cannot be copied. It returns the directory.
func (p *pass) seedCache(id string, gen uint64) (string, error) {
	dst := p.cacheGenDir(id, gen)
	fresh := func() error {
		p.releaseCacheDevice(id, dst)
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		return p.mkdirOwned(dst, 0o700, engineUID, engineGID)
	}
	if err := ensurePrivateDir(filepath.Dir(dst)); err != nil {
		return "", err
	}
	if err := fresh(); err != nil {
		return "", err
	}
	src := p.canonicalCache(id)
	if src == 0 || src == gen {
		return dst, nil
	}
	if _, ok := readPsiphonIdentity(p.cacheGenDir(id, src)); ok {
		// The cache of warp-plus, which ran the egress before Psiphon's own
		// client: its WARP device is not to be carried over (once the new
		// generation serves alone, the old cache goes and its device is
		// deleted), and its Psiphon data is laid out otherwise.
		return dst, nil
	}
	changed, err := p.copyCache(p.cacheGenDir(id, src), dst)
	if err != nil {
		p.r.log().Warn("the cache of Psiphon could not be copied for a new generation, which starts with an empty one",
			"egress", id, "generation", gen, "from_generation", src, "err", err)
		if err := fresh(); err != nil {
			return "", err
		}
		return dst, nil
	}
	if len(changed) > 0 {
		p.r.log().Warn("files of the cache of Psiphon changed while they were copied, twice; the copy of the new generation leaves them out",
			"egress", id, "generation", gen, "from_generation", src, "files", len(changed), "first", changed[0])
	}
	// The notices are those of the generation before: the readiness of the new
	// one is read from its own.
	for _, name := range psiphoncore.NoticeFiles {
		if err := os.Remove(filepath.Join(dst, filepath.FromSlash(name))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return dst, nil
}

// cacheBatch is how many entries of a directory the copy of a cache reads at a
// time.
const cacheBatch = 256

// errCacheTooLarge is the error of a copy of a cache that holds too much.
var errCacheTooLarge = fmt.Errorf("the cache is larger than %d bytes", maxCacheBytes)

// cacheCopy is a copy of a cache under way.
type cacheCopy struct {
	p       *pass
	root    *os.Root // the cache copied
	dst     string   // where it goes
	budget  int64    // the bytes the copy may still read
	entries int      // the entries copied or left out so far
	read    int      // the entries read from directories so far
	changed []string // the files left out: they changed while they were copied
}

// copyCache copies the regular files and the directories of the cache src
// into the empty directory dst, owned by 65534, the files 0600 and the
// directories 0700, and returns the files it left out because they changed
// while they were copied. Anything else in src is left out; a file that goes
// away on the way too.
func (p *pass) copyCache(src, dst string) ([]string, error) {
	root, err := os.OpenRoot(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	c := &cacheCopy{p: p, root: root, dst: dst, budget: maxCacheBytes}
	if err := c.dir("."); err != nil {
		return nil, err
	}
	return c.changed, nil
}

// dir copies the directory name of the cache ("." for the cache itself), whose
// copy in dst exists: its regular files, then its directories. It holds one
// directory open at a time, and reads it cacheBatch entries at a time, so that
// a directory with more entries than a cache may have is never read whole.
// Directories are opened as files are, O_NONBLOCK: nothing the container puts
// in the cache, a FIFO or a lease, can hold the worker.
func (c *cacheCopy) dir(name string) error {
	d, err := c.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) && name != "." {
		return nil // gone on the way
	}
	if err != nil {
		return err
	}
	subdirs, err := c.copyEntries(d, name)
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for _, sub := range subdirs {
		if err := c.dir(sub); err != nil {
			return err
		}
	}
	return nil
}

// copyEntries copies the regular files of the open directory d, name in the
// cache, and makes the copies of its directories, which it returns.
func (c *cacheCopy) copyEntries(d *os.File, name string) ([]string, error) {
	info, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil // no longer a directory: left out
	}
	var subdirs []string
	for {
		batch, err := d.ReadDir(cacheBatch)
		c.read += len(batch)
		for _, e := range batch {
			if c.entries++; c.entries > maxCacheEntries {
				return nil, fmt.Errorf("the cache has more than %d entries", maxCacheEntries)
			}
			child := filepath.Join(name, e.Name())
			target := filepath.Join(c.dst, child)
			switch {
			case e.IsDir():
				if err := c.p.mkdirOwned(target, 0o700, engineUID, engineGID); err != nil {
					return nil, err
				}
				subdirs = append(subdirs, child)
			case e.Type().IsRegular():
				if err := c.file(child, target); err != nil {
					return nil, err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return subdirs, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// file copies the regular file name of the cache to target. A file whose size
// or time of modification changes while it is copied (Psiphon writes it) is
// copied again; one that changes again is left out, and noted.
func (c *cacheCopy) file(name, target string) error {
	for range 2 {
		stable, err := c.fileOnce(name, target)
		if err != nil || stable {
			return err
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	c.changed = append(c.changed, name)
	return nil
}

// fileOnce copies the regular file name of the cache to target once, and
// reports whether the file stayed as it was meanwhile; one that is gone, or
// is no regular file, is left out and counts as such. Every byte read counts
// against the budget, also those of a copy made again.
func (c *cacheCopy) fileOnce(name, target string) (bool, error) {
	// O_NONBLOCK: neither a FIFO put in the place of the file nor a lease on
	// it holds the worker.
	in, err := c.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = in.Close() }()
	before, err := in.Stat()
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() {
		return true, nil
	}
	if before.Size() > c.budget {
		return false, errCacheTooLarge
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	n, err := io.Copy(out, io.LimitReader(in, c.budget+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	c.budget -= n
	switch {
	case err != nil:
		return false, err
	case c.budget < 0:
		return false, errCacheTooLarge
	}
	if c.p.r.cacheCopied != nil {
		c.p.r.cacheCopied(name)
	}
	after, err := in.Stat()
	if err != nil {
		return false, err
	}
	if n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return false, nil
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return false, err
	}
	return true, c.p.chown(target, engineUID, engineGID)
}

// removeCache removes the cache directory of a generation that is gone, unless
// it is the canonical cache.
func (p *pass) removeCache(id string, gen uint64) {
	if gen == p.canonicalCache(id) {
		return
	}
	p.releaseCacheDevice(id, p.cacheGenDir(id, gen))
	if err := os.RemoveAll(p.cacheGenDir(id, gen)); err != nil {
		p.r.log().Warn("could not remove the cache of an egress generation", "egress", id, "generation", gen, "err", err)
	}
}

// tidyCaches makes the cache of a generation that serves alone the canonical
// cache of its egress, and removes the cache directories that neither a
// generation of the record nor the canonical cache are (left by a crash, or by
// a generation that was given up).
func (p *pass) tidyCaches(id string, rec state.EgressRecord) {
	dir := p.r.Store.Paths.EgressDir(id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	canonical := p.canonicalCache(id)
	if rec.Generation > 0 && len(rec.Draining) == 0 && canonical != rec.Generation {
		if info, err := os.Lstat(p.cacheGenDir(id, rec.Generation)); err == nil && info.IsDir() {
			if err := linkCanonicalCache(dir, rec.Generation); err != nil {
				p.r.log().Warn("could not make the cache of the serving generation the canonical one", "egress", id, "generation", rec.Generation, "err", err)
			} else {
				canonical = rec.Generation
			}
		}
	}
	keep := map[uint64]bool{canonical: true, rec.Generation: true}
	for _, d := range rec.Draining {
		keep[d.Generation] = true
	}
	for _, e := range entries {
		gen, ok := cacheGeneration(e.Name())
		if !ok || keep[gen] {
			continue
		}
		p.releaseCacheDevice(id, filepath.Join(dir, e.Name()))
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			p.r.log().Warn("could not remove the cache of an egress generation", "egress", id, "dir", e.Name(), "err", err)
		}
	}
}

// linkCanonicalCache makes the cache of generation gen the canonical cache of
// the egress whose directory is dir: a new symlink, renamed over the old one.
func linkCanonicalCache(dir string, gen uint64) error {
	link := filepath.Join(dir, cacheLink)
	if info, err := os.Lstat(link); err == nil && info.IsDir() {
		// A cache of an older agent, shared by its generations.
		if err := os.RemoveAll(link); err != nil {
			return err
		}
	}
	tmp := filepath.Join(dir, "."+cacheLink+".tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Symlink(cacheGenPrefix+genString(gen), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory after a rename in it; a failure is of no
// consequence beyond a crash.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
