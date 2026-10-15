package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// The WARP device that warp-plus registers for Psiphon. warp-plus v1.2.6 makes
// an anonymous WARP device of its own and keeps its identity in the cache
// directory it is given, as wgcf-identity.json (warp/account.go: identityFile;
// the fields "id" and "token" are those of warp/api.go: Identity). Before the
// agent removes such a cache directory it deletes that device through the same
// client as the devices of WARP egresses (warp.Delete: a 404 is "gone" only
// when it is the API's JSON error). A directory whose identity is also in
// another cache directory of the egress is a copy of it (a new generation
// starts with a copy of the canonical cache): the device is still in use and
// stays.
//
// A deletion that fails does not hold the removal back: the device (its id and
// token, no key) is kept in a 0600 file in data/state/psiphon-devices, and each
// pass tries it again, at most every psiphonRetryEvery. Neither the log nor an
// event ever says an id or a token.

const (
	psiphonIdentityFile = "wgcf-identity.json"
	maxPsiphonIdentity  = 64 << 10
	psiphonRetryEvery   = 30 * time.Minute
	psiphonGiveUpAfter  = 7 * 24 * time.Hour

	// evPsiphonDeviceKept says that the deletion of a warp-plus device is given
	// up. It names no device.
	evPsiphonDeviceGiveUp = "psiphon_warp_device_give_up"
)

// psiphonDevice is a WARP device that warp-plus registered.
type psiphonDevice struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	// Since is when the deletion first failed (the pending record only).
	Since time.Time `json:"since,omitzero"`
}

func (d psiphonDevice) account() *warp.Account { return &warp.Account{ID: d.ID, Token: d.Token} }

// readPsiphonIdentity reads the device of the identity file in a cache
// directory, which the container writes: nothing leaves the directory (os.Root),
// and the file must be a regular one of at most maxPsiphonIdentity bytes.
func readPsiphonIdentity(cacheDir string) (psiphonDevice, bool) {
	root, err := os.OpenRoot(cacheDir)
	if err != nil {
		return psiphonDevice{}, false
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(psiphonIdentityFile)
	if err != nil {
		return psiphonDevice{}, false
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return psiphonDevice{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPsiphonIdentity+1))
	if err != nil || len(data) > maxPsiphonIdentity {
		return psiphonDevice{}, false
	}
	var d psiphonDevice
	if json.Unmarshal(data, &d) != nil || d.ID == "" || d.Token == "" {
		return psiphonDevice{}, false
	}
	return d, true
}

func (p *pass) psiphonDevicesDir() string {
	return filepath.Join(p.r.Store.Paths.StateDir(), "psiphon-devices")
}

func (p *pass) psiphonDevicePath(d psiphonDevice) string {
	sum := sha256.Sum256([]byte(d.ID))
	return filepath.Join(p.psiphonDevicesDir(), hex.EncodeToString(sum[:8])+".json")
}

// cacheDirs lists the cache directories of an egress, except skip.
func (p *pass) cacheDirs(id, skip string) []string {
	dir := p.r.Store.Paths.EgressDir(id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if _, ok := cacheGeneration(e.Name()); ok && e.IsDir() && filepath.Join(dir, e.Name()) != skip {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// releaseCacheDevice deletes the device of the cache directory dir of egress
// id, which is about to be removed, unless another cache directory of the
// egress holds the same device.
func (p *pass) releaseCacheDevice(id, dir string) {
	dev, ok := readPsiphonIdentity(dir)
	if !ok {
		return
	}
	for _, other := range p.cacheDirs(id, dir) {
		if o, ok := readPsiphonIdentity(other); ok && o.ID == dev.ID {
			return
		}
	}
	p.deletePsiphonDevice(id, dev)
}

// releaseEgressDevices deletes the devices of every cache directory of egress
// id, whose directory is about to be removed.
func (p *pass) releaseEgressDevices(id string) {
	seen := map[string]bool{}
	for _, dir := range p.cacheDirs(id, "") {
		if dev, ok := readPsiphonIdentity(dir); ok && !seen[dev.ID] {
			seen[dev.ID] = true
			p.deletePsiphonDevice(id, dev)
		}
	}
}

// savePsiphonDevice writes the pending record of a device, 0600.
func (p *pass) savePsiphonDevice(dev psiphonDevice) error {
	if err := ensurePrivateDir(p.psiphonDevicesDir()); err != nil {
		return err
	}
	data, err := json.Marshal(dev)
	if err != nil {
		return err
	}
	return state.WriteFileAtomic(p.psiphonDevicePath(dev), append(data, '\n'), 0o600)
}

// deletePsiphonDevice deletes a device now; when that fails it is kept for a
// later pass.
func (p *pass) deletePsiphonDevice(egress string, dev psiphonDevice) {
	if p.tryPsiphonDevice(dev) {
		return
	}
	if dev.Since.IsZero() {
		dev.Since = p.r.now().UTC()
	}
	if err := p.savePsiphonDevice(dev); err != nil {
		p.r.log().Warn("could not keep a WARP device of warp-plus for a later deletion", "egress", egress, "err", err)
		return
	}
	if p.r.psiphonRetry == nil {
		p.r.psiphonRetry = map[string]time.Time{}
	}
	p.r.psiphonRetry[p.psiphonDevicePath(dev)] = p.r.now().Add(psiphonRetryEvery)
	p.r.log().Warn("could not delete the WARP device that warp-plus registered; it is kept and tried again later", "egress", egress)
}

// tryPsiphonDevice deletes the device and reports whether it is gone: deleted,
// or gone already. Its pending record goes with it.
func (p *pass) tryPsiphonDevice(dev psiphonDevice) bool {
	ctx, cancel := context.WithTimeout(p.ctx, warpTimeout)
	err := p.r.deleteWARP(ctx, dev.account())
	cancel()
	if err != nil && !errors.Is(err, warp.ErrDeviceGone) {
		return false
	}
	if err := os.Remove(p.psiphonDevicePath(dev)); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.r.log().Warn("could not remove the record of a deleted WARP device of warp-plus", "err", err)
	}
	return true
}

// retryPsiphonDevices tries the devices kept by deletePsiphonDevice again, each
// at most every psiphonRetryEvery.
func (p *pass) retryPsiphonDevices() {
	entries, err := os.ReadDir(p.psiphonDevicesDir())
	if err != nil {
		return
	}
	now := p.r.now()
	if p.r.psiphonRetry == nil {
		p.r.psiphonRetry = map[string]time.Time{}
	}
	for _, e := range entries {
		if p.ctx.Err() != nil {
			return
		}
		path := filepath.Join(p.psiphonDevicesDir(), e.Name())
		if at, ok := p.r.psiphonRetry[path]; ok && now.Before(at) {
			continue
		}
		data, err := os.ReadFile(path)
		var dev psiphonDevice
		if err != nil || json.Unmarshal(data, &dev) != nil || dev.ID == "" || dev.Token == "" {
			continue
		}
		if dev.Since.IsZero() { // a record of an older agent: its age starts now
			dev.Since = now.UTC()
			if err := p.savePsiphonDevice(dev); err != nil {
				p.r.log().Warn("could not date the record of a WARP device of warp-plus", "err", err)
			}
		}
		if now.Sub(dev.Since) >= psiphonGiveUpAfter {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				p.r.log().Warn("could not remove the record of a WARP device of warp-plus that is given up", "err", err)
			}
			delete(p.r.psiphonRetry, path)
			p.r.log().Warn("gave up deleting a WARP device that warp-plus registered")
			p.r.event(evPsiphonDeviceGiveUp, sevWarning, "",
				"a WARP device that warp-plus registered for a Psiphon egress could not be deleted for 7 days; "+
					"the deletion is not tried any more: remove the device in the Cloudflare dashboard (Zero Trust, Devices)",
				map[string]string{"days": "7"})
			continue
		}
		if p.tryPsiphonDevice(dev) {
			delete(p.r.psiphonRetry, path)
			p.r.log().Info("deleted a WARP device that warp-plus registered")
			continue
		}
		p.r.psiphonRetry[path] = now.Add(psiphonRetryEvery)
	}
}
