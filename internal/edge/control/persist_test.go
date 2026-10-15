package control

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// fullConfig is a configuration with something in every field. Its generation
// is beyond what a float64 holds exactly, so that a round trip through JSON
// numbers would lose it.
func fullConfig() *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: 1<<53 + 1,
		Listeners: []*edgev1.EdgeListener{
			{
				Id: "l1", BindIp: "192.0.2.10", Port: 443, Kind: "tls",
				StrangerAction: "mask", MaskTarget: "mask.example.com:443", NonTlsAction: "http400",
				TrustedCidrs: []string{"198.51.100.0/24", "2001:db8::/32"},
			},
			{Id: "l2", BindIp: "::", Port: 8443, Kind: "http-upstream", StrangerAction: "drop", NonTlsAction: "drop"},
		},
		Routes: []*edgev1.Route{
			{
				ListenerId: "l1", Sni: "proxy.example.com", ProxyId: "p1", Kind: "engine",
				Backend: "127.0.0.1:20001", ProxyProtocol: true,
				Limits: &edgev1.EdgeLimits{Devices: 3, ConnsTotal: 100, ConnsPerIp: 10},
			},
			{ListenerId: "l1", Sni: "mgmt.example.com", Kind: "mgmt", Backend: "127.0.0.1:40001"},
			{ListenerId: "l2", Sni: "web.example.com", ProxyId: "p2", Kind: "web", Backend: "127.0.0.1:20002"},
		},
		Certs: []*edgev1.CertRef{{Domain: "web.example.com", Generation: 1<<53 + 3}},
		Socks: []*edgev1.SocksPort{
			{
				Port: 30001, ProxyId: "p1", DefaultChainId: "c1",
				ScopeChains: map[string]string{"me": "c2", "fetch": "c1"},
			},
		},
		Chains: []*edgev1.Chain{
			{Id: "c1", Members: []*edgev1.ChainMember{
				{Key: "m1", Kind: "direct", BindDevice: "wg0", BindIp: "192.0.2.20"},
			}},
			{Id: "c2", Members: []*edgev1.ChainMember{
				{Key: "m2", Kind: "socks5", Addr: "127.0.0.1:35001", Username: "user", Password: "not-a-real-password"},
				{Key: "m3", Kind: "http", Addr: "127.0.0.1:35002"},
			}},
		},
		BlacklistCidrs:    []string{"203.0.113.0/24", "2001:db8:1::/48"},
		MaskDomains:       []string{"mask.example.com", "pool.example.com"},
		Health:            &edgev1.HealthCheck{IntervalSeconds: 20, TimeoutSeconds: 3, FailThreshold: 4, RecoverThreshold: 2, DcAddrs: []string{"149.154.175.50:443"}, EchoUrls: []string{"https://echo.example.com/ip"}},
		DeviceIdleSeconds: 90,
		TestListeners:     []*edgev1.TestListener{{Port: 40001, ListenerId: "l1"}},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := fullConfig()
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Errorf("round trip changed the configuration:\n got %v\nwant %v", got, want)
	}
	if got.GetGeneration() != 1<<53+1 {
		t.Errorf("generation = %d, want %d", got.GetGeneration(), uint64(1<<53+1))
	}
}

func TestSaveConfigMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := SaveConfig(path, fullConfig()); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, path); got != 0o600 {
		t.Errorf("mode of a new file = %o, want 600", got)
	}

	// A file that was readable by others is replaced by one that is not: it
	// holds the passwords of the egress members.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(path, fullConfig()); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, path); got != 0o600 {
		t.Errorf("mode after overwriting a 0644 file = %o, want 600", got)
	}
}

func modeOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestSaveConfigOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	a, b := &edgev1.EdgeConfig{Generation: 1}, fullConfig()
	if err := SaveConfig(path, a); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(path, b); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, b) {
		t.Errorf("the file holds %v, want the second configuration", got)
	}
}

func TestSaveConfigNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveConfig(path, nil); err == nil {
		t.Error("SaveConfig(nil) succeeded")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file was written for a nil configuration: %v", err)
	}
}

// files lists the names in a directory.
func files(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// stubDisk replaces the steps of SaveConfig that touch the disk for the
// duration of a test.
func stubDisk(t *testing.T, syncF func(*os.File) error, rename func(oldpath, newpath string) error, syncD func(string) error) {
	t.Helper()
	oldF, oldR, oldD := syncFile, renameFile, syncDir
	t.Cleanup(func() { syncFile, renameFile, syncDir = oldF, oldR, oldD })
	if syncF != nil {
		syncFile = syncF
	}
	if rename != nil {
		renameFile = rename
	}
	if syncD != nil {
		syncDir = syncD
	}
}

// TestSaveConfigSteps pins the order that makes the write atomic and durable:
// the new content is complete in a temporary file and on disk before the
// rename, and the directory is synced after it.
func TestSaveConfigSteps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := &edgev1.EdgeConfig{Generation: 1}
	if err := SaveConfig(path, old); err != nil {
		t.Fatal(err)
	}
	want := fullConfig()

	var steps []string
	mustHold := func(name string, cfg *edgev1.EdgeConfig, step string) {
		t.Helper()
		got, err := LoadConfig(name)
		if err != nil {
			t.Errorf("at %s the file %s cannot be read: %v", step, filepath.Base(name), err)
			return
		}
		if !proto.Equal(got, cfg) {
			t.Errorf("at %s the file %s holds %v, want %v", step, filepath.Base(name), got, cfg)
		}
	}
	var tmpName string
	stubDisk(t,
		func(f *os.File) error {
			steps = append(steps, "sync-file")
			tmpName = f.Name()
			if filepath.Dir(tmpName) != dir {
				t.Errorf("the temporary file is in %s, want the directory of the file (%s): a rename across file systems is not atomic", filepath.Dir(tmpName), dir)
			}
			mustHold(tmpName, want, "the sync of the file")
			return f.Sync()
		},
		func(oldpath, newpath string) error {
			steps = append(steps, "rename")
			if oldpath != tmpName || newpath != path {
				t.Errorf("rename(%s, %s), want the synced file onto %s", oldpath, newpath, path)
			}
			mustHold(oldpath, want, "the rename")
			mustHold(newpath, old, "the rename") // the old content is there until the rename
			return os.Rename(oldpath, newpath)
		},
		func(d string) error {
			steps = append(steps, "sync-dir")
			if d != dir {
				t.Errorf("sync of directory %s, want %s", d, dir)
			}
			mustHold(path, want, "the sync of the directory")
			return nil
		})

	if err := SaveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(steps, ","); got != "sync-file,rename,sync-dir" {
		t.Errorf("steps = %s, want sync-file,rename,sync-dir", got)
	}
	if got := files(t, dir); !slices.Equal(got, []string{"config.json"}) {
		t.Errorf("directory holds %v after the save, want only config.json", got)
	}
}

// TestSaveConfigFailureKeepsOldFile makes each step fail: the old file stays,
// complete, and no temporary file is left.
func TestSaveConfigFailureKeepsOldFile(t *testing.T) {
	injected := errors.New("injected")
	tests := []struct {
		name string
		stub func(t *testing.T)
	}{
		{"sync of the file", func(t *testing.T) {
			stubDisk(t, func(*os.File) error { return injected }, nil, nil)
		}},
		{"rename", func(t *testing.T) {
			stubDisk(t, nil, func(string, string) error { return injected }, nil)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			old := &edgev1.EdgeConfig{Generation: 5}
			if err := SaveConfig(path, old); err != nil {
				t.Fatal(err)
			}
			tt.stub(t)
			err := SaveConfig(path, fullConfig())
			if !errors.Is(err, injected) {
				t.Fatalf("SaveConfig error = %v, want it to wrap the injected one", err)
			}
			got, err := LoadConfig(path)
			if err != nil || !proto.Equal(got, old) {
				t.Errorf("the old file reads %v, %v after the failed save, want it untouched", got, err)
			}
			if names := files(t, dir); !slices.Equal(names, []string{"config.json"}) {
				t.Errorf("directory holds %v after the failed save, want only config.json", names)
			}
		})
	}
}

// TestSaveConfigSyncDirFailure: once the file is renamed it is in place; the
// error of the directory sync is reported all the same, because the caller
// must not take the save as durable.
func TestSaveConfigSyncDirFailure(t *testing.T) {
	injected := errors.New("injected")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	stubDisk(t, nil, nil, func(string) error { return injected })
	want := fullConfig()
	if err := SaveConfig(path, want); !errors.Is(err, injected) {
		t.Fatalf("SaveConfig error = %v, want the injected one", err)
	}
	if got, err := LoadConfig(path); err != nil || !proto.Equal(got, want) {
		t.Errorf("file = %v, %v; the rename had happened, so the new content is in place", got, err)
	}
	if names := files(t, dir); !slices.Equal(names, []string{"config.json"}) {
		t.Errorf("directory holds %v, want only config.json", names)
	}
}

func TestSaveConfigErrors(t *testing.T) {
	t.Run("no directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "config.json")
		if err := SaveConfig(path, fullConfig()); err == nil {
			t.Error("SaveConfig into a directory that does not exist succeeded")
		}
	})
	t.Run("path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := SaveConfig(path, fullConfig()); err == nil {
			t.Error("SaveConfig over a directory succeeded")
		}
		if names := files(t, dir); !slices.Equal(names, []string{"config.json"}) {
			t.Errorf("directory holds %v after the failed save, want only the directory that was there", names)
		}
	})
}

// TestSaveConfigAtomicForReaders: a reader that races with writers sees one
// complete configuration or the other, never a torn file, and never no file.
func TestSaveConfigAtomicForReaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	a, b := fullConfig(), &edgev1.EdgeConfig{Generation: 2, MaskDomains: []string{"example.com"}}
	if err := SaveConfig(path, a); err != nil {
		t.Fatal(err)
	}

	const writers, rounds = 4, 40
	var wg sync.WaitGroup
	stop := make(chan struct{})
	failed := make(chan string, 1)
	fail := func(msg string) {
		select {
		case failed <- msg:
		default:
		}
	}

	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := LoadConfig(path)
			if err != nil {
				fail("reader: " + err.Error())
				return
			}
			if !proto.Equal(got, a) && !proto.Equal(got, b) {
				fail("reader: a configuration that was never written: " + got.String())
				return
			}
		}
	}()
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := a
			if w%2 == 1 {
				cfg = b
			}
			for range rounds {
				if err := SaveConfig(path, cfg); err != nil {
					fail("writer: " + err.Error())
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	readers.Wait()
	select {
	case msg := <-failed:
		t.Fatal(msg)
	default:
	}
	if names := files(t, dir); !slices.Equal(names, []string{"config.json"}) {
		t.Errorf("directory holds %v after the writers are done, want only config.json", names)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("missing", func(t *testing.T) {
		_, err := LoadConfig(filepath.Join(dir, "absent.json"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("error = %v, want one that matches fs.ErrNotExist", err)
		}
	})
	for _, tt := range []struct{ name, content string }{
		{"empty", ""},
		{"garbage", "not json at all"},
		{"truncated", `{"generation": "3", "listeners": [{"id": "l1"`},
		{"wrong type", `{"listeners": 5}`},
		{"object where a number belongs", `{"generation": {"a": 1}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := write(strings.ReplaceAll(tt.name, " ", "_")+".json", tt.content)
			cfg, err := LoadConfig(p)
			if err == nil {
				t.Fatalf("LoadConfig accepted %q: %v", tt.content, cfg)
			}
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q does not name the file %s", err, p)
			}
		})
	}
}

func TestLoadConfigAcceptsAgentFiles(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		name, content string
		check         func(*edgev1.EdgeConfig) bool
	}{
		{"empty object", `{}`, func(c *edgev1.EdgeConfig) bool { return c.GetGeneration() == 0 }},
		{
			"lowerCamelCase, numbers as strings",
			`{"generation": "7", "deviceIdleSeconds": 90, "listeners": [{"id": "l1", "bindIp": "127.0.0.1", "port": 443}]}`,
			func(c *edgev1.EdgeConfig) bool {
				return c.GetGeneration() == 7 && c.GetDeviceIdleSeconds() == 90 && c.GetListeners()[0].GetBindIp() == "127.0.0.1"
			},
		},
		{
			"proto names, numbers as numbers",
			`{"generation": 8, "device_idle_seconds": 60, "listeners": [{"id": "l1", "bind_ip": "127.0.0.1", "port": 443}]}`,
			func(c *edgev1.EdgeConfig) bool {
				return c.GetGeneration() == 8 && c.GetDeviceIdleSeconds() == 60 && c.GetListeners()[0].GetBindIp() == "127.0.0.1"
			},
		},
		{
			// A newer agent may know fields that this edge does not; the edge must
			// still come up from the file.
			"unknown fields",
			`{"generation": "9", "someFutureField": {"a": [1, 2]}, "listeners": [{"id": "l1", "futureKnob": true}]}`,
			func(c *edgev1.EdgeConfig) bool { return c.GetGeneration() == 9 && c.GetListeners()[0].GetId() == "l1" },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			if err := os.WriteFile(p, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(p)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if !tt.check(cfg) {
				t.Errorf("LoadConfig(%s) = %v", tt.content, cfg)
			}
		})
	}
}

func TestLoadConfigSizeLimit(t *testing.T) {
	old := maxConfigBytes
	maxConfigBytes = 1 << 10
	t.Cleanup(func() { maxConfigBytes = old })

	dir := t.TempDir()
	pad := func(n int) string { return `{"maskDomains": ["` + strings.Repeat("a", n) + `.example.com"]}` }
	small, big := filepath.Join(dir, "small.json"), filepath.Join(dir, "big.json")
	if err := os.WriteFile(small, []byte(pad(100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(pad(int(maxConfigBytes))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(small); err != nil {
		t.Errorf("a file under the limit: %v", err)
	}
	if _, err := LoadConfig(big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a file over the limit: error = %v, want one that says the file is too large", err)
	}
}
