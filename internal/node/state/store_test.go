package state

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

func TestPaths(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "opt", "postern")
	p := Paths{Home: home}
	for _, c := range []struct{ got, want string }{
		{p.StateDir(), filepath.Join(home, "data", "state")},
		{p.EdgeDir(), filepath.Join(home, "data", "edge")},
		{p.RunDir(), filepath.Join(home, "data", "run")},
		{p.ArtifactsDir(), filepath.Join(home, "data", "artifacts")},
		{p.InstancesDir(), filepath.Join(home, "data", "instances")},
		{p.CertsDir(), filepath.Join(home, "data", "certs")},
		{p.EdgeConfigPath(12), filepath.Join(home, "data", "edge", "config-g12.json")},
		{p.EdgeSocketPath(12), filepath.Join(home, "data", "run", "edge-g12.sock")},
		{p.ResolvConfPath(), filepath.Join(home, "data", "run", "resolv.conf")},
		{p.EgressDir("NL-2"), filepath.Join(home, "data", "instances", "egr-nl-2")},
		{p.EgressStateDir("NL-2"), filepath.Join(home, "data", "state", "egress", "nl-2")},
		{p.MEAddrsPath(), filepath.Join(home, "data", "state", "me-addrs.json")},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Paths: Paths{Home: t.TempDir()}}
}

func TestLoadDesiredAbsent(t *testing.T) {
	st, err := newStore(t).LoadDesired()
	if err != nil || st != nil {
		t.Fatalf("LoadDesired = %v, %v; want nil, nil", st, err)
	}
}

func TestSaveLoadDesired(t *testing.T) {
	s := newStore(t)
	want := validState()
	if err := s.SaveDesired(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadDesired()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, want) {
		t.Errorf("LoadDesired = %v, want %v", got, want)
	}
	assertMode(t, filepath.Join(s.Paths.StateDir(), "desired.json"), 0o600)
	assertMode(t, s.Paths.StateDir(), 0o700)
	assertOnlyFiles(t, s.Paths.StateDir(), "desired.json")
}

func TestSaveDesiredKeepsPrevious(t *testing.T) {
	s := newStore(t)
	first, second := validState(), validState()
	first.Generation, second.Generation = 1, 2
	if err := s.SaveDesired(first); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDesired(second); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadDesired()
	if err != nil {
		t.Fatal(err)
	}
	if got.GetGeneration() != 2 {
		t.Errorf("desired generation = %d, want 2", got.GetGeneration())
	}
	prev := readState(t, filepath.Join(s.Paths.StateDir(), "desired.prev.json"))
	if !proto.Equal(prev, first) {
		t.Errorf("desired.prev.json = %v, want the first state", prev)
	}
	assertMode(t, filepath.Join(s.Paths.StateDir(), "desired.prev.json"), 0o600)
	assertOnlyFiles(t, s.Paths.StateDir(), "desired.json", "desired.prev.json")
}

func TestLoadDesiredIgnoresUnknownFields(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(s.Paths.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := `{"generation":"5","fieldFromTheFuture":{"x":1}}`
	if err := os.WriteFile(filepath.Join(s.Paths.StateDir(), "desired.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadDesired()
	if err != nil {
		t.Fatal(err)
	}
	if st.GetGeneration() != 5 {
		t.Errorf("generation = %d, want 5", st.GetGeneration())
	}
}

func TestLoadDesiredCorrupt(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(s.Paths.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Paths.StateDir(), "desired.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := s.LoadDesired(); err == nil {
		t.Fatalf("LoadDesired = %v, nil; want an error", st)
	}
}

func TestRuntimeAbsentIsEmpty(t *testing.T) {
	rt, err := newStore(t).LoadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Ports == nil || rt.Instances == nil {
		t.Fatalf("LoadRuntime = %+v; want non-nil maps", rt)
	}
	if len(rt.Ports) != 0 || len(rt.Instances) != 0 || rt.EdgeGeneration != 0 || rt.AppliedGeneration != 0 {
		t.Errorf("LoadRuntime = %+v; want an empty runtime", rt)
	}
}

func TestRuntimeRoundTrip(t *testing.T) {
	s := newStore(t)
	since := time.Date(2026, 10, 4, 10, 30, 0, 0, time.UTC)
	want := &Runtime{
		Ports: map[string]uint16{
			EnginePortKey("P1", 2, PortListen): 20001,
			EnginePortKey("P1", 2, PortAPI):    25001,
			EnginePortKey("P1", 2, PortSocks):  30001,
			TestListenerPortKey("L1"):          40000,
		},
		Instances: map[string]InstanceRecord{
			"P1": {
				Generation: 2, Hash: "abc", Engine: "telemt", Version: "3.5.13",
				ListenerID: "L1", Domain: "a.example.com", BinaryPath: "/opt/postern/data/artifacts/telemt/3.5.13/amd64/telemt",
				ListenPort: 20001, APIPort: 25001, SocksPort: 30001,
				APIToken: "token", ServingSince: since,
				Draining:       []DrainingInstance{{Generation: 1, ContainerName: "postern-eng-p1-g1", Since: since, ListenPort: 20000}},
				LastGeneration: 2,
				NatIP:          "203.0.113.9",
			},
		},
		Egresses: map[string]EgressRecord{
			"NL": {
				Generation: 4, Hash: "def", Provider: "xray", Version: "v26.3.27",
				BinaryPath:          "/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray",
				Members:             []EgressMember{{Key: "member-a", Port: 35001}, {Key: "member-b", Port: 35002}},
				ServingSince:        since,
				Draining:            []DrainingEgress{{Generation: 3, ContainerName: "postern-egr-nl-g3", Since: since}},
				LastGeneration:      4,
				SubscriptionFetched: since,
				SubscriptionURL:     "0f0e",
			},
		},
		EdgeGeneration:    3,
		AppliedGeneration: 9,
	}
	if err := s.SaveRuntime(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadRuntime = %+v\nwant %+v", got, want)
	}
	assertMode(t, filepath.Join(s.Paths.StateDir(), "runtime.json"), 0o600)
	assertOnlyFiles(t, s.Paths.StateDir(), "runtime.json")
}

func TestPortKeys(t *testing.T) {
	if got := EgressPortKey("NL", 3, "0123456789ab"); got != "egr:NL:g3:0123456789ab" || !strings.HasPrefix(got, EgressPortPrefix("NL", 3)) {
		t.Errorf("EgressPortKey = %q", got)
	}
	if got := EnginePortKey("01J9ABC", 4, PortListen); got != "eng:01J9ABC:g4:listen" {
		t.Errorf("EnginePortKey = %q", got)
	}
	if got := TestListenerPortKey("L1"); got != "svc:test:L1" {
		t.Errorf("TestListenerPortKey = %q", got)
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	for _, content := range []string{"one", "two"} {
		if err := WriteFileAtomic(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Errorf("content = %q, want %q", got, content)
		}
	}
	assertMode(t, path, 0o600)
	assertOnlyFiles(t, dir, "f.json")
}

func readState(t *testing.T, path string) *nodev1.NodeState {
	t.Helper()
	s := &Store{}
	st, err := s.readDesired(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// assertMode checks permission bits where the platform has them.
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %v, want %v", path, got, want)
	}
}

// assertOnlyFiles checks that dir holds exactly the named files: no temporary
// files are left behind.
func assertOnlyFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Errorf("%s holds %v, want %v", dir, got, names)
	}
}
