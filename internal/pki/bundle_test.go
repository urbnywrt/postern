package pki

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

// maxFile is the largest file a bundle may hold: 64 KiB.
const maxFile = 64 * 1024

// tarEntry is one entry of a hand-built archive.
type tarEntry struct {
	name     string
	body     []byte
	typeflag byte // zero for a regular file
}

// buildTar writes an archive the way a hostile or buggy producer might, which
// MarshalTar never would.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(e.body))}
		switch e.typeflag {
		case 0:
		case tar.TypeSymlink:
			hdr.Typeflag, hdr.Size, hdr.Linkname = tar.TypeSymlink, 0, "elsewhere"
		default:
			hdr.Typeflag, hdr.Size = e.typeflag, 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func metaJSON(version int, nodeID string, port int) []byte {
	return fmt.Appendf(nil, `{"version":%d,"node_id":%q,"mgmt_port":%d}`, version, nodeID, port)
}

// bundleEntries lists the files of a bundle as MarshalTar writes them, with
// placeholder PEM contents: parsing only needs them to be there.
func bundleEntries(meta []byte) []tarEntry {
	return []tarEntry{
		{name: "bundle.json", body: meta},
		{name: "ca.pem", body: []byte("ca")},
		{name: "node.pem", body: []byte("cert")},
		{name: "node-key.pem", body: []byte("key")},
	}
}

// replace returns entries with the body of the named file swapped.
func replace(entries []tarEntry, name string, body []byte) []tarEntry {
	out := slices.Clone(entries)
	for i := range out {
		if out[i].name == name {
			out[i].body = body
		}
	}
	return out
}

// without returns entries minus the named file.
func without(entries []tarEntry, name string) []tarEntry {
	return slices.DeleteFunc(slices.Clone(entries), func(e tarEntry) bool { return e.name == name })
}

func newTestBundle(p *testPKI) *Bundle {
	return &Bundle{
		Version:  1,
		NodeID:   "node-1",
		MgmtPort: 8443,
		CAPEM:    p.ca.CertPEM,
		CertPEM:  p.node.certPEM,
		KeyPEM:   p.node.keyPEM,
	}
}

// requireSameBundle compares two bundles without printing the key.
func requireSameBundle(t *testing.T, got, want *Bundle) {
	t.Helper()
	if got.Version != want.Version || got.NodeID != want.NodeID || got.MgmtPort != want.MgmtPort {
		t.Errorf("bundle = (version %d, node %q, port %d), want (version %d, node %q, port %d)",
			got.Version, got.NodeID, got.MgmtPort, want.Version, want.NodeID, want.MgmtPort)
	}
	for _, f := range []struct {
		name      string
		got, want []byte
	}{
		{"CAPEM", got.CAPEM, want.CAPEM},
		{"CertPEM", got.CertPEM, want.CertPEM},
		{"KeyPEM", got.KeyPEM, want.KeyPEM},
	} {
		if !bytes.Equal(f.got, f.want) {
			t.Errorf("%s differs", f.name)
		}
	}
}

func requireErrorContaining(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("succeeded, want an error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	p := newTestPKI(t)
	want := newTestBundle(p)

	t.Run("tar", func(t *testing.T) {
		data, err := want.MarshalTar()
		if err != nil {
			t.Fatalf("MarshalTar: %v", err)
		}
		got, err := ParseBundleTar(data)
		if err != nil {
			t.Fatalf("ParseBundleTar: %v", err)
		}
		requireSameBundle(t, got, want)
	})
}

func TestBundleTarLayout(t *testing.T) {
	p := newTestPKI(t)
	b := newTestBundle(p)
	data, err := b.MarshalTar()
	if err != nil {
		t.Fatalf("MarshalTar: %v", err)
	}

	wantBodies := map[string][]byte{
		"ca.pem":       b.CAPEM,
		"node.pem":     b.CertPEM,
		"node-key.pem": b.KeyPEM,
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		names = append(names, hdr.Name)
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			t.Errorf("%s: type %q, want a regular file", hdr.Name, hdr.Typeflag)
		}
		// The bundle holds a private key; whoever unpacks it with a plain
		// `tar -x` must not end up with a world-readable key.
		if hdr.Mode != 0o600 {
			t.Errorf("%s: mode %o, want 600", hdr.Name, hdr.Mode)
		}
		if hdr.Name == "bundle.json" {
			continue
		}
		if !bytes.Equal(body, wantBodies[hdr.Name]) {
			t.Errorf("%s: the file differs from the bundle's field", hdr.Name)
		}
	}
	if want := []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"}; !slices.Equal(names, want) {
		t.Errorf("files = %v, want %v", names, want)
	}

	// bundle.json is read by shell scripts too: three keys, no more.
	meta, err := tarFile(data, "bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"version":1,"node_id":"node-1","mgmt_port":8443}`; string(meta) != want {
		t.Errorf("bundle.json = %s, want %s", meta, want)
	}
}

// tarFile returns the contents of one file of an archive.
func tarFile(data []byte, name string) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, err
		}
		if hdr.Name == name {
			return io.ReadAll(tr)
		}
	}
}

func TestBundleZeroVersionMeansCurrent(t *testing.T) {
	p := newTestPKI(t)
	b := newTestBundle(p)
	b.Version = 0

	data, err := b.MarshalTar()
	if err != nil {
		t.Fatalf("MarshalTar: %v", err)
	}
	got, err := ParseBundleTar(data)
	if err != nil {
		t.Fatalf("ParseBundleTar: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if BundleVersion != 1 {
		t.Errorf("BundleVersion = %d, want 1", BundleVersion)
	}
}

func TestBundleRejectsUnknownVersion(t *testing.T) {
	for _, version := range []int{0, 2, 3, 100, -1} {
		t.Run(fmt.Sprintf("parse version %d", version), func(t *testing.T) {
			data := buildTar(t, bundleEntries(metaJSON(version, "node-1", 8443)))
			_, err := ParseBundleTar(data)
			requireErrorContaining(t, err, fmt.Sprintf("unsupported bundle version %d", version))
		})
	}

	t.Run("no version at all", func(t *testing.T) {
		data := buildTar(t, bundleEntries([]byte(`{"node_id":"node-1","mgmt_port":8443}`)))
		_, err := ParseBundleTar(data)
		requireErrorContaining(t, err, "version")
	})

	t.Run("a newer layout is reported as a version problem", func(t *testing.T) {
		// A future bundle may rename or add files. The agent should say that
		// it is too old, not that a file it never heard of is unexpected.
		entries := without(bundleEntries(metaJSON(2, "node-1", 8443)), "node-key.pem")
		entries = append(entries, tarEntry{name: "something-new.pem", body: []byte("new")})
		_, err := ParseBundleTar(buildTar(t, entries))
		requireErrorContaining(t, err, "unsupported bundle version 2")
	})

	t.Run("marshal", func(t *testing.T) {
		b := newTestBundle(newTestPKI(t))
		for _, version := range []int{2, -1} {
			b.Version = version
			_, err := b.MarshalTar()
			requireErrorContaining(t, err, "unsupported bundle version")
		}
	})
}

func TestBundleRejectsMissingFiles(t *testing.T) {
	for _, name := range []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"} {
		t.Run(name, func(t *testing.T) {
			entries := without(bundleEntries(metaJSON(1, "node-1", 8443)), name)
			_, err := ParseBundleTar(buildTar(t, entries))
			requireErrorContaining(t, err, name)
			requireErrorContaining(t, err, "missing")
		})
	}
}

func TestBundleFileSizeLimit(t *testing.T) {
	meta := metaJSON(1, "node-1", 8443)

	for _, name := range []string{"bundle.json", "ca.pem", "node.pem", "node-key.pem"} {
		t.Run("over the limit/"+name, func(t *testing.T) {
			entries := replace(bundleEntries(meta), name, bytes.Repeat([]byte("x"), maxFile+1))
			_, err := ParseBundleTar(buildTar(t, entries))
			requireErrorContaining(t, err, name)
			requireErrorContaining(t, err, "too large")
		})
	}

	for _, name := range []string{"ca.pem", "node.pem", "node-key.pem"} {
		t.Run("at the limit/"+name, func(t *testing.T) {
			entries := replace(bundleEntries(meta), name, bytes.Repeat([]byte("x"), maxFile))
			if _, err := ParseBundleTar(buildTar(t, entries)); err != nil {
				t.Errorf("a file of exactly 64 KiB was rejected: %v", err)
			}
		})
	}
}

func TestBundleRejectsMalformedArchives(t *testing.T) {
	meta := metaJSON(1, "node-1", 8443)
	valid := buildTar(t, bundleEntries(meta))
	// A tar entry is a 512-byte header and its body padded to 512 bytes, so in
	// this archive bundle.json takes the first 1024 bytes and ca.pem the next
	// 512+3072: cutting at 2536 lands in the middle of ca.pem's body.
	large := buildTar(t, replace(bundleEntries(meta), "ca.pem", bytes.Repeat([]byte("x"), 3000)))

	tooMany := bundleEntries(meta)
	for i := range 10 {
		tooMany = append(tooMany, tarEntry{name: fmt.Sprintf("extra-%d.pem", i), body: []byte("x")})
	}

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty input", nil, "missing"},
		{"not an archive", []byte("hello"), "archive"},
		{"garbage blocks", bytes.Repeat([]byte("x"), 2048), "archive"},
		{"cut inside a file", large[:2536], "archive"},
		{"cut inside a header", valid[:1024+100], "archive"},
		{"cut after the first file", valid[:1024], "missing"},
		{"duplicate file", buildTar(t, append(bundleEntries(meta), tarEntry{name: "ca.pem", body: []byte("other")})), "duplicate"},
		{"duplicate metadata", buildTar(t, append(bundleEntries(meta), tarEntry{name: "bundle.json", body: meta})), "duplicate"},
		{"unexpected file", buildTar(t, append(bundleEntries(meta), tarEntry{name: "extra.txt", body: []byte("x")})), "unexpected"},
		{"path outside the bundle", buildTar(t, append(bundleEntries(meta), tarEntry{name: "../ca.pem", body: []byte("x")})), "unexpected"},
		{"symlink instead of a file", buildTar(t, append(without(bundleEntries(meta), "ca.pem"), tarEntry{name: "ca.pem", typeflag: tar.TypeSymlink})), "not a regular file"},
		{"directory entry", buildTar(t, append(bundleEntries(meta), tarEntry{name: "pki/", typeflag: tar.TypeDir})), "not a regular file"},
		{"too many entries", buildTar(t, tooMany), "too many"},
		{"empty PEM file", buildTar(t, replace(bundleEntries(meta), "ca.pem", nil)), "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBundleTar(tt.data)
			requireErrorContaining(t, err, tt.want)
		})
	}
}

func TestBundleRejectsBadMetadata(t *testing.T) {
	tests := []struct {
		name string
		meta string
		want string
	}{
		{"not JSON", `not json`, "bundle.json"},
		{"a JSON array", `[1]`, "bundle.json"},
		{"trailing data", `{"version":1,"node_id":"n","mgmt_port":8443} {}`, "bundle.json"},
		{"unknown field", `{"version":1,"node_id":"n","mgmt_port":8443,"extra":true}`, "bundle.json"},
		{"port as a string", `{"version":1,"node_id":"n","mgmt_port":"8443"}`, "bundle.json"},
		{"no node id", `{"version":1,"mgmt_port":8443}`, "node id"},
		{"empty node id", `{"version":1,"node_id":"","mgmt_port":8443}`, "node id"},
		{"no port", `{"version":1,"node_id":"n"}`, "port"},
		{"port zero", `{"version":1,"node_id":"n","mgmt_port":0}`, "port"},
		{"port negative", `{"version":1,"node_id":"n","mgmt_port":-1}`, "port"},
		{"port above 65535", `{"version":1,"node_id":"n","mgmt_port":65536}`, "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBundleTar(buildTar(t, bundleEntries([]byte(tt.meta))))
			requireErrorContaining(t, err, tt.want)
		})
	}

	t.Run("the extreme valid ports", func(t *testing.T) {
		for _, port := range []int{1, 65535} {
			got, err := ParseBundleTar(buildTar(t, bundleEntries(metaJSON(1, "n", port))))
			if err != nil {
				t.Errorf("port %d: %v", port, err)
			} else if got.MgmtPort != port {
				t.Errorf("port = %d, want %d", got.MgmtPort, port)
			}
		}
	})
}

func TestBundleMarshalRejectsIncompleteBundles(t *testing.T) {
	p := newTestPKI(t)
	tests := []struct {
		name   string
		mutate func(*Bundle)
		want   string
	}{
		{"no node id", func(b *Bundle) { b.NodeID = "" }, "node id"},
		{"port zero", func(b *Bundle) { b.MgmtPort = 0 }, "port"},
		{"port above 65535", func(b *Bundle) { b.MgmtPort = 65536 }, "port"},
		{"no CA", func(b *Bundle) { b.CAPEM = nil }, "ca.pem"},
		{"no certificate", func(b *Bundle) { b.CertPEM = nil }, "node.pem"},
		{"no key", func(b *Bundle) { b.KeyPEM = nil }, "node-key.pem"},
		// MarshalTar must not produce what ParseBundleTar refuses.
		{"oversized key", func(b *Bundle) { b.KeyPEM = bytes.Repeat([]byte("x"), maxFile+1) }, "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBundle(p)
			tt.mutate(b)
			if _, err := b.MarshalTar(); err == nil {
				t.Error("MarshalTar succeeded")
			} else {
				requireErrorContaining(t, err, tt.want)
			}
		})
	}
}

// TestBundleCredentialsHandshake follows the credentials the way production
// does: the panel packs a node's certificate into a bundle, the node builds its
// server configuration from the bundle alone, and the panel connects, having
// remembered the node's fingerprint.
func TestBundleCredentialsHandshake(t *testing.T) {
	p := newTestPKI(t)
	archive, err := newTestBundle(p).MarshalTar()
	if err != nil {
		t.Fatal(err)
	}

	onNode, err := ParseBundleTar(archive)
	if err != nil {
		t.Fatal(err)
	}
	nodeCfg, err := ServerTLSConfig(onNode.CAPEM, onNode.CertPEM, onNode.KeyPEM)
	if err != nil {
		t.Fatalf("ServerTLSConfig from the bundle: %v", err)
	}
	srv := startEchoServer(t, nodeCfg)

	pin, err := Fingerprint(onNode.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	out := exchange(t, srv.addr, clientTLS(t, p, p.panel, "cdn.example.com", pin))
	if err := out.err(); err != nil {
		t.Fatalf("the panel cannot reach the node: %v", err)
	}
	if want := "hello postern-panel"; out.reply != want {
		t.Errorf("reply = %q, want %q", out.reply, want)
	}
}

func TestBundleDoesNotAliasInput(t *testing.T) {
	p := newTestPKI(t)
	b := newTestBundle(p)
	keyBefore := bytes.Clone(b.KeyPEM)

	data, err := b.MarshalTar()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBundleTar(data)
	if err != nil {
		t.Fatal(err)
	}
	// Scribbling over the archive must not change the parsed bundle, and
	// marshalling must not change the bundle.
	for i := range data {
		data[i] = 0
	}
	if !bytes.Equal(got.KeyPEM, keyBefore) {
		t.Error("the parsed bundle shares memory with the archive")
	}
	if !bytes.Equal(b.KeyPEM, keyBefore) {
		t.Error("MarshalTar modified the bundle")
	}
}
