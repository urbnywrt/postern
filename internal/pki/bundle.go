package pki

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
)

// BundleVersion is the bundle format this package reads and writes.
const BundleVersion = 1

// The files of a bundle. The key is mode 0600 in the archive, so unpacking it
// with a plain tar leaves it private.
const (
	bundleMetaFile = "bundle.json"
	bundleCAFile   = "ca.pem"
	bundleCertFile = "node.pem"
	bundleKeyFile  = "node-key.pem"
)

// Limits on untrusted input. A real bundle is a few kilobytes; these only have
// to stop an archive from making the node allocate without bound.
const (
	maxBundleFileSize = 64 << 10 // any one file
	maxBundleEntries  = 8        // archive entries read; a version 1 bundle has 4
)

// Bundle is what a node needs to be installed: its identity, the port it
// serves management on, the CA that vouches for the panel, and the node's own
// server certificate and private key.
//
// A bundle contains a private key. Treat it as a secret.
type Bundle struct {
	// Version is the format version. Zero means BundleVersion when marshalling.
	// Parsing returns BundleVersion or fails.
	Version  int
	NodeID   string
	MgmtPort int
	// CAPEM is the CA certificate. CertPEM and KeyPEM are the node's server
	// certificate and its private key.
	CAPEM, CertPEM, KeyPEM []byte
}

// bundleMeta is the content of bundle.json.
type bundleMeta struct {
	Version  int    `json:"version"`
	NodeID   string `json:"node_id"`
	MgmtPort int    `json:"mgmt_port"`
}

// MarshalTar returns the bundle as a tar archive of four files: bundle.json
// ({version, node_id, mgmt_port}), ca.pem, node.pem and node-key.pem. The
// archive is a flat USTAR file that GNU tar and busybox both unpack.
func (b *Bundle) MarshalTar() ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	meta, err := json.Marshal(bundleMeta{Version: BundleVersion, NodeID: b.NodeID, MgmtPort: b.MgmtPort})
	if err != nil {
		return nil, fmt.Errorf("pki: bundle: encode %s: %w", bundleMetaFile, err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{bundleMetaFile, meta},
		{bundleCAFile, b.CAPEM},
		{bundleCertFile, b.CertPEM},
		{bundleKeyFile, b.KeyPEM},
	} {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.name,
			Mode:     0o600,
			Size:     int64(len(f.data)),
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("pki: bundle: write %s: %w", f.name, err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, fmt.Errorf("pki: bundle: write %s: %w", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("pki: bundle: finish archive: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseBundleTar reads a bundle from a tar archive made by MarshalTar.
//
// It is strict, because the archive comes from outside: it rejects versions
// other than BundleVersion, missing, empty, duplicate and unexpected files,
// anything but regular files, files larger than 64 KiB, and metadata that is
// not exactly what MarshalTar writes. The returned bundle shares no memory with
// data.
func ParseBundleTar(data []byte) (*Bundle, error) {
	files, err := readBundleFiles(data)
	if err != nil {
		return nil, err
	}

	rawMeta, ok := files[bundleMetaFile]
	if !ok {
		return nil, missingFile(bundleMetaFile)
	}
	// The version comes first. A bundle of a newer format may lay its files out
	// differently, and what the operator needs to hear then is that this build
	// is too old, not that a file it never heard of is unexpected.
	var probe struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(rawMeta, &probe); err != nil {
		return nil, fmt.Errorf("pki: bundle: parse %s: %w", bundleMetaFile, err)
	}
	if probe.Version == nil {
		return nil, fmt.Errorf("pki: bundle: %s has no version", bundleMetaFile)
	}
	if *probe.Version != BundleVersion {
		return nil, unsupportedVersion(*probe.Version)
	}

	for _, name := range slices.Sorted(maps.Keys(files)) {
		switch name {
		case bundleMetaFile, bundleCAFile, bundleCertFile, bundleKeyFile:
		default:
			return nil, fmt.Errorf("pki: bundle: unexpected file %q", name)
		}
	}
	for _, name := range []string{bundleCAFile, bundleCertFile, bundleKeyFile} {
		if _, ok := files[name]; !ok {
			return nil, missingFile(name)
		}
	}

	var meta bundleMeta
	dec := json.NewDecoder(bytes.NewReader(rawMeta))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("pki: bundle: parse %s: %w", bundleMetaFile, err)
	}
	b := &Bundle{
		Version:  meta.Version,
		NodeID:   meta.NodeID,
		MgmtPort: meta.MgmtPort,
		CAPEM:    files[bundleCAFile],
		CertPEM:  files[bundleCertFile],
		KeyPEM:   files[bundleKeyFile],
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// validate checks what both directions require of a bundle. The PEM files are
// only checked for being there: whether they hold a usable certificate is for
// ServerTLSConfig to find out.
func (b *Bundle) validate() error {
	if b.Version != 0 && b.Version != BundleVersion {
		return unsupportedVersion(b.Version)
	}
	if b.NodeID == "" {
		return errors.New("pki: bundle: node id is empty")
	}
	if b.MgmtPort < 1 || b.MgmtPort > 65535 {
		return fmt.Errorf("pki: bundle: management port %d is out of range", b.MgmtPort)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{bundleCAFile, b.CAPEM},
		{bundleCertFile, b.CertPEM},
		{bundleKeyFile, b.KeyPEM},
	} {
		switch {
		case len(f.data) == 0:
			return fmt.Errorf("pki: bundle: %s is empty", f.name)
		case len(f.data) > maxBundleFileSize:
			return fmt.Errorf("pki: bundle: %s is too large (%d bytes, at most %d)", f.name, len(f.data), maxBundleFileSize)
		}
	}
	return nil
}

// readBundleFiles reads the archive into memory, within limits: regular files
// only, at most maxBundleEntries of them, none larger than maxBundleFileSize,
// and each name once. It does not look at the names beyond that; a hostile
// name is harmless because nothing is ever unpacked to disk here.
func readBundleFiles(data []byte) (map[string][]byte, error) {
	files := make(map[string][]byte)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("pki: bundle: read archive: %w", err)
		}
		if len(files) == maxBundleEntries {
			return nil, fmt.Errorf("pki: bundle: too many files (more than %d)", maxBundleEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("pki: bundle: %q is not a regular file", hdr.Name)
		}
		if _, dup := files[hdr.Name]; dup {
			return nil, fmt.Errorf("pki: bundle: duplicate file %q", hdr.Name)
		}
		if hdr.Size > maxBundleFileSize {
			return nil, fmt.Errorf("pki: bundle: %s is too large (%d bytes, at most %d)", hdr.Name, hdr.Size, maxBundleFileSize)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("pki: bundle: read archive: %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = body
	}
}

func missingFile(name string) error {
	return fmt.Errorf("pki: bundle: missing file %q", name)
}

func unsupportedVersion(version int) error {
	return fmt.Errorf("pki: bundle: unsupported bundle version %d (this build understands version %d)", version, BundleVersion)
}
