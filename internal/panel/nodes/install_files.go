package nodes

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urbnywrt/postern/internal/pki"
)

// The files that a node is installed from, for an install that does not go
// through the downloads: the panel itself copies them to the server over SSH
// (internal/panel/deploy).

// ErrNoKit is the error of [Service.OpenKit] for an architecture whose node kit
// the panel does not have.
var ErrNoKit = errors.New("the panel has no node kit for this architecture")

// A KitFile is one file of the node kit of an architecture, open. Reading it
// gives exactly Size bytes, the size that the file had when it was opened; a
// file that got shorter since fails to read instead of ending early.
type KitFile struct {
	Name string // postern-node, install.sh, launcher.sh or compose.yaml
	Size int64

	r    io.Reader
	left int64
}

func (f *KitFile) Read(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > f.left {
		p = p[:f.left]
	}
	n, err := f.r.Read(p)
	f.left -= int64(n)
	switch {
	case errors.Is(err, io.EOF) && f.left > 0:
		return n, fmt.Errorf("%w: %s", errKitChanged, f.Name)
	case errors.Is(err, io.EOF):
		return n, nil // the next call says EOF
	}
	return n, err
}

// A Kit is the node kit of one architecture, with its files open, in the order
// of the tar of the download: postern-node, install.sh, launcher.sh,
// compose.yaml. Close it when it is done.
type Kit struct {
	Arch  string
	Files []*KitFile

	opened *openedKit
}

// Close closes the files of the kit.
func (k *Kit) Close() {
	k.opened.close()
}

// OpenKit opens the node kit of arch, amd64 or arm64, as the download would
// serve it. When the panel has no kit for arch, the error is [ErrNoKit] and
// says what is missing.
func (s *Service) OpenKit(arch string) (*Kit, error) {
	opened, err := openKit(s.kitDir, arch)
	return kitOf(arch, opened, err)
}

// OpenKitFor is [Service.OpenKit] with the node binary of the kit source
// ([WithKitSource]): the running panel's version, which is what an install
// sends.
func (s *Service) OpenKitFor(ctx context.Context, arch string) (*Kit, error) {
	opened, err := s.openKitFor(ctx, arch)
	return kitOf(arch, opened, err)
}

func kitOf(arch string, opened *openedKit, err error) (*Kit, error) {
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %w", ErrNoKit, arch, err)
	}
	k := &Kit{Arch: arch, opened: opened}
	for i, m := range kitMembers {
		k.Files = append(k.Files, &KitFile{Name: m.name, Size: opened.sizes[i], r: opened.files[i], left: opened.sizes[i]})
	}
	return k, nil
}

// Bundle returns the bundle of a node, the same that its download serves: the
// CA certificate, and the certificate of the node with its private key,
// opened. The caller clears KeyPEM once it is done with it. A node that does
// not exist is store.ErrNotFound, one without a certificate [ErrNoBundle].
func (s *Service) Bundle(ctx context.Context, nodeID string) (*pki.Bundle, error) {
	return s.bundle(ctx, nodeID)
}
