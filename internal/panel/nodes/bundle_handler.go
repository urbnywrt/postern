package nodes

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

// BundleRoute is the pattern under which the panel serves [Service.BundleHandler]
// in an [http.ServeMux]. The handler reads the id of the node from {id}.
const BundleRoute = "GET /api/nodes/{id}/bundle.tar"

// bundleFileName is the name that the bundle is downloaded as, and the one
// that installCommand expects.
const bundleFileName = "postern-node-bundle.tar"

// ErrNoBundle is the error of [Service.Bundle] for a node that has no
// certificate.
var ErrNoBundle = errors.New("the node has no certificate")

// ErrJoinedNode is the error of [Service.Bundle] for a node that joined with a
// key of its own (see [Service.Join]): the panel has its certificate but no
// key. It is an [ErrNoBundle] too.
var ErrJoinedNode error = joinedNodeError{}

type joinedNodeError struct{}

func (joinedNodeError) Error() string {
	return "the node joined with a key of its own, so the panel has no key for it"
}

func (joinedNodeError) Is(target error) bool { return target == ErrNoBundle }

// BundleURL is the path at which an admin downloads the bundle of a node.
func BundleURL(nodeID string) string {
	return "/api/nodes/" + url.PathEscape(nodeID) + "/bundle.tar"
}

// BundleHandler serves the bundle of a node, postern-node-bundle.tar, as an
// attachment: the CA certificate, the certificate and private key of the
// node, and its management port (see [pki.Bundle]).
//
// The bundle holds a private key, so the handler is wrapped in
// [auth.RequireAdmin]: a request without an admin session gets a 401. The
// route is not a Connect procedure, which the auth middleware would guard by
// itself, so the handler is mounted behind the middleware, which finds the
// admin, with a pattern that has {id}: [BundleRoute] on the outer mux, or
// "GET /nodes/{id}/bundle.tar" behind a prefix of /api that is stripped. An
// unknown node is a 404, a node without a certificate a 409.
func (s *Service) BundleHandler() http.Handler {
	return auth.RequireAdmin(http.HandlerFunc(s.serveBundle))
}

func (s *Service) serveBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	b, err := s.bundle(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound) || id == "":
		http.Error(w, "no such node", http.StatusNotFound)
		return
	case errors.Is(err, ErrJoinedNode):
		http.Error(w, "the node joined with a key of its own, so the panel has no bundle for it; get a new install command instead", http.StatusConflict)
		return
	case errors.Is(err, ErrNoBundle):
		http.Error(w, "the node has no certificate, so there is no bundle for it", http.StatusConflict)
		return
	case err != nil:
		s.log.Error("could not make a node bundle", "node", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := b.MarshalTar()
	clear(b.KeyPEM)
	if err != nil {
		s.log.Error("could not make a node bundle", "node", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	adminID := adminIDOf(r.Context())
	s.audit(r.Context(), adminID, "node.bundle", id)
	s.log.Info("node bundle downloaded", "node", id, "admin", adminID)
	h := w.Header()
	h.Set("Content-Type", "application/x-tar")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": bundleFileName}))
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data) // the client is gone if this fails
	}
	clear(data)
}

// adminIDOf is the id of the admin of a request that auth.RequireAdmin let
// through, for the audit log.
func adminIDOf(ctx context.Context) string {
	if a, ok := auth.AdminFrom(ctx); ok {
		return a.ID
	}
	return ""
}

// bundle builds the bundle of a node from what is stored: the certificate of
// the node, its key opened, and the CA certificate. The certificate is not
// reissued, so every download is the same bundle. A node without a
// certificate is ErrNoBundle, a node that does not exist store.ErrNotFound.
func (s *Service) bundle(ctx context.Context, id string) (*pki.Bundle, error) {
	n, err := s.db.NodeByID(ctx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case n.CertPEM == "":
		return nil, ErrNoBundle
	case len(n.KeyEnc) == 0:
		return nil, ErrJoinedNode
	}
	keyPEM, err := seal.Open(s.key, n.KeyEnc, nodeKeyAAD(n.ID))
	if err != nil {
		return nil, err
	}
	return &pki.Bundle{
		NodeID:   n.ID,
		MgmtPort: int(n.MgmtPort),
		CAPEM:    s.ca.CertPEM,
		CertPEM:  []byte(n.CertPEM),
		KeyPEM:   keyPEM,
	}, nil
}
