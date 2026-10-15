package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

const (
	evCertImported = "cert_imported"
	// maxPEMBytes is the most bytes of either PEM of PutCertificate: a chain
	// of a few certificates is some kilobytes, a key less.
	maxPEMBytes = 64 << 10
)

// PutCertificate stores an imported certificate (Ruling S3-1) under
// data/certs/<domain>/ through the ACME manager's Put: the pair is checked,
// the key is written 0600, the same files are not written again, and an
// issuance of the domain that runs ends first. When the files change, the
// reconciler is asked for a pass, so that the route of the proxy whose
// cert_sha256 the chain matches is served at once. Nothing of the files is
// logged.
func (s *Service) PutCertificate(ctx context.Context, req *connect.Request[nodev1.PutCertificateRequest]) (*connect.Response[nodev1.PutCertificateResponse], error) {
	domain := req.Msg.GetDomain()
	if len(req.Msg.GetFullchainPem()) > maxPEMBytes || len(req.Msg.GetKeyPem()) > maxPEMBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the certificate chain and the key must each be at most 64 KiB"))
	}
	res, err := s.certs.Put(ctx, domain, req.Msg.GetFullchainPem(), req.Msg.GetKeyPem())
	if err != nil {
		if ctx.Err() != nil {
			return nil, connect.NewError(connect.CodeCanceled, err)
		}
		s.log.Warn("agent: certificate refused", "domain", domain, "err", err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if res.Stored {
		s.log.Info("agent: certificate stored", "domain", domain, "sha256", res.SHA256, "not_after", res.NotAfter.UTC().Format(time.RFC3339))
		s.event(evCertImported, sevInfo, fmt.Sprintf("certificate of %s stored (expires %s)", domain, res.NotAfter.UTC().Format(time.RFC3339)),
			map[string]string{"domain": domain, "sha256": res.SHA256})
		s.trigger()
	}
	return connect.NewResponse(&nodev1.PutCertificateResponse{
		Sha256: res.SHA256, Stored: res.Stored, NotAfter: res.NotAfter.UTC().Format(time.RFC3339),
	}), nil
}
