package nodes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
)

// A join token lets a node that is installed with one docker run join the
// panel with a key of its own: see [Service.MintJoinToken] and [Service.Join].
const (
	joinTokenBytes = 32
	joinTokenLen   = 43 // joinTokenBytes in unpadded base64url
	joinTokenTTL   = 24 * time.Hour

	// joinKeyPrefix is the prefix of the limiter keys of joins: the address of
	// the client as auth.IPKey gives it.
	joinKeyPrefix = "join-ip:"

	maxJoinVersionLen = 64
)

// The answers of Join to a token that does not let the node in.
var (
	errJoinTokenInvalid = connect.NewError(connect.CodeUnauthenticated, errors.New("the join token is not valid"))
	errJoinTokenExpired = connect.NewError(connect.CodeUnauthenticated,
		errors.New("the join token has expired: get a new install command in the panel"))
	errJoinTokenUsed = connect.NewError(connect.CodeUnauthenticated, errors.New("the join token was used already"))
)

// joinVersionRe is what a node may say its version is: what the preflight of
// an SSH install accepts as a version.
var joinVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)

var _ panelv1connect.JoinServiceHandler = (*Service)(nil)

// MintJoinToken makes a new join token for a node, valid for 24 hours, and
// stores its hash in place of the node's previous token, which stops working
// at once. The token itself is returned and nowhere kept or logged. Errors
// are Connect errors.
// The audit row names the admin of the request in ctx.
func (s *Service) MintJoinToken(ctx context.Context, nodeID string) (token string, expires time.Time, err error) {
	return s.MintJoinTokenBy(ctx, nodeID, adminIDOf(ctx))
}

// MintJoinTokenBy is MintJoinToken for adminID, which the audit row names:
// for a caller that is not the request of the admin, such as the job of an
// SSH install, whose context outlives the request.
func (s *Service) MintJoinTokenBy(ctx context.Context, nodeID, adminID string) (token string, expires time.Time, err error) {
	var raw [joinTokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", time.Time{}, s.fail("could not make a join token", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	now := time.Now()
	t := &store.JoinToken{NodeID: nodeID, TokenHash: joinTokenHash(token), CreatedAt: now, ExpiresAt: now.Add(joinTokenTTL)}
	if err := s.db.PutJoinToken(ctx, t); err != nil {
		return "", time.Time{}, s.storeError("could not store a join token", err)
	}
	s.audit(ctx, adminID, "node.join_token", nodeID)
	s.log.Info("join token made", "node", nodeID, "expires", t.ExpiresAt)
	return token, t.ExpiresAt, nil
}

// joinTokenHash is what the store keeps of a token: the SHA-256 of its text.
func joinTokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Join lets a node in with a join token and a certificate request for a key
// of its own, and answers with the node's certificate and the CA. Anybody can
// call it: its answers "not valid" are counted per client address with the
// limiter of the sign-in, so that tokens cannot be guessed.
func (s *Service) Join(ctx context.Context, req *connect.Request[panelv1.JoinRequest]) (*connect.Response[panelv1.JoinResponse], error) {
	ip, known := s.callerIP(ctx)
	ip = ip.Unmap().WithZone("")
	key, source := joinKeyPrefix+"unknown", "unknown"
	if known {
		key, source = joinKeyPrefix+auth.IPKey(ip), ip.String()
	}
	att, err := s.joinLimits.Begin(key)
	if err != nil {
		return nil, err
	}
	defer att.Release()

	resp, err := s.join(ctx, req.Msg, ip, known, source)
	if err != nil {
		// Only a token that is not valid counts against the address: that is
		// what guessing looks like. An expired or used token, or a bad request
		// with a good one, can only come from a holder of the token (a node
		// that restarts with it, say), and must not lock its address out.
		if errors.Is(err, errJoinTokenInvalid) {
			att.Fail()
		}
		return nil, err
	}
	att.Succeed()
	return connect.NewResponse(resp), nil
}

// join is Join without the limiter. Its errors are Connect errors.
func (s *Service) join(ctx context.Context, msg *panelv1.JoinRequest, ip netip.Addr, known bool, source string) (*panelv1.JoinResponse, error) {
	token := msg.GetToken()
	if len(token) != joinTokenLen {
		return nil, errJoinTokenInvalid
	}
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != joinTokenBytes {
		return nil, errJoinTokenInvalid
	}
	hash := joinTokenHash(token)
	tok, err := s.db.JoinTokenByHash(ctx, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errJoinTokenInvalid
	case err != nil:
		return nil, s.fail("could not read a join token", err)
	}
	now := time.Now()
	if !now.Before(tok.ExpiresAt) {
		return nil, errJoinTokenExpired
	}

	pub, err := pki.ParseServerCSR(msg.GetCsr())
	if err != nil {
		return nil, invalid("csr: %v", err)
	}
	if a := msg.GetArch(); a != "amd64" && a != "arm64" {
		return nil, invalid("arch must be amd64 or arm64")
	}
	if !joinVersionRe.MatchString(msg.GetVersion()) {
		return nil, invalid("version must be 1 to %d letters, digits and . + ~ _ -", maxJoinVersionLen)
	}
	keyHash, err := publicKeyHash(pub)
	if err != nil {
		return nil, s.fail("could not encode a public key", err)
	}

	if tok.Used() {
		return s.joinAgain(ctx, tok, keyHash, now)
	}

	certPEM, err := s.ca.SignServerCSR(msg.GetCsr(), nodeCommonName(tok.NodeID), []string{nodeDNSName(tok.NodeID)})
	if err != nil {
		return nil, s.fail("could not sign a node certificate", err)
	}
	fingerprint, err := pki.Fingerprint(certPEM)
	if err != nil {
		return nil, s.fail("could not take the fingerprint of a node certificate", err)
	}
	j := store.NodeJoin{
		NodeID: tok.NodeID, TokenHash: hash, UsedKey: keyHash, At: now,
		CertPEM: string(certPEM), CertFingerprint: fingerprint,
	}
	if known && s.joinHostOK(ip) {
		if s.cloudflare != nil && s.cloudflare.Contains(ip) {
			// The panel is behind the proxy of Cloudflare: the address is one
			// of Cloudflare, not of the node. The node page asks for the host.
			s.log.Info("join through Cloudflare: the management host is not filled", "node", tok.NodeID)
		} else {
			j.MgmtHost = ip.String()
		}
	}
	n, err := s.db.ApplyJoin(ctx, j)
	switch {
	case errors.Is(err, store.ErrConflict):
		// Another join consumed the token in the meantime (or it was replaced or
		// expired): the token is looked at again, which answers the same as a
		// join that came after that one.
		tok, err := s.db.JoinTokenByHash(ctx, hash)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, errJoinTokenInvalid
		case err != nil:
			return nil, s.fail("could not read a join token", err)
		case !tok.Used():
			return nil, errJoinTokenExpired
		}
		return s.joinAgain(ctx, tok, keyHash, time.Now())
	case errors.Is(err, store.ErrNotFound):
		return nil, errJoinTokenInvalid // the node was deleted meanwhile
	case err != nil:
		return nil, s.fail("could not store a join", err)
	}

	s.auditDetails(ctx, "", "node.join", n.ID, map[string]string{
		"source":  source,
		"arch":    msg.GetArch(),
		"version": msg.GetVersion(),
	})
	s.log.Info("node joined", "node", n.ID, "source", source, "arch", msg.GetArch(), "version", msg.GetVersion(),
		"mgmt_host_set", j.MgmtHost != "")
	s.notify(n.ID)
	return &panelv1.JoinResponse{NodeId: n.ID, MgmtPort: n.MgmtPort, CaPem: s.ca.CertPEM, CertPem: []byte(n.CertPEM)}, nil
}

// joinAgain answers a join with a token that was used already. When it is the
// same key that used it, the token has not expired, and the node still has
// the certificate of that join, the answer is that certificate: the node lost
// the answer to its join and asks again. Anything else is refused.
func (s *Service) joinAgain(ctx context.Context, tok *store.JoinToken, keyHash []byte, now time.Time) (*panelv1.JoinResponse, error) {
	if !tok.SameKey(keyHash) || !now.Before(tok.ExpiresAt) {
		return nil, errJoinTokenUsed
	}
	n, err := s.db.NodeByID(ctx, tok.NodeID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errJoinTokenInvalid
	case err != nil:
		return nil, s.fail("could not read a node", err)
	}
	if !certHasKey(n.CertPEM, keyHash) {
		return nil, errJoinTokenUsed
	}
	return &panelv1.JoinResponse{NodeId: n.ID, MgmtPort: n.MgmtPort, CaPem: s.ca.CertPEM, CertPem: []byte(n.CertPEM)}, nil
}

// AddrRanges is a set of address ranges, such as the ranges of Cloudflare
// that the panel keeps (preflight.CloudflareRanges).
type AddrRanges interface {
	Contains(netip.Addr) bool
}

// WithCloudflareRanges gives the panel the address ranges of Cloudflare: a
// join from one of them does not fill the management host of the node, since
// it came through the proxy of Cloudflare and not from the node.
func WithCloudflareRanges(r AddrRanges) Option {
	return func(s *Service) { s.cloudflare = r }
}

// publicKeyHash is the SHA-256 of the PKIX DER encoding of a public key.
func publicKeyHash(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

// certHasKey reports whether the certificate in certPEM is for the public key
// whose hash is keyHash.
func certHasKey(certPEM string, keyHash []byte) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	h, err := publicKeyHash(cert.PublicKey)
	return err == nil && bytes.Equal(h, keyHash)
}

// nonPublicPrefixes are the addresses that a join does not take as the
// management address of a node, beyond what netip tells apart (private,
// loopback, link-local, unspecified, multicast): shared address space (CGNAT)
// and the documentation ranges.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT, RFC 6598
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("2001:db8::/32"),   // RFC 3849
	netip.MustParsePrefix("3fff::/20"),       // RFC 9637
}

// publicUnicast reports whether a node that joins from ip can be reached
// there: a global unicast address that is not private, loopback, link-local,
// CGNAT, documentation or unspecified.
func publicUnicast(ip netip.Addr) bool { return publicUnicastExcept(ip, nonPublicPrefixes) }

func publicUnicastExcept(ip netip.Addr, excluded []netip.Prefix) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range excluded {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
