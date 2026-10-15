package proxies

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// The DnsCredentialService: the DNS provider tokens that the nodes issue the
// certificates of WEB proxies with. A token is sealed with the master key
// for its credential (dnsCredentialAAD), handed to the nodes inside the
// desired state (WebSettings.dns_credential) and never returned to an admin
// or logged.

var _ panelv1connect.DnsCredentialServiceHandler = (*Service)(nil)

// maxTokenLen bounds a token.
const maxTokenLen = 1024

// dnsCredentialAAD is the additional data that the token of a credential is
// sealed with: it opens for its own credential only.
func dnsCredentialAAD(id string) []byte {
	return []byte("dnscred:" + id)
}

// errDNSCredential marks a token that cannot be opened: a fault of the panel
// (another master key), not of the data.
var errDNSCredential = errors.New("a dns credential cannot be opened")

// OpenDNSToken opens the sealed token of a credential. Never log it.
func OpenDNSToken(key seal.Key, c *store.DNSCredential) (string, error) {
	plain, err := seal.Open(key, c.TokenEnc, dnsCredentialAAD(c.ID))
	if err != nil {
		return "", fmt.Errorf("%w: credential %s: %w", errDNSCredential, c.ID, err)
	}
	defer clear(plain)
	return string(plain), nil
}

// checkDNSProvider returns the provider of a credential: cloudflare, which is
// also what empty means.
func checkDNSProvider(s string) (string, error) {
	switch strings.TrimSpace(s) {
	case "", store.DNSProviderCloudflare:
		return store.DNSProviderCloudflare, nil
	}
	return "", invalid("provider must be cloudflare")
}

// checkToken returns a token without the spaces around it: 1 to 1024
// characters of valid UTF-8 without control characters. The error never
// quotes it.
func checkToken(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", invalid("token is empty")
	case !utf8.ValidString(s):
		return "", invalid("token is not valid UTF-8")
	case utf8.RuneCountInString(s) > maxTokenLen:
		return "", invalid("token has more than %d characters", maxTokenLen)
	case strings.IndexFunc(s, unicode.IsControl) >= 0:
		return "", invalid("token has a control character")
	}
	return s, nil
}

// checkCredentialName returns the name of a credential: 1 to 64 characters,
// as checkName has them, not empty.
func checkCredentialName(s string) (string, error) {
	name, err := checkName(s)
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", invalid("name is empty")
	}
	return name, nil
}

func dnsCredentialProto(c *store.DNSCredential) *panelv1.DnsCredential {
	return &panelv1.DnsCredential{
		Id:          c.ID,
		Name:        c.Name,
		Provider:    c.Provider,
		UsedBy:      uint32(min(c.UsedBy, 1<<32-1)), // bounded: fits a uint32
		CreatedUnix: c.CreatedAt.Unix(),
		UpdatedUnix: c.UpdatedAt.Unix(),
	}
}

// ListDnsCredentials returns every credential, without its token.
func (s *Service) ListDnsCredentials(ctx context.Context, _ *connect.Request[panelv1.ListDnsCredentialsRequest]) (*connect.Response[panelv1.ListDnsCredentialsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	list, err := s.db.ListDNSCredentials(ctx)
	if err != nil {
		return nil, s.fail("could not list the dns credentials", err)
	}
	resp := &panelv1.ListDnsCredentialsResponse{}
	for _, c := range list {
		resp.Credentials = append(resp.Credentials, dnsCredentialProto(c))
	}
	return connect.NewResponse(resp), nil
}

// CreateDnsCredential stores a credential with its token sealed.
func (s *Service) CreateDnsCredential(ctx context.Context, req *connect.Request[panelv1.CreateDnsCredentialRequest]) (*connect.Response[panelv1.CreateDnsCredentialResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	c := &store.DNSCredential{}
	if c.Name, err = checkCredentialName(req.Msg.GetName()); err != nil {
		return nil, err
	}
	if c.Provider, err = checkDNSProvider(req.Msg.GetProvider()); err != nil {
		return nil, err
	}
	token, err := checkToken(req.Msg.GetToken())
	if err != nil {
		return nil, err
	}
	c.ID = newID()
	if c.TokenEnc, err = seal.Seal(s.key, []byte(token), dnsCredentialAAD(c.ID)); err != nil {
		return nil, s.fail("could not seal a dns token", err)
	}
	if err := s.db.CreateDNSCredential(ctx, c); err != nil {
		return nil, s.fail("could not store a dns credential", err)
	}
	s.audit(ctx, admin.ID, "dns_credential.create", "dns_credential:"+c.ID, "")
	s.log.Info("dns credential created", "credential", c.ID, "provider", c.Provider, "admin", admin.ID)
	return connect.NewResponse(&panelv1.CreateDnsCredentialResponse{Credential: dnsCredentialProto(c)}), nil
}

// UpdateDnsCredential changes the name or the token of a credential. A new
// token raises the desired generation of every node that has a proxy using
// the credential, so that the nodes get it.
func (s *Service) UpdateDnsCredential(ctx context.Context, req *connect.Request[panelv1.UpdateDnsCredentialRequest]) (*connect.Response[panelv1.UpdateDnsCredentialResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	var name, token *string
	if msg.Name != nil {
		n, err := checkCredentialName(msg.GetName())
		if err != nil {
			return nil, err
		}
		name = &n
	}
	if msg.Token != nil {
		t, err := checkToken(msg.GetToken())
		if err != nil {
			return nil, err
		}
		token = &t
	}
	c, err := s.db.DNSCredentialByID(ctx, msg.GetId())
	if err != nil {
		return nil, s.readError("dns credential", err)
	}
	changed := false
	if name != nil && *name != c.Name {
		c.Name = *name
		changed = true
	}
	if token != nil {
		if c.TokenEnc, err = seal.Seal(s.key, []byte(*token), dnsCredentialAAD(c.ID)); err != nil {
			return nil, s.fail("could not seal a dns token", err)
		}
		changed = true
	}
	if !changed {
		return connect.NewResponse(&panelv1.UpdateDnsCredentialResponse{Credential: dnsCredentialProto(c)}), nil
	}
	if err := s.db.UpdateDNSCredential(ctx, c); err != nil {
		return nil, s.readError("dns credential", err)
	}
	s.audit(ctx, admin.ID, "dns_credential.update", "dns_credential:"+c.ID, "")
	if token != nil {
		s.log.Info("dns credential token replaced", "credential", c.ID, "admin", admin.ID)
		s.raiseNodesUsing(ctx, c.ID)
	}
	return connect.NewResponse(&panelv1.UpdateDnsCredentialResponse{Credential: dnsCredentialProto(c)}), nil
}

// raiseNodesUsing raises the desired generation of every node that has a
// proxy using the credential and tells the notifier, so that the nodes get
// the new token. A node that cannot be raised is logged: the token reaches
// it with its next change.
func (s *Service) raiseNodesUsing(ctx context.Context, credentialID string) {
	nodes, err := s.db.NodesUsingDNSCredential(ctx, credentialID)
	if err != nil {
		s.log.Error("could not find the nodes that use a dns credential", "credential", credentialID, "err", err)
		return
	}
	for _, nodeID := range nodes {
		if _, err := s.nextGen(ctx, nodeID); err != nil {
			s.log.Error("could not raise the desired generation of a node after a dns token change", "node", nodeID, "err", err)
			continue
		}
		if s.notifier != nil {
			s.notifier.Notify(nodeID)
		}
	}
}

// DeleteDnsCredential deletes a credential that no proxy uses.
func (s *Service) DeleteDnsCredential(ctx context.Context, req *connect.Request[panelv1.DeleteDnsCredentialRequest]) (*connect.Response[panelv1.DeleteDnsCredentialResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	err = s.db.DeleteDNSCredential(ctx, req.Msg.GetId())
	switch {
	case errors.Is(err, store.ErrConflict):
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("proxies still use the dns credential: give them another one first"))
	case err != nil:
		return nil, s.readError("dns credential", err)
	}
	s.audit(ctx, admin.ID, "dns_credential.delete", "dns_credential:"+req.Msg.GetId(), "")
	s.log.Info("dns credential deleted", "credential", req.Msg.GetId(), "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteDnsCredentialResponse{}), nil
}
