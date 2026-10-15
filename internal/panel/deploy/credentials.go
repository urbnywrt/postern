package deploy

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/sshx"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// sealedCredentials are the credentials that the panel keeps for a node, as
// JSON, sealed with the master key and the additional data "ssh:<node id>".
type sealedCredentials struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// credentialsAAD is the additional data that the credentials of a node are
// sealed with.
func credentialsAAD(nodeID string) []byte { return []byte("ssh:" + nodeID) }

// credentials returns what the panel logs in to the server of t with: the
// credentials of the request, or the ones that it keeps for the node, which are
// for the target that it keeps. A private key is read here, so that one that
// cannot be used is refused before anything is sent.
func (s *Service) credentials(nodeID string, c *panelv1.SshCredentials, t sshx.Target, stored *store.SSHTarget) (sshx.Auth, error) {
	if c.GetUseSaved() {
		if stored == nil || stored.AuthKind == store.SSHAuthNone || len(stored.SecretEnc) == 0 {
			return sshx.Auth{}, precondition("the panel keeps no credentials for this node")
		}
		if !sameServer(stored, t) || stored.User != t.User {
			return sshx.Auth{}, precondition("the saved credentials are for %s@%s", stored.User,
				net.JoinHostPort(stored.Host, strconv.FormatUint(uint64(stored.Port), 10)))
		}
		a, err := s.openCredentials(nodeID, stored.SecretEnc)
		if err != nil {
			return sshx.Auth{}, s.fail("could not open the saved SSH credentials of a node", err)
		}
		return a, nil
	}
	switch {
	case len(c.GetPassword()) > maxPassword:
		return sshx.Auth{}, invalid("the password is longer than %d bytes", maxPassword)
	case len(c.GetPrivateKey()) > maxPrivateKey:
		return sshx.Auth{}, invalid("the private key is larger than %d bytes", maxPrivateKey)
	case len(c.GetPassphrase()) > maxPassphrase:
		return sshx.Auth{}, invalid("the passphrase is longer than %d bytes", maxPassphrase)
	case c.GetPassword() == "" && c.GetPrivateKey() == "":
		return sshx.Auth{}, invalid("a password or a private key is needed to log in")
	}
	a := sshx.Auth{Password: c.GetPassword(), Passphrase: c.GetPassphrase()}
	if c.GetPrivateKey() != "" {
		a.PrivateKeyPEM = []byte(c.GetPrivateKey())
		if err := checkPrivateKey(a.PrivateKeyPEM, a.Passphrase); err != nil {
			return sshx.Auth{}, err
		}
	}
	return a, nil
}

// checkPrivateKey refuses a private key that cannot be read, or that its
// passphrase does not open. The errors hold nothing of the key.
func checkPrivateKey(pemBytes []byte, passphrase string) error {
	_, err := ssh.ParsePrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &missing):
		return invalid("the private key cannot be read: it must be in PEM, as ssh-keygen writes it")
	case passphrase == "":
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%w, and none was given", sshx.ErrKeyPassphrase))
	}
	_, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	switch {
	case errors.Is(err, x509.IncorrectPasswordError):
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%w, and the one given does not open it", sshx.ErrKeyPassphrase))
	case err != nil:
		return invalid("the private key cannot be read: it must be in PEM, as ssh-keygen writes it")
	}
	return nil
}

// sealCredentials seals credentials for a node, and says what they are.
func (s *Service) sealCredentials(nodeID string, a sshx.Auth) (kind string, enc []byte, err error) {
	kind = store.SSHAuthPassword
	if len(a.PrivateKeyPEM) > 0 {
		kind = store.SSHAuthKey
	}
	plain, err := json.Marshal(sealedCredentials{Password: a.Password, PrivateKey: string(a.PrivateKeyPEM), Passphrase: a.Passphrase})
	if err != nil {
		return "", nil, fmt.Errorf("encode the credentials: %w", err)
	}
	defer clear(plain)
	enc, err = seal.Seal(s.key, plain, credentialsAAD(nodeID))
	if err != nil {
		return "", nil, fmt.Errorf("seal the credentials: %w", err)
	}
	return kind, enc, nil
}

// openCredentials opens the credentials that the panel keeps for a node.
func (s *Service) openCredentials(nodeID string, enc []byte) (sshx.Auth, error) {
	plain, err := seal.Open(s.key, enc, credentialsAAD(nodeID))
	if err != nil {
		return sshx.Auth{}, fmt.Errorf("open the credentials: %w", err)
	}
	defer clear(plain)
	var c sealedCredentials
	if err := json.Unmarshal(plain, &c); err != nil {
		return sshx.Auth{}, errors.New("decode the credentials: they are not what the panel sealed")
	}
	a := sshx.Auth{Password: c.Password, Passphrase: c.Passphrase}
	if c.PrivateKey != "" {
		a.PrivateKeyPEM = []byte(c.PrivateKey)
	}
	return a, nil
}
