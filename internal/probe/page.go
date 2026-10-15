package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

// PageOptions tune Page.
type PageOptions struct {
	// VerifyChain checks the certificate chain as a client does (RootCAs, or
	// the system's roots); without it only the name of the certificate is
	// checked (a node's own chain is not the point).
	VerifyChain bool
	RootCAs     *x509.CertPool
	// HTTP2 offers HTTP/2 only, as a browser that reaches the page does: an
	// answer over HTTP/1.1 is not one.
	HTTP2 bool
}

// maxPageBody is how much of the page Page reads before it lets it go.
const maxPageBody = 64 << 10

// Page makes an HTTPS GET of "/" for the host sni at addr ("host:port") and
// returns nil when the page answers 200: the decoy of a WEB proxy serves, not
// only its TLS. ctx bounds it. The error
// holds no secret.
func Page(ctx context.Context, addr, sni string, opt PageOptions) error {
	cfg := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12, RootCAs: opt.RootCAs}
	if !opt.VerifyChain {
		cfg.InsecureSkipVerify = true // the name is checked in VerifyConnection; the chain is not the point of the check
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			if err := cs.PeerCertificates[0].VerifyHostname(sni); err != nil {
				return fmt.Errorf("the certificate is not for the domain: %w", err)
			}
			return nil
		}
	}
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	if !opt.HTTP2 {
		protocols.SetHTTP1(true)
	}
	tr := &http.Transport{
		TLSClientConfig:   cfg,
		Protocols:         &protocols,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+sni+"/", nil)
	if err != nil {
		return err
	}
	req.Host = sni
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if uerr := (*url.Error)(nil); errors.As(err, &uerr) {
			err = uerr.Err // without the URL, which is made up
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPageBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET / answered %s", resp.Status)
	}
	return nil
}
