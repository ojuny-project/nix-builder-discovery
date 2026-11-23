package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
)

// ServerConfig requires a client certificate. Trust is checked by the handler
// against the pinned fingerprint, not by the certificate chain.
func ServerConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientConfig pins one server certificate fingerprint and presents the
// device certificate.
func ClientConfig(certificate tls.Certificate, expectedFingerprint string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tls: server sent no certificate")
			}

			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("tls: parse server certificate: %w", err)
			}

			public, err := identity.PublicKeyFromCertificate(leaf)
			if err != nil {
				return err
			}
			if got := identity.FingerprintOf(public); got != expectedFingerprint {
				return fmt.Errorf("tls: server fingerprint %s does not match %s", got, expectedFingerprint)
			}

			return nil
		},
	}
}

// PeerFingerprint returns the fingerprint of the client certificate.
func PeerFingerprint(state *tls.ConnectionState) (string, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", errors.New("tls: connection has no peer certificate")
	}

	public, err := identity.PublicKeyFromCertificate(state.PeerCertificates[0])
	if err != nil {
		return "", err
	}

	return identity.FingerprintOf(public), nil
}
