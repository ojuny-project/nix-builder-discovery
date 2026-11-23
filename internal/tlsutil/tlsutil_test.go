package tlsutil

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
)

func TestPinnedHandshake(t *testing.T) {
	serverIdentity, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	clientIdentity, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}

	serverCertificate, err := serverIdentity.TLSCertificate()
	if err != nil {
		t.Fatalf("server certificate: %v", err)
	}
	clientCertificate, err := clientIdentity.TLSCertificate()
	if err != nil {
		t.Fatalf("client certificate: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	server := tls.Server(serverConn, ServerConfig(serverCertificate))
	client := tls.Client(clientConn, ClientConfig(clientCertificate, serverIdentity.Fingerprint()))

	errors := make(chan error, 2)

	go func() {
		errors <- server.Handshake()
	}()

	deadline := time.Now().Add(5 * time.Second)
	clientConn.SetDeadline(deadline)
	serverConn.SetDeadline(deadline)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errors; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	serverState := server.ConnectionState()
	fingerprint, err := PeerFingerprint(&serverState)
	if err != nil {
		t.Fatalf("peer fingerprint: %v", err)
	}
	if fingerprint != clientIdentity.Fingerprint() {
		t.Fatalf("peer fingerprint = %s, want %s", fingerprint, clientIdentity.Fingerprint())
	}
}

func TestWrongPinnedFingerprintFails(t *testing.T) {
	serverIdentity, _ := identity.LoadOrCreate(t.TempDir())
	clientIdentity, _ := identity.LoadOrCreate(t.TempDir())

	serverCertificate, _ := serverIdentity.TLSCertificate()
	clientCertificate, _ := clientIdentity.TLSCertificate()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	server := tls.Server(serverConn, ServerConfig(serverCertificate))
	client := tls.Client(clientConn, ClientConfig(clientCertificate, "WRONG"))

	go func() {
		server.Handshake()
	}()

	deadline := time.Now().Add(5 * time.Second)
	clientConn.SetDeadline(deadline)
	serverConn.SetDeadline(deadline)

	if err := client.Handshake(); err == nil {
		t.Fatal("expected the pinned fingerprint check to fail")
	}
}
