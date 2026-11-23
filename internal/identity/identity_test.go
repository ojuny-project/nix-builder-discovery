package identity

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("fingerprint changed: %s != %s", first.Fingerprint(), second.Fingerprint())
	}
	if first.PublicKeyBase64() != second.PublicKeyBase64() {
		t.Fatalf("public key changed")
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("load: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("key mode = %04o, want 0400", got)
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("load: %v", err)
	}

	path := filepath.Join(dir, keyFile)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("expected an error for a group or world readable key")
	}
}

func TestSignVerify(t *testing.T) {
	identity, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	message := []byte("payload")
	signature := identity.Sign(message)

	if !Verify(identity.PublicKey(), message, signature) {
		t.Fatal("signature did not verify")
	}
	if Verify(identity.PublicKey(), []byte("other"), signature) {
		t.Fatal("signature verified for a different message")
	}
}

func TestCertificateMatchesIdentity(t *testing.T) {
	identity, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	certificate, err := identity.TLSCertificate()
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}

	leaf := certificate.Leaf
	if leaf == nil {
		t.Fatal("certificate has no parsed leaf")
	}

	public, err := PublicKeyFromCertificate(leaf)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	if FingerprintOf(public) != identity.Fingerprint() {
		t.Fatalf("certificate fingerprint does not match identity")
	}

	message := []byte("challenge")
	signature := identity.Sign(message)
	if !Verify(public, message, signature) {
		t.Fatal("certificate key did not verify the identity signature")
	}
}

func TestParsePublicKey(t *testing.T) {
	identity, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	decoded, err := ParsePublicKey(base64.StdEncoding.EncodeToString(identity.PublicKey()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if FingerprintOf(decoded) != identity.Fingerprint() {
		t.Fatal("parsed key has a different fingerprint")
	}

	if _, err := ParsePublicKey("not base64"); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
}

func TestFingerprintLength(t *testing.T) {
	identity, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(identity.Fingerprint()) != FingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", len(identity.Fingerprint()), FingerprintLength)
	}
	if len(identity.ShortID()) != ShortIDLength {
		t.Fatalf("short ID length = %d, want %d", len(identity.ShortID()), ShortIDLength)
	}
}
