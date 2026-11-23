package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	keyFile = "identity.key"

	// FingerprintLength is the number of characters in a full fingerprint.
	FingerprintLength = 52

	// ShortIDLength is the number of characters shown in dialogs and the CLI.
	ShortIDLength = 8
)

var fingerprintEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Identity is the device key pair used for the public-plane signature, the
// build-plane TLS certificate, and the trust records.
type Identity struct {
	private     ed25519.PrivateKey
	public      ed25519.PublicKey
	fingerprint string
}

// LoadOrCreate reads the identity key from dir, creating it on first use. The
// key file is created with mode 0400 and a file that is readable by another
// user is rejected.
func LoadOrCreate(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	path := filepath.Join(dir, keyFile)

	seed, err := readSeed(path)
	if err == nil {
		return FromSeed(seed)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	seed = make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	if err := writeSeed(path, seed); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another process won the race. Read its key instead.
			seed, err = readSeed(path)
			if err != nil {
				return nil, err
			}
			return FromSeed(seed)
		}
		return nil, err
	}

	return FromSeed(seed)
}

func readSeed(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: identity key is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: identity key must not be readable or writable by group or others, got %04o", path, info.Mode().Perm())
	}

	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: identity key has %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}

	return seed, nil
}

func writeSeed(path string, seed []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}

	if _, err := file.Write(seed); err != nil {
		file.Close()
		return fmt.Errorf("write identity key: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close identity key: %w", err)
	}

	return nil
}

// FromSeed builds an identity from a 32-byte Ed25519 seed.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity seed has %d bytes, want %d", len(seed), ed25519.SeedSize)
	}

	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)

	return &Identity{
		private:     private,
		public:      public,
		fingerprint: FingerprintOf(public),
	}, nil
}

// FingerprintOf returns the base32 SHA-256 of a raw Ed25519 public key.
func FingerprintOf(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return fingerprintEncoding.EncodeToString(sum[:])
}

// ParsePublicKey decodes a base64 public key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// PublicKey returns a copy of the raw public key.
func (identity *Identity) PublicKey() ed25519.PublicKey {
	public := make(ed25519.PublicKey, len(identity.public))
	copy(public, identity.public)
	return public
}

// PublicKeyBase64 returns the public key in the wire format.
func (identity *Identity) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(identity.public)
}

// Fingerprint returns the full base32 fingerprint.
func (identity *Identity) Fingerprint() string {
	return identity.fingerprint
}

// ShortID returns the prefix shown in dialogs and the CLI.
func (identity *Identity) ShortID() string {
	if len(identity.fingerprint) < ShortIDLength {
		return identity.fingerprint
	}
	return identity.fingerprint[:ShortIDLength]
}

// Sign signs data with the device key.
func (identity *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(identity.private, data)
}

// Verify checks a signature against a raw public key.
func Verify(public ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(public, data, signature)
}

// TLSCertificate builds a self-signed certificate from the device key. The
// certificate carries no hostname. Peers compare the public key.
func (identity *Identity) TLSCertificate() (tls.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nix-builder-discovery"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, identity.public, identity.private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  identity.private,
		Leaf:        leaf,
	}, nil
}

// PublicKeyFromCertificate extracts the Ed25519 key carried by a certificate.
func PublicKeyFromCertificate(certificate *x509.Certificate) (ed25519.PublicKey, error) {
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate key is %T, want ed25519.PublicKey", certificate.PublicKey)
	}
	return public, nil
}
