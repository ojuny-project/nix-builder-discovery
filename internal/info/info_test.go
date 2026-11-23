package info

import (
	"testing"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
)

func testPayload(device *identity.Identity) Payload {
	return Payload{
		ID:         device.Fingerprint(),
		Hostname:   "builder",
		Systems:    []string{"x86_64-linux", "aarch64-linux"},
		InfoPort:   5056,
		BuildPort:  5057,
		CacheURL:   "http://192.168.1.2:5055",
		State:      "idle",
		BusyReason: "",
		Accepting:  true,
		Slots:      2,
		Key:        device.PublicKeyBase64(),
		Timestamp:  time.Now().Unix(),
	}
}

func TestSignAndParse(t *testing.T) {
	device, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	payload := testPayload(device)
	parsed, err := Parse(payload.Sign(device))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed.ID != payload.ID || parsed.Hostname != payload.Hostname {
		t.Fatalf("payload changed: %#v", parsed)
	}
	if len(parsed.Systems) != 2 || parsed.Systems[1] != "aarch64-linux" {
		t.Fatalf("systems: %#v", parsed.Systems)
	}
	if !parsed.Accepting || parsed.Slots != 2 {
		t.Fatalf("flags: %#v", parsed)
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	device, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	signed := testPayload(device).Sign(device)
	tampered := []byte(string(signed))
	tampered[0] = 'X'

	if _, err := Parse(tampered); err == nil {
		t.Fatal("expected a tampered payload to be rejected")
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	first, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	second, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	payload := testPayload(second)
	signed := payload.Sign(first)

	if _, err := Parse(signed); err == nil {
		t.Fatal("expected a signature from another key to be rejected")
	}
}

func TestStaleTimestampIsRejected(t *testing.T) {
	device, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	payload := testPayload(device)
	payload.Timestamp = time.Now().Add(-time.Hour).Unix()

	if _, err := Parse(payload.Sign(device)); err == nil {
		t.Fatal("expected a stale payload to be rejected")
	}
}
