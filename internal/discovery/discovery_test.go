package discovery

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
	"github.com/ojuny-project/nix-builder-discovery/internal/info"
)

func TestScanFindsPeer(t *testing.T) {
	device, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	payload := info.Payload{
		ID:        device.Fingerprint(),
		Hostname:  "builder",
		Systems:   []string{"x86_64-linux"},
		InfoPort:  5056,
		BuildPort: 5057,
		State:     "idle",
		Accepting: true,
		Slots:     1,
		Key:       device.PublicKeyBase64(),
		Timestamp: time.Now().Unix(),
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != info.Path() {
			http.NotFound(response, request)
			return
		}
		response.Write(payload.Sign(device))
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	registry := NewRegistry()
	scanner := New(
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		port,
		time.Second,
		1,
		"",
		registry,
		slog.Default(),
	)

	if live := scanner.Scan(context.Background()); live != 1 {
		t.Fatalf("live peers = %d, want 1", live)
	}

	peers := registry.Snapshot()
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(peers))
	}
	if peers[0].Hostname != "builder" || peers[0].BuildPort != 5057 {
		t.Fatalf("peer: %#v", peers[0])
	}
}

func TestScanExcludesSelf(t *testing.T) {
	device, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	payload := info.Payload{
		ID:        device.Fingerprint(),
		Hostname:  "self",
		Systems:   []string{"x86_64-linux"},
		InfoPort:  5056,
		BuildPort: 5057,
		State:     "idle",
		Accepting: true,
		Slots:     1,
		Key:       device.PublicKeyBase64(),
		Timestamp: time.Now().Unix(),
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Write(payload.Sign(device))
	}))
	defer server.Close()

	parsed, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(parsed.Port())

	registry := NewRegistry()
	scanner := New(
		[]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		port,
		time.Second,
		1,
		device.Fingerprint(),
		registry,
		slog.Default(),
	)

	if live := scanner.Scan(context.Background()); live != 0 {
		t.Fatalf("live peers = %d, want 0", live)
	}
}

func TestBuildTargets(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/30")}
	targets := buildTargets(ranges, nil)

	if len(targets) != 4 {
		t.Fatalf("targets = %d, want 4", len(targets))
	}
}
