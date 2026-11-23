package pairing

import (
	"context"
	"testing"
	"time"
)

func TestDecideTrust(t *testing.T) {
	manager := New(time.Minute)

	request, err := manager.Add(Request{
		Direction: Incoming,
		PeerID:    "peer",
		Hostname:  "client",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	if len(manager.List()) != 1 {
		t.Fatalf("pending = %d, want 1", len(manager.List()))
	}

	go func() {
		if err := manager.Decide(request.ID, DecisionTrust); err != nil {
			t.Errorf("decide: %v", err)
		}
	}()

	decision, err := manager.Wait(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if decision != DecisionTrust {
		t.Fatalf("decision = %s, want trust", decision)
	}
}

func TestTimeoutDefaultsToSkip(t *testing.T) {
	manager := New(20 * time.Millisecond)

	request, err := manager.Add(Request{Direction: Incoming, PeerID: "peer"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	decision, err := manager.Wait(context.Background(), request.ID)
	if err != ErrTimeout {
		t.Fatalf("error = %v, want timeout", err)
	}
	if decision != DecisionSkip {
		t.Fatalf("decision = %s, want skip", decision)
	}
}

func TestUnknownRequest(t *testing.T) {
	manager := New(time.Minute)

	if err := manager.Decide("missing", DecisionTrust); err != ErrNotFound {
		t.Fatalf("error = %v, want not found", err)
	}
}
