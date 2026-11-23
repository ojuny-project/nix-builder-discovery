package broker

import (
	"context"
	"testing"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

type fakeCatalog struct {
	peers []model.Peer
}

func (catalog fakeCatalog) Snapshot() []model.Peer {
	return catalog.peers
}

func peer(id string, slots int) model.Peer {
	return model.Peer{
		ID:        id,
		Systems:   []string{"x86_64-linux"},
		Accepting: true,
		State:     "idle",
		Slots:     slots,
	}
}

func TestFanOut(t *testing.T) {
	catalog := fakeCatalog{peers: []model.Peer{peer("a", 1), peer("b", 1)}}
	broker := New(catalog)

	first, err := broker.Acquire(context.Background(), "x86_64-linux", false)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	second, err := broker.Acquire(context.Background(), "x86_64-linux", false)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first.ID == second.ID {
		t.Fatalf("both leases went to %s", first.ID)
	}
}

func TestUnavailableWithoutWait(t *testing.T) {
	catalog := fakeCatalog{peers: []model.Peer{peer("a", 1)}}
	broker := New(catalog)

	if _, err := broker.Acquire(context.Background(), "x86_64-linux", false); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if _, err := broker.Acquire(context.Background(), "x86_64-linux", false); err != ErrBusy {
		t.Fatalf("error = %v, want busy", err)
	}
}

func TestWaitForRelease(t *testing.T) {
	catalog := fakeCatalog{peers: []model.Peer{peer("a", 1)}}
	broker := New(catalog)

	if _, err := broker.Acquire(context.Background(), "x86_64-linux", false); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := broker.Acquire(context.Background(), "x86_64-linux", true)
		result <- err
	}()

	time.Sleep(20 * time.Millisecond)
	broker.Release("a")

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return")
	}
}

func TestWaitWithNoCandidateReturns(t *testing.T) {
	broker := New(fakeCatalog{})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := broker.Acquire(ctx, "x86_64-linux", true); err != ErrUnavailable {
		t.Fatalf("error = %v, want unavailable", err)
	}
}

func TestSkipsWrongSystem(t *testing.T) {
	catalog := fakeCatalog{peers: []model.Peer{peer("a", 1)}}
	broker := New(catalog)

	if _, err := broker.Acquire(context.Background(), "aarch64-linux", true); err != ErrUnavailable {
		t.Fatalf("error = %v, want unavailable", err)
	}
}
