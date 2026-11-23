package broker

import (
	"context"
	"errors"
	"sync"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

var (
	ErrUnavailable = errors.New("no builder is available")
	ErrBusy        = errors.New("every eligible builder is at capacity")
)

// Catalog is the discovery snapshot the broker selects from.
type Catalog interface {
	Snapshot() []model.Peer
}

// Broker hands out leases so concurrent jobs fan out across builders.
type Broker struct {
	mu      sync.Mutex
	catalog Catalog
	leases  map[string]int
	notify  chan struct{}
}

func New(catalog Catalog) *Broker {
	return &Broker{
		catalog: catalog,
		leases:  map[string]int{},
		notify:  make(chan struct{}),
	}
}

// Acquire returns a builder for the system and records a lease. When wait is
// true and at least one accepting builder exists but all are at capacity, it
// blocks until a lease is released or the context ends.
func (broker *Broker) Acquire(ctx context.Context, system string, wait bool) (model.Peer, error) {
	for {
		broker.mu.Lock()

		var (
			best      *model.Peer
			accepting bool
		)

		for _, peer := range broker.catalog.Snapshot() {
			if !peer.Supports(system) || !peer.Accepting {
				continue
			}
			accepting = true

			if broker.leases[peer.ID] >= peer.Capacity() {
				continue
			}

			if best == nil ||
				broker.leases[peer.ID] < broker.leases[best.ID] ||
				(broker.leases[peer.ID] == broker.leases[best.ID] && peer.ID < best.ID) {
				candidate := peer
				best = &candidate
			}
		}

		if best != nil {
			broker.leases[best.ID]++
			broker.mu.Unlock()
			return *best, nil
		}

		if !wait || !accepting {
			broker.mu.Unlock()
			if accepting {
				return model.Peer{}, ErrBusy
			}
			return model.Peer{}, ErrUnavailable
		}

		notify := broker.notify
		broker.mu.Unlock()

		select {
		case <-notify:
		case <-ctx.Done():
			return model.Peer{}, ctx.Err()
		}
	}
}

func (broker *Broker) Release(id string) {
	broker.mu.Lock()
	defer broker.mu.Unlock()

	broker.leases[id]--
	if broker.leases[id] <= 0 {
		delete(broker.leases, id)
	}

	close(broker.notify)
	broker.notify = make(chan struct{})
}

func (broker *Broker) Leases() map[string]int {
	broker.mu.Lock()
	defer broker.mu.Unlock()

	leases := make(map[string]int, len(broker.leases))
	for id, count := range broker.leases {
		leases[id] = count
	}

	return leases
}
