package pairing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

type Direction string

const (
	Incoming Direction = "incoming"
	Outgoing Direction = "outgoing"
)

type Decision string

const (
	DecisionTrust Decision = "trust"
	DecisionSkip  Decision = "skip"
	DecisionDeny  Decision = "deny"
)

var (
	ErrNotFound = errors.New("pairing request not found")
	ErrDecided  = errors.New("pairing request already decided")
	ErrTimeout  = errors.New("pairing request timed out")
)

type Request struct {
	ID        string    `json:"id"`
	Direction Direction `json:"direction"`
	PeerID    string    `json:"peer_id"`
	Hostname  string    `json:"hostname"`
	Address   string    `json:"address"`
	Systems   []string  `json:"systems"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

type pending struct {
	request Request
	result  chan Decision
}

// Manager holds pairing requests until a local agent or the CLI decides.
type Manager struct {
	mu      sync.Mutex
	timeout time.Duration
	pending map[string]*pending
}

func New(timeout time.Duration) *Manager {
	if timeout <= 0 {
		timeout = time.Minute
	}

	return &Manager{
		timeout: timeout,
		pending: map[string]*pending{},
	}
}

func (manager *Manager) Add(request Request) (Request, error) {
	id, err := randomID()
	if err != nil {
		return Request{}, err
	}

	request.ID = id
	request.Created = time.Now()
	request.Expires = request.Created.Add(manager.timeout)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	manager.pending[id] = &pending{
		request: request,
		result:  make(chan Decision, 1),
	}

	return request, nil
}

func (manager *Manager) Wait(ctx context.Context, id string) (Decision, error) {
	manager.mu.Lock()
	entry, ok := manager.pending[id]
	manager.mu.Unlock()
	if !ok {
		return "", ErrNotFound
	}

	timer := time.NewTimer(time.Until(entry.request.Expires))
	defer timer.Stop()

	select {
	case decision := <-entry.result:
		return decision, nil
	case <-timer.C:
		manager.remove(id)
		return DecisionSkip, ErrTimeout
	case <-ctx.Done():
		manager.remove(id)
		return DecisionSkip, ctx.Err()
	}
}

func (manager *Manager) Decide(id string, decision Decision) error {
	switch decision {
	case DecisionTrust, DecisionSkip, DecisionDeny:
	default:
		return errors.New("invalid pairing decision")
	}

	manager.mu.Lock()
	entry, ok := manager.pending[id]
	if !ok {
		manager.mu.Unlock()
		return ErrNotFound
	}
	delete(manager.pending, id)
	manager.mu.Unlock()

	select {
	case entry.result <- decision:
	default:
		return ErrDecided
	}

	return nil
}

func (manager *Manager) List() []Request {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	requests := make([]Request, 0, len(manager.pending))
	for _, entry := range manager.pending {
		requests = append(requests, entry.request)
	}

	sort.Slice(requests, func(left, right int) bool {
		return requests[left].Created.Before(requests[right].Created)
	})

	return requests
}

func (manager *Manager) remove(id string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	delete(manager.pending, id)
}

func randomID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
