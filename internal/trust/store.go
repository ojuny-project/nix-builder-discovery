package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

const storeVersion = 1

// Record is the local trust decision for one peer.
type Record struct {
	Fingerprint string       `json:"fingerprint"`
	PublicKey   string       `json:"public_key"`
	Hostname    string       `json:"hostname"`
	Address     string       `json:"address"`
	State       model.State  `json:"state"`
	Source      model.Source `json:"source"`
	Created     time.Time    `json:"created"`
	Updated     time.Time    `json:"updated"`
}

type storeData struct {
	Version int               `json:"version"`
	Records map[string]Record `json:"records"`
}

// Store is the persistent trust database. It has one writer, the service.
type Store struct {
	mu   sync.RWMutex
	path string
	data storeData
}

func Open(path string) (*Store, error) {
	store := &Store{
		path: path,
		data: storeData{Version: storeVersion, Records: map[string]Record{}},
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read trust store: %w", err)
	}

	var data storeData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if data.Version != storeVersion {
		return nil, fmt.Errorf("trust store version %d is not supported", data.Version)
	}
	if data.Records == nil {
		data.Records = map[string]Record{}
	}

	store.data = data
	return store, nil
}

func (store *Store) Path() string {
	return store.path
}

func (store *Store) List() []Record {
	store.mu.RLock()
	defer store.mu.RUnlock()

	records := make([]Record, 0, len(store.data.Records))
	for _, record := range store.data.Records {
		records = append(records, record)
	}

	sort.Slice(records, func(left, right int) bool {
		return records[left].Fingerprint < records[right].Fingerprint
	})

	return records
}

func (store *Store) Get(fingerprint string) (Record, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	record, ok := store.data.Records[fingerprint]
	return record, ok
}

func (store *Store) Put(record Record) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	now := time.Now()
	if existing, ok := store.data.Records[record.Fingerprint]; ok {
		record.Created = existing.Created
	} else {
		record.Created = now
	}
	record.Updated = now
	store.data.Records[record.Fingerprint] = record

	return store.saveLocked()
}

func (store *Store) Remove(fingerprint string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	delete(store.data.Records, fingerprint)
	return store.saveLocked()
}

func (store *Store) RemoveSource(source model.Source) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	for fingerprint, record := range store.data.Records {
		if record.Source == source {
			delete(store.data.Records, fingerprint)
		}
	}

	return store.saveLocked()
}

// Decide applies the precedence rules for one direction. A manual record wins.
// A default-sourced record follows the live default, so changing the default
// takes effect without cleanup. A peer deny always wins.
func (store *Store) Decide(fingerprint string, policy model.Policy) model.Policy {
	record, ok := store.Get(fingerprint)
	if !ok {
		return policy
	}

	switch record.Source {
	case model.SourceManual:
		if record.State == model.StateTrusted {
			return model.PolicyAllow
		}
		return model.PolicyDeny
	case model.SourcePeer:
		if record.State == model.StateDenied {
			return model.PolicyDeny
		}
		return policy
	case model.SourceDefault:
		return policy
	default:
		return policy
	}
}

func (store *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create trust store directory: %w", err)
	}

	encoded, err := json.MarshalIndent(store.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trust store: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".trust-*")
	if err != nil {
		return fmt.Errorf("create temporary trust store: %w", err)
	}
	temporaryName := temporary.Name()

	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("chmod temporary trust store: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return fmt.Errorf("write trust store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close trust store: %w", err)
	}
	if err := os.Rename(temporaryName, store.path); err != nil {
		return fmt.Errorf("replace trust store: %w", err)
	}

	return nil
}
