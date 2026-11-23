package trust

import (
	"path/filepath"
	"testing"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

func TestManualRecordOverridesDefault(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := store.Put(Record{
		Fingerprint: "peer",
		PublicKey:   "key",
		State:       model.StateTrusted,
		Source:      model.SourceManual,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	if got := store.Decide("peer", model.PolicyDeny); got != model.PolicyAllow {
		t.Fatalf("manual trust with deny default = %s, want allow", got)
	}
}

func TestDefaultRecordFollowsLiveDefault(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := store.Put(Record{
		Fingerprint: "peer",
		PublicKey:   "key",
		State:       model.StateTrusted,
		Source:      model.SourceDefault,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	if got := store.Decide("peer", model.PolicyAllow); got != model.PolicyAllow {
		t.Fatalf("default allow = %s, want allow", got)
	}
	if got := store.Decide("peer", model.PolicyDeny); got != model.PolicyDeny {
		t.Fatalf("default deny = %s, want deny", got)
	}
}

func TestPeerDenyWins(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := store.Put(Record{
		Fingerprint: "peer",
		PublicKey:   "key",
		State:       model.StateDenied,
		Source:      model.SourcePeer,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	if got := store.Decide("peer", model.PolicyAllow); got != model.PolicyDeny {
		t.Fatalf("peer deny = %s, want deny", got)
	}
}

func TestNeutralFollowsDefault(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if got := store.Decide("missing", model.PolicyAsk); got != model.PolicyAsk {
		t.Fatalf("neutral = %s, want ask", got)
	}
}

func TestRemoveSource(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	for _, record := range []Record{
		{Fingerprint: "default", PublicKey: "k1", State: model.StateTrusted, Source: model.SourceDefault},
		{Fingerprint: "manual", PublicKey: "k2", State: model.StateTrusted, Source: model.SourceManual},
	} {
		if err := store.Put(record); err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	if err := store.RemoveSource(model.SourceDefault); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	if _, ok := store.Get("default"); ok {
		t.Fatal("default-sourced record was not removed")
	}
	if _, ok := store.Get("manual"); !ok {
		t.Fatal("manual record was removed")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Put(Record{
		Fingerprint: "peer",
		PublicKey:   "key",
		Hostname:    "builder",
		State:       model.StateTrusted,
		Source:      model.SourceManual,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	record, ok := reopened.Get("peer")
	if !ok {
		t.Fatal("record did not persist")
	}
	if record.Hostname != "builder" || record.State != model.StateTrusted {
		t.Fatalf("record changed: %#v", record)
	}
}
