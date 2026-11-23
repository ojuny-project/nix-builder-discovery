package model

import "time"

// Policy is the declarative default for one direction.
type Policy string

const (
	PolicyAsk   Policy = "ask"
	PolicyAllow Policy = "allow"
	PolicyDeny  Policy = "deny"
)

func ParsePolicy(value string) (Policy, bool) {
	switch Policy(value) {
	case PolicyAsk, PolicyAllow, PolicyDeny:
		return Policy(value), true
	default:
		return "", false
	}
}

// State is the persistent trust decision for one peer.
type State string

const (
	StateTrusted State = "trusted"
	StateDenied  State = "denied"
)

// Source records how a trust record was created.
type Source string

const (
	SourceManual  Source = "manual"
	SourceDefault Source = "default"
	SourcePeer    Source = "peer"
)

// Peer is one device as advertised on the public plane.
type Peer struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Hostname   string    `json:"hostname"`
	Address    string    `json:"address"`
	Systems    []string  `json:"systems"`
	InfoPort   int       `json:"info_port"`
	BuildPort  int       `json:"build_port"`
	CacheURL   string    `json:"cache_url,omitempty"`
	State      string    `json:"state"`
	BusyReason string    `json:"busy_reason,omitempty"`
	Accepting  bool      `json:"accepting"`
	Slots      int       `json:"slots"`
	LastSeen   time.Time `json:"last_seen"`
}

func (peer Peer) Supports(system string) bool {
	for _, candidate := range peer.Systems {
		if candidate == system {
			return true
		}
	}
	return false
}

func (peer Peer) Available() bool {
	return peer.Accepting
}

func (peer Peer) Capacity() int {
	if peer.Slots < 1 {
		return 1
	}
	return peer.Slots
}

// JobSpec is one derivation sent to a builder.
type JobSpec struct {
	ID       string   `json:"id"`
	System   string   `json:"system"`
	DrvPath  string   `json:"drv_path"`
	DrvJSON  []byte   `json:"drv_json"`
	Inputs   []string `json:"inputs"`
	Outputs  []string `json:"outputs"`
	Client   Peer     `json:"client"`
	Attempt  int      `json:"attempt"`
	Deadline int64    `json:"deadline,omitempty"`
}

// JobEvent is one frame in a job stream.
type JobEvent struct {
	Type    string   `json:"type"`
	Log     string   `json:"log,omitempty"`
	Offset  int      `json:"offset,omitempty"`
	Outputs []string `json:"outputs,omitempty"`
	Error   string   `json:"error,omitempty"`
}

const (
	EventLog    = "log"
	EventResult = "result"
	EventError  = "error"
)
