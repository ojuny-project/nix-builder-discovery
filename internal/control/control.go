package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/pairing"
	"github.com/ojuny-project/nix-builder-discovery/internal/trust"
)

// DefaultSocket is the local control socket used by the CLI, the agent, and
// the build hook.
const DefaultSocket = "/run/nix-builder-discovery/control.sock"

type Request struct {
	Command     string     `json:"command"`
	ID          string     `json:"id,omitempty"`
	Decision    string     `json:"decision,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	State       string     `json:"state,omitempty"`
	Source      string     `json:"source,omitempty"`
	System      string     `json:"system,omitempty"`
	Wait        bool       `json:"wait,omitempty"`
	DrvPath     string     `json:"drv_path,omitempty"`
	DrvJSON     []byte     `json:"drv_json,omitempty"`
	Features    []string   `json:"features,omitempty"`
	Inputs      []string   `json:"inputs,omitempty"`
	Outputs     []string   `json:"outputs,omitempty"`
	JobID       string     `json:"job_id,omitempty"`
	Offset      int        `json:"offset,omitempty"`
	Client      model.Peer `json:"client,omitempty"`
}

type Status struct {
	ID         string            `json:"id"`
	Hostname   string            `json:"hostname"`
	InfoPort   int               `json:"info_port"`
	BuildPort  int               `json:"build_port"`
	State      string            `json:"state"`
	BusyReason string            `json:"busy_reason"`
	Accepting  bool              `json:"accepting"`
	Peers      int               `json:"peers"`
	ActiveJobs int               `json:"active_jobs"`
	MaxJobs    int               `json:"max_jobs"`
	Leases     map[string]int    `json:"leases"`
	Systems    []string          `json:"systems"`
	Policy     map[string]string `json:"policy"`
}

type JobInfo struct {
	ID      string    `json:"id"`
	System  string    `json:"system"`
	DrvPath string    `json:"drv_path"`
	Client  string    `json:"client"`
	State   string    `json:"state"`
	Started time.Time `json:"started"`
}

type Event struct {
	Type       string            `json:"type"`
	Error      string            `json:"error,omitempty"`
	Decision   string            `json:"decision,omitempty"`
	Peer       model.Peer        `json:"peer,omitempty"`
	JobID      string            `json:"job_id,omitempty"`
	Log        string            `json:"log,omitempty"`
	Outputs    []string          `json:"outputs,omitempty"`
	ExportPath string            `json:"export_path,omitempty"`
	CacheURL   string            `json:"cache_url,omitempty"`
	Status     Status            `json:"status,omitempty"`
	Peers      []model.Peer      `json:"peers,omitempty"`
	Pending    []pairing.Request `json:"pending,omitempty"`
	Trust      []trust.Record    `json:"trust,omitempty"`
	Jobs       []JobInfo         `json:"jobs,omitempty"`
}

const (
	EventLog      = "log"
	EventResult   = "result"
	EventError    = "error"
	EventDecision = "decision"
	EventStatus   = "status"
	EventPeers    = "peers"
	EventPending  = "pending"
	EventTrust    = "trust"
	EventJobs     = "jobs"
	EventDone     = "done"
)

// Client is a one-shot control connection.
type Client struct {
	Socket  string
	Timeout time.Duration
}

func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	return &Client{Socket: socket, Timeout: 30 * time.Second}
}

// Do sends one request and calls onEvent for every response frame.
func (client *Client) Do(ctx context.Context, request Request, onEvent func(Event) error) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", client.Socket)
	if err != nil {
		return fmt.Errorf("connect to service: %w", err)
	}
	defer connection.Close()

	if deadline, ok := ctx.Deadline(); ok {
		connection.SetDeadline(deadline)
	} else if client.Timeout > 0 {
		connection.SetDeadline(time.Now().Add(client.Timeout))
	}

	encoder := json.NewEncoder(connection)
	if err := encoder.Encode(request); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	decoder := json.NewDecoder(connection)
	for {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			return err
		}
		if onEvent != nil {
			if err := onEvent(event); err != nil {
				return err
			}
		}
		if event.Type == EventDone {
			return nil
		}
		if event.Type == EventError && event.Error != "" {
			return nil
		}
	}
}
