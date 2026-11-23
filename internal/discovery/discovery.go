package discovery

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/info"
	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

const (
	maxMisses        = 5
	maxScanAddresses = 65536
)

// Registry holds the peers seen by the most recent scans.
type Registry struct {
	mu    sync.RWMutex
	peers map[string]model.Peer
}

func NewRegistry() *Registry {
	return &Registry{peers: map[string]model.Peer{}}
}

func (registry *Registry) Mark(peer model.Peer) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	_, existed := registry.peers[peer.ID]
	registry.peers[peer.ID] = peer
	return !existed
}

// Prune removes peers that have not answered for maxMisses scans. The scanner
// bumps a miss counter by dropping LastSeen updates; a peer is pruned once its
// last successful probe is older than the interval times maxMisses.
func (registry *Registry) Prune(maxAge time.Duration) []model.Peer {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var removed []model.Peer

	for id, peer := range registry.peers {
		if peer.LastSeen.Before(cutoff) {
			removed = append(removed, peer)
			delete(registry.peers, id)
		}
	}

	sort.Slice(removed, func(left, right int) bool {
		return removed[left].ID < removed[right].ID
	})

	return removed
}

func (registry *Registry) Snapshot() []model.Peer {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	peers := make([]model.Peer, 0, len(registry.peers))
	for _, peer := range registry.peers {
		peers = append(peers, peer)
	}

	sort.Slice(peers, func(left, right int) bool {
		return peers[left].ID < peers[right].ID
	})

	return peers
}

func (registry *Registry) Lookup(id string) (model.Peer, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	peer, ok := registry.peers[id]
	return peer, ok
}

func (registry *Registry) Clear() {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	registry.peers = map[string]model.Peer{}
}

// Scanner probes a set of prefixes for public info endpoints.
type Scanner struct {
	Ranges   []netip.Prefix
	Port     int
	Timeout  time.Duration
	Workers  int
	Interval time.Duration
	SelfID   string
	Gate     func() bool
	Registry *Registry
	Logger   *slog.Logger
	Client   *http.Client

	mu     sync.RWMutex
	ranges []netip.Prefix
}

func New(ranges []netip.Prefix, port int, timeout time.Duration, workers int, selfID string, registry *Registry, logger *slog.Logger) *Scanner {
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}

	return &Scanner{
		Ranges:   ranges,
		Port:     port,
		Timeout:  timeout,
		Workers:  workers,
		Interval: time.Minute,
		SelfID:   selfID,
		Registry: registry,
		Logger:   logger,
		ranges:   ranges,
		Client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

func (scanner *Scanner) SetRanges(ranges []netip.Prefix) {
	scanner.mu.Lock()
	defer scanner.mu.Unlock()

	scanner.ranges = ranges
}

func (scanner *Scanner) activeRanges() []netip.Prefix {
	scanner.mu.RLock()
	defer scanner.mu.RUnlock()

	return scanner.ranges
}

func (scanner *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(scanner.Interval)
	defer ticker.Stop()

	for {
		if scanner.Gate == nil || scanner.Gate() {
			scanner.Scan(ctx)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (scanner *Scanner) Scan(ctx context.Context) int {
	started := time.Now()
	targets := buildTargets(scanner.activeRanges(), scanner.Registry.Snapshot())

	var (
		wait       sync.WaitGroup
		workers    = make(chan struct{}, scanner.Workers)
		discovered atomic.Int64
	)

	for _, address := range targets {
		if ctx.Err() != nil {
			break
		}

		wait.Add(1)
		workers <- struct{}{}

		go func(address netip.Addr) {
			defer wait.Done()
			defer func() { <-workers }()

			peer, err := scanner.probe(ctx, address)
			if err != nil {
				return
			}
			if scanner.Registry.Mark(peer) {
				discovered.Add(1)
				scanner.Logger.Info("discovered peer", "id", peer.ID, "hostname", peer.Hostname, "address", peer.Address)
			}
		}(address)
	}

	wait.Wait()

	removed := scanner.Registry.Prune(scanner.Interval * maxMisses)
	for _, peer := range removed {
		scanner.Logger.Info("lost peer", "id", peer.ID, "hostname", peer.Hostname)
	}

	live := len(scanner.Registry.Snapshot())
	scanner.Logger.Debug("discovery scan finished",
		"targets", len(targets),
		"discovered", discovered.Load(),
		"peers", live,
		"duration", time.Since(started),
	)

	return live
}

func (scanner *Scanner) probe(ctx context.Context, address netip.Addr) (model.Peer, error) {
	timeout, cancel := context.WithTimeout(ctx, scanner.Timeout)
	defer cancel()

	url := "http://" + net.JoinHostPort(address.String(), strconv.Itoa(scanner.Port)) + info.Path()
	request, err := http.NewRequestWithContext(timeout, http.MethodGet, url, nil)
	if err != nil {
		return model.Peer{}, err
	}

	response, err := scanner.Client.Do(request)
	if err != nil {
		return model.Peer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return model.Peer{}, errUnexpectedStatus(response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return model.Peer{}, err
	}

	payload, err := info.Parse(body)
	if err != nil {
		return model.Peer{}, err
	}
	if payload.ID == scanner.SelfID {
		return model.Peer{}, errNotAPeer{}
	}

	return model.Peer{
		ID:         payload.ID,
		Key:        payload.Key,
		Hostname:   payload.Hostname,
		Address:    address.String(),
		Systems:    payload.Systems,
		InfoPort:   payload.InfoPort,
		BuildPort:  payload.BuildPort,
		CacheURL:   payload.CacheURL,
		State:      payload.State,
		BusyReason: payload.BusyReason,
		Accepting:  payload.Accepting,
		Slots:      payload.Slots,
		LastSeen:   time.Now(),
	}, nil
}

type errUnexpectedStatus int

func (err errUnexpectedStatus) Error() string {
	return "unexpected HTTP status " + strconv.Itoa(int(err))
}

type errNotAPeer struct{}

func (errNotAPeer) Error() string { return "not a peer" }

func buildTargets(ranges []netip.Prefix, peers []model.Peer) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	targets := make([]netip.Addr, 0, 1024)

	add := func(address netip.Addr) {
		address = address.Unmap()
		if !address.IsValid() {
			return
		}
		if _, ok := seen[address]; ok {
			return
		}

		inside := false
		for _, prefix := range ranges {
			if prefix.Contains(address) {
				inside = true
				break
			}
		}
		if !inside {
			return
		}

		seen[address] = struct{}{}
		targets = append(targets, address)
	}

	for _, peer := range peers {
		address, err := netip.ParseAddr(peer.Address)
		if err == nil {
			add(address)
		}
	}

	for _, prefix := range ranges {
		enumerate(prefix, add)
		if len(targets) >= maxScanAddresses {
			break
		}
	}

	return targets
}

func enumerate(prefix netip.Prefix, add func(netip.Addr)) {
	address := prefix.Masked().Addr()

	for prefix.Contains(address) {
		add(address)
		address = address.Next()
		if !address.IsValid() {
			return
		}
	}
}

// PrimaryPrefix returns the connected subnet, or an empty prefix when no
// network is available.
func PrimaryPrefix() (netip.Prefix, bool) {
	connection, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return netip.Prefix{}, false
	}
	defer connection.Close()

	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return netip.Prefix{}, false
	}

	address, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Prefix{}, false
	}

	bits := 24
	prefix, err := address.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}

	return prefix, true
}
