package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/broker"
	"github.com/ojuny-project/nix-builder-discovery/internal/control"
	"github.com/ojuny-project/nix-builder-discovery/internal/discovery"
	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
	"github.com/ojuny-project/nix-builder-discovery/internal/info"
	"github.com/ojuny-project/nix-builder-discovery/internal/job"
	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/pairing"
	"github.com/ojuny-project/nix-builder-discovery/internal/tlsutil"
	"github.com/ojuny-project/nix-builder-discovery/internal/trust"
)

type Config struct {
	StateDir   string
	RuntimeDir string
	Hostname   string
	Systems    []string

	InfoPort  int
	BuildPort int
	CacheURL  string

	Incoming model.Policy
	Outgoing model.Policy

	Ranges       []netip.Prefix
	AutoDiscover bool
	ScanInterval time.Duration
	ScanTimeout  time.Duration
	Workers      int

	MaxConnections int
	Wait           bool
	WaitTimeout    time.Duration
	PairTimeout    time.Duration
	ReconnectGrace time.Duration
	MaxAttempts    int

	IdleSession bool
	IdlePower   bool
	IdlePeriod  time.Duration

	Nix           string
	ControlSocket string
}

func DefaultConfig() Config {
	return Config{
		StateDir:       "/var/lib/nix-builder-discovery",
		RuntimeDir:     "/run/nix-builder-discovery",
		InfoPort:       5056,
		BuildPort:      5057,
		Incoming:       model.PolicyAsk,
		Outgoing:       model.PolicyAsk,
		ScanInterval:   time.Minute,
		ScanTimeout:    1500 * time.Millisecond,
		Workers:        256,
		MaxConnections: 1,
		WaitTimeout:    30 * time.Minute,
		PairTimeout:    time.Minute,
		ReconnectGrace: time.Minute,
		MaxAttempts:    3,
		IdleSession:    true,
		IdlePower:      true,
		IdlePeriod:     5 * time.Minute,
		ControlSocket:  control.DefaultSocket,
	}
}

type prepared struct {
	peer    model.Peer
	expires time.Time
}

// Service wires discovery, trust, pairing, the broker, the job API, and the
// control socket into one process.
type Service struct {
	Config Config
	Logger *slog.Logger

	Device   *identity.Identity
	Store    *trust.Store
	Registry *discovery.Registry
	Scanner  *discovery.Scanner
	Pairing  *pairing.Manager
	Broker   *broker.Broker
	Jobs     *job.Server
	Client   *job.Client

	certificate tls.Certificate
	preparedMu  sync.Mutex
	prepared    map[string]prepared
	idle        idleState
	started     time.Time
}

func New(config Config, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if config.InfoPort == 0 {
		config.InfoPort = 5056
	}
	if config.BuildPort == 0 {
		config.BuildPort = 5057
	}
	if config.MaxConnections < 1 {
		config.MaxConnections = 1
	}
	if config.MaxAttempts < 1 {
		config.MaxAttempts = 1
	}
	if config.PairTimeout <= 0 {
		config.PairTimeout = time.Minute
	}
	if config.ReconnectGrace <= 0 {
		config.ReconnectGrace = time.Minute
	}
	if config.ScanInterval <= 0 {
		config.ScanInterval = time.Minute
	}
	if config.ScanTimeout <= 0 {
		config.ScanTimeout = 1500 * time.Millisecond
	}
	if config.Workers < 1 {
		config.Workers = 256
	}
	if config.ControlSocket == "" {
		config.ControlSocket = control.DefaultSocket
	}

	device, err := identity.LoadOrCreate(config.StateDir)
	if err != nil {
		return nil, err
	}

	store, err := trust.Open(filepath.Join(config.StateDir, "trust.json"))
	if err != nil {
		return nil, err
	}

	registry := discovery.NewRegistry()
	scanner := discovery.New(config.Ranges, config.InfoPort, config.ScanTimeout, config.Workers, device.Fingerprint(), registry, logger)
	scanner.Interval = config.ScanInterval

	service := &Service{
		Config:   config,
		Logger:   logger,
		Device:   device,
		Store:    store,
		Registry: registry,
		Scanner:  scanner,
		Pairing:  pairing.New(config.PairTimeout),
		prepared: map[string]prepared{},
		started:  time.Now(),
	}

	service.idle.set(idleSnapshot{session: true, power: true})

	service.Broker = broker.New(catalog{service: service})

	runner := job.NewNixRunner(config.Nix, []string{
		"HOME=" + config.StateDir,
	})
	service.Jobs = job.NewServer(runner, config.MaxConnections, config.ReconnectGrace, service.authorizeIncoming, logger)

	service.certificate, err = device.TLSCertificate()
	if err != nil {
		return nil, err
	}
	service.Client = job.NewClient(service.certificate)

	return service, nil
}

func (service *Service) Run(ctx context.Context) error {
	if service.Config.AutoDiscover && len(service.Config.Ranges) == 0 {
		if prefix, ok := discovery.PrimaryPrefix(); ok {
			service.Config.Ranges = []netip.Prefix{prefix}
			service.Scanner.SetRanges(service.Config.Ranges)
			service.Logger.Info("automatic discovery range", "prefix", prefix.String())
		} else {
			service.Logger.Warn("automatic discovery found no prefix")
		}
	}

	errorChannel := make(chan error, 4)

	infoListener, err := net.Listen("tcp", fmt.Sprintf(":%d", service.Config.InfoPort))
	if err != nil {
		return fmt.Errorf("listen on info port: %w", err)
	}
	infoServer := &http.Server{
		Handler: http.HandlerFunc(service.handleInfo),
	}
	go func() {
		if err := infoServer.Serve(infoListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorChannel <- fmt.Errorf("info server: %w", err)
		}
	}()

	buildListener, err := net.Listen("tcp", fmt.Sprintf(":%d", service.Config.BuildPort))
	if err != nil {
		return fmt.Errorf("listen on build port: %w", err)
	}
	buildServer := &http.Server{
		Handler: service.Jobs.Handler(),
	}
	tlsListener := tls.NewListener(buildListener, tlsutil.ServerConfig(service.certificate))
	go func() {
		if err := buildServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorChannel <- fmt.Errorf("build server: %w", err)
		}
	}()

	controlListener, err := service.listenControl()
	if err != nil {
		return err
	}
	go func() {
		if err := service.serveControl(ctx, controlListener); err != nil {
			errorChannel <- err
		}
	}()

	go service.Scanner.Run(ctx)
	go service.monitor(ctx)
	go service.cleanup(ctx)

	service.Logger.Info("service started",
		"id", service.Device.ShortID(),
		"hostname", service.hostname(),
		"info-port", service.Config.InfoPort,
		"build-port", service.Config.BuildPort,
		"systems", strings.Join(service.Config.Systems, ","),
	)

	select {
	case <-ctx.Done():
	case err := <-errorChannel:
		return err
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = infoServer.Shutdown(shutdown)
	_ = buildServer.Shutdown(shutdown)
	_ = controlListener.Close()
	_ = os.Remove(service.Config.ControlSocket)

	return nil
}

func (service *Service) hostname() string {
	if service.Config.Hostname != "" {
		return service.Config.Hostname
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func (service *Service) handleInfo(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != info.Path() {
		http.NotFound(response, request)
		return
	}

	payload := service.infoPayload()
	response.Header().Set("Content-Type", "text/plain")
	_, _ = response.Write(payload.Sign(service.Device))
}

func (service *Service) infoPayload() info.Payload {
	active := service.Jobs.Active()
	idle := service.idle.snapshot()

	state := "idle"
	reason := ""
	if active > 0 {
		state = "busy"
		reason = "remote-build"
	} else if idle.localBuild {
		state = "busy"
		reason = "local-build"
	} else if !idle.session {
		state = "busy"
		reason = "session"
	} else if !idle.power {
		state = "busy"
		reason = "battery"
	}

	accepting := service.Config.Incoming != model.PolicyDeny &&
		active < service.Config.MaxConnections &&
		idle.session && idle.power

	return info.Payload{
		ID:         service.Device.Fingerprint(),
		Hostname:   service.hostname(),
		Systems:    service.Config.Systems,
		InfoPort:   service.Config.InfoPort,
		BuildPort:  service.Config.BuildPort,
		CacheURL:   service.Config.CacheURL,
		State:      state,
		BusyReason: reason,
		Accepting:  accepting,
		Slots:      service.Config.MaxConnections,
		Key:        service.Device.PublicKeyBase64(),
		Timestamp:  time.Now().Unix(),
	}
}

func (service *Service) selfPeer() model.Peer {
	payload := service.infoPayload()
	return model.Peer{
		ID:         payload.ID,
		Key:        payload.Key,
		Hostname:   payload.Hostname,
		Systems:    payload.Systems,
		InfoPort:   payload.InfoPort,
		BuildPort:  payload.BuildPort,
		CacheURL:   payload.CacheURL,
		State:      payload.State,
		BusyReason: payload.BusyReason,
		Accepting:  payload.Accepting,
		Slots:      payload.Slots,
	}
}

func (service *Service) status() control.Status {
	payload := service.infoPayload()
	return control.Status{
		ID:         payload.ID,
		Hostname:   payload.Hostname,
		InfoPort:   payload.InfoPort,
		BuildPort:  payload.BuildPort,
		State:      payload.State,
		BusyReason: payload.BusyReason,
		Accepting:  payload.Accepting,
		Peers:      len(service.Registry.Snapshot()),
		ActiveJobs: service.Jobs.Active(),
		MaxJobs:    service.Config.MaxConnections,
		Leases:     service.Broker.Leases(),
		Systems:    payload.Systems,
		Policy: map[string]string{
			"incoming": string(service.Config.Incoming),
			"outgoing": string(service.Config.Outgoing),
		},
	}
}

type catalog struct {
	service *Service
}

func (catalog catalog) Snapshot() []model.Peer {
	peers := []model.Peer{}

	for _, peer := range catalog.service.Registry.Snapshot() {
		if catalog.service.Store.Decide(peer.ID, catalog.service.Config.Outgoing) == model.PolicyDeny {
			continue
		}
		if !peer.Accepting {
			if !catalog.service.manualTrusted(peer.ID) {
				continue
			}
			peer.Accepting = true
		}
		peers = append(peers, peer)
	}

	return peers
}

func (service *Service) manualTrusted(fingerprint string) bool {
	record, ok := service.Store.Get(fingerprint)
	return ok && record.Source == model.SourceManual && record.State == model.StateTrusted
}

func (service *Service) cleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.preparedMu.Lock()
			for id, entry := range service.prepared {
				if time.Now().After(entry.expires) {
					delete(service.prepared, id)
					service.Broker.Release(entry.peer.ID)
				}
			}
			service.preparedMu.Unlock()
		}
	}
}

func (service *Service) takePrepared(id string) (prepared, bool) {
	service.preparedMu.Lock()
	defer service.preparedMu.Unlock()

	entry, ok := service.prepared[id]
	if !ok {
		return prepared{}, false
	}
	delete(service.prepared, id)

	if time.Now().After(entry.expires) {
		service.Broker.Release(entry.peer.ID)
		return prepared{}, false
	}

	return entry, true
}

func randomID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
