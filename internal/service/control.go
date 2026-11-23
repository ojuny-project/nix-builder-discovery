package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/broker"
	"github.com/ojuny-project/nix-builder-discovery/internal/control"
	"github.com/ojuny-project/nix-builder-discovery/internal/job"
	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/pairing"
	"github.com/ojuny-project/nix-builder-discovery/internal/trust"
)

var (
	errDenied  = errors.New("device is denied")
	errSkipped = errors.New("pairing was skipped")
)

func (service *Service) listenControl() (net.Listener, error) {
	directory := filepath.Dir(service.Config.ControlSocket)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create runtime directory: %w", err)
	}

	_ = os.Remove(service.Config.ControlSocket)

	listener, err := net.Listen("unix", service.Config.ControlSocket)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(service.Config.ControlSocket, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("chmod control socket: %w", err)
	}

	return listener, nil
}

func (service *Service) serveControl(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go service.handleControl(connection)
	}
}

func (service *Service) handleControl(connection net.Conn) {
	defer connection.Close()

	decoder := json.NewDecoder(connection)
	encoder := json.NewEncoder(connection)

	var request control.Request
	if err := decoder.Decode(&request); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		buffer := make([]byte, 1)
		_, _ = connection.Read(buffer)
		cancel()
	}()

	send := func(event control.Event) {
		_ = encoder.Encode(event)
	}

	switch request.Command {
	case "status":
		send(control.Event{Type: control.EventStatus, Status: service.status()})
	case "peers":
		send(control.Event{Type: control.EventPeers, Peers: service.Registry.Snapshot()})
	case "pending":
		send(control.Event{Type: control.EventPending, Pending: service.Pairing.List()})
	case "decide":
		if err := service.Pairing.Decide(request.ID, pairing.Decision(request.Decision)); err != nil {
			send(control.Event{Type: control.EventError, Error: err.Error()})
		}
	case "trust.list":
		send(control.Event{Type: control.EventTrust, Trust: service.Store.List()})
	case "trust.set":
		if err := service.setTrust(request); err != nil {
			send(control.Event{Type: control.EventError, Error: err.Error()})
		}
	case "trust.revoke":
		if err := service.Store.Remove(request.Fingerprint); err != nil {
			send(control.Event{Type: control.EventError, Error: err.Error()})
		}
	case "trust.revoke-default":
		if err := service.Store.RemoveSource(model.SourceDefault); err != nil {
			send(control.Event{Type: control.EventError, Error: err.Error()})
		}
	case "jobs":
		converted := []control.JobInfo{}
		for _, entry := range service.Jobs.Jobs() {
			converted = append(converted, control.JobInfo{
				ID:      entry.ID,
				System:  entry.System,
				DrvPath: entry.DrvPath,
				Client:  entry.Client,
				State:   entry.State,
			})
		}
		send(control.Event{Type: control.EventJobs, Jobs: converted})
	case "job.prepare":
		service.prepareJob(ctx, request, send)
	case "job.run":
		service.runJob(ctx, request, send)
	default:
		send(control.Event{Type: control.EventError, Error: "unknown command " + request.Command})
	}

	send(control.Event{Type: control.EventDone})
}

func (service *Service) setTrust(request control.Request) error {
	state := model.State(request.State)
	if state != model.StateTrusted && state != model.StateDenied {
		return errors.New("state must be trusted or denied")
	}

	source := model.Source(request.Source)
	if source == "" {
		source = model.SourceManual
	}
	if source != model.SourceManual && source != model.SourceDefault && source != model.SourcePeer {
		return errors.New("invalid trust source")
	}

	record := trust.Record{
		Fingerprint: request.Fingerprint,
		State:       state,
		Source:      source,
	}

	if peer, ok := service.Registry.Lookup(request.Fingerprint); ok {
		record.PublicKey = peer.Key
		record.Hostname = peer.Hostname
		record.Address = peer.Address
	}

	return service.Store.Put(record)
}

func (service *Service) prepareJob(ctx context.Context, request control.Request, send func(control.Event)) {
	waitCtx := ctx
	if service.Config.Wait {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, service.Config.WaitTimeout)
		defer cancel()
	}

	peer, err := service.Broker.Acquire(waitCtx, request.System, service.Config.Wait)
	if err != nil {
		switch {
		case errors.Is(err, broker.ErrBusy):
			if service.Config.Wait {
				send(control.Event{Type: control.EventDecision, Decision: "postpone"})
			} else {
				send(control.Event{Type: control.EventDecision, Decision: "decline"})
			}
		case errors.Is(err, context.DeadlineExceeded):
			send(control.Event{Type: control.EventDecision, Decision: "postpone"})
		default:
			send(control.Event{Type: control.EventDecision, Decision: "decline"})
		}
		return
	}

	if err := service.ensureOutgoing(ctx, peer); err != nil {
		service.Broker.Release(peer.ID)
		send(control.Event{Type: control.EventDecision, Decision: "decline"})
		return
	}

	id, err := randomID()
	if err != nil {
		service.Broker.Release(peer.ID)
		send(control.Event{Type: control.EventError, Error: err.Error()})
		return
	}

	service.preparedMu.Lock()
	service.prepared[id] = prepared{peer: peer, expires: time.Now().Add(2 * time.Minute)}
	service.preparedMu.Unlock()

	send(control.Event{Type: control.EventDecision, Decision: "accept", Peer: peer, JobID: id})
}

func (service *Service) runJob(ctx context.Context, request control.Request, send func(control.Event)) {
	entry, ok := service.takePrepared(request.JobID)
	if !ok {
		send(control.Event{Type: control.EventError, Error: "prepared job is missing or expired"})
		return
	}

	peer := entry.peer
	leased := true
	release := func() {
		if leased {
			service.Broker.Release(peer.ID)
			leased = false
		}
	}
	defer release()

	spec := model.JobSpec{
		System:  request.System,
		DrvPath: request.DrvPath,
		DrvJSON: request.DrvJSON,
		Inputs:  request.Inputs,
		Outputs: request.Outputs,
		Client:  service.selfPeer(),
	}

	offset := 0
	onLog := func(text string) {
		offset += len(text)
		send(control.Event{Type: control.EventLog, Log: text})
	}

	for attempt := 1; attempt <= service.Config.MaxAttempts; attempt++ {
		spec.ID = fmt.Sprintf("%s-%d", request.JobID, attempt)
		spec.Attempt = attempt

		outputs, err := service.Client.Run(ctx, peer, spec, offset, onLog)
		if err == nil {
			service.finishJob(ctx, peer, spec.ID, outputs, send)
			return
		}

		var remote *job.RemoteError
		if errors.As(err, &remote) {
			send(control.Event{Type: control.EventError, Error: remote.Error()})
			return
		}

		attachCtx, cancel := context.WithTimeout(ctx, service.Config.ReconnectGrace)
		outputs, attachErr := service.attach(attachCtx, peer, spec.ID, offset, onLog)
		cancel()
		if attachErr == nil {
			service.finishJob(ctx, peer, spec.ID, outputs, send)
			return
		}

		service.Logger.Warn("builder lost",
			"peer", peer.ID,
			"attempt", attempt,
			"error", attachErr,
		)

		release()
		offset = 0

		if attempt == service.Config.MaxAttempts {
			break
		}

		next, err := service.Broker.Acquire(ctx, request.System, service.Config.Wait)
		if err != nil {
			send(control.Event{Type: control.EventError, Error: "no builder completed the job: " + err.Error()})
			return
		}
		peer = next
		leased = true

		if err := service.ensureOutgoing(ctx, peer); err != nil {
			send(control.Event{Type: control.EventError, Error: err.Error()})
			return
		}
	}

	send(control.Event{Type: control.EventError, Error: "no builder completed the job"})
}

func (service *Service) attach(ctx context.Context, peer model.Peer, id string, offset int, onLog func(string)) ([]string, error) {
	for {
		outputs, err := service.Client.Attach(ctx, peer, id, offset, onLog)
		if err == nil {
			return outputs, nil
		}

		var refused *job.RefusedError
		if errors.As(err, &refused) && refused.Status == 404 {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (service *Service) finishJob(ctx context.Context, peer model.Peer, jobID string, outputs []string, send func(control.Event)) {
	service.Logger.Info("job finished", "peer", peer.ID, "job", jobID, "outputs", outputs, "cache", peer.CacheURL)

	if peer.CacheURL != "" {
		send(control.Event{Type: control.EventResult, Outputs: outputs, CacheURL: peer.CacheURL})
		return
	}

	service.Logger.Info("fetching outputs", "peer", peer.ID, "job", jobID)

	reader, err := service.Client.Outputs(ctx, peer, jobID)
	if err != nil {
		send(control.Event{Type: control.EventError, Error: "fetch outputs: " + err.Error()})
		return
	}
	defer reader.Close()

	if err := os.MkdirAll(service.Config.RuntimeDir, 0o755); err != nil {
		send(control.Event{Type: control.EventError, Error: err.Error()})
		return
	}

	file, err := os.CreateTemp(service.Config.RuntimeDir, "outputs-*.nar")
	if err != nil {
		send(control.Event{Type: control.EventError, Error: err.Error()})
		return
	}
	path := file.Name()

	if _, err := io.Copy(file, reader); err != nil {
		file.Close()
		os.Remove(path)
		send(control.Event{Type: control.EventError, Error: "download outputs: " + err.Error()})
		return
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		send(control.Event{Type: control.EventError, Error: err.Error()})
		return
	}

	service.Logger.Info("outputs downloaded", "peer", peer.ID, "job", jobID, "path", path, "bytes", fileSize(path))
	send(control.Event{Type: control.EventResult, Outputs: outputs, ExportPath: path})
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func (service *Service) ensureOutgoing(ctx context.Context, peer model.Peer) error {
	switch service.Store.Decide(peer.ID, service.Config.Outgoing) {
	case model.PolicyAllow:
		return service.rememberDefault(peer)
	case model.PolicyDeny:
		return errDenied
	}

	request, err := service.Pairing.Add(pairing.Request{
		Direction: pairing.Outgoing,
		PeerID:    peer.ID,
		Hostname:  peer.Hostname,
		Address:   peer.Address,
		Systems:   peer.Systems,
	})
	if err != nil {
		return err
	}

	decision, err := service.Pairing.Wait(ctx, request.ID)
	if err != nil && !errors.Is(err, pairing.ErrTimeout) {
		return err
	}

	return service.applyDecision(peer, decision)
}

func (service *Service) authorizeIncoming(ctx context.Context, fingerprint string, client model.Peer) error {
	switch service.Store.Decide(fingerprint, service.Config.Incoming) {
	case model.PolicyAllow:
		return service.rememberDefault(client)
	case model.PolicyDeny:
		return errDenied
	}

	request, err := service.Pairing.Add(pairing.Request{
		Direction: pairing.Incoming,
		PeerID:    fingerprint,
		Hostname:  client.Hostname,
		Address:   client.Address,
		Systems:   client.Systems,
	})
	if err != nil {
		return err
	}

	decision, err := service.Pairing.Wait(ctx, request.ID)
	if err != nil && !errors.Is(err, pairing.ErrTimeout) {
		return err
	}

	return service.applyDecision(client, decision)
}

func (service *Service) applyDecision(peer model.Peer, decision pairing.Decision) error {
	switch decision {
	case pairing.DecisionTrust:
		return service.Store.Put(trust.Record{
			Fingerprint: peer.ID,
			PublicKey:   peer.Key,
			Hostname:    peer.Hostname,
			Address:     peer.Address,
			State:       model.StateTrusted,
			Source:      model.SourceManual,
		})
	case pairing.DecisionDeny:
		_ = service.Store.Put(trust.Record{
			Fingerprint: peer.ID,
			PublicKey:   peer.Key,
			Hostname:    peer.Hostname,
			Address:     peer.Address,
			State:       model.StateDenied,
			Source:      model.SourcePeer,
		})
		return errDenied
	default:
		return errSkipped
	}
}

func (service *Service) rememberDefault(peer model.Peer) error {
	if _, ok := service.Store.Get(peer.ID); ok {
		return nil
	}

	return service.Store.Put(trust.Record{
		Fingerprint: peer.ID,
		PublicKey:   peer.Key,
		Hostname:    peer.Hostname,
		Address:     peer.Address,
		State:       model.StateTrusted,
		Source:      model.SourceDefault,
	})
}
