package job

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/tlsutil"
)

const logLimit = 1 << 20

// Authorizer checks incoming trust for one certificate fingerprint. It may
// block while a pairing request waits for a local decision.
type Authorizer func(ctx context.Context, fingerprint string, client model.Peer) error

// Server is the builder-side job API.
type Server struct {
	Runner    Runner
	Max       int
	Grace     time.Duration
	Authorize Authorizer
	Logger    *slog.Logger

	mu     sync.Mutex
	jobs   map[string]*Job
	active int
}

func NewServer(runner Runner, max int, grace time.Duration, authorize Authorizer, logger *slog.Logger) *Server {
	if max < 1 {
		max = 1
	}
	if grace <= 0 {
		grace = time.Minute
	}

	return &Server{
		Runner:    runner,
		Max:       max,
		Grace:     grace,
		Authorize: authorize,
		Logger:    logger,
		jobs:      map[string]*Job{},
	}
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jobs", server.handleJobs)
	mux.HandleFunc("/v1/jobs/", server.handleJob)
	return mux
}

func (server *Server) Active() int {
	server.mu.Lock()
	defer server.mu.Unlock()

	return server.active
}

func (server *Server) Jobs() []JobInfo {
	server.mu.Lock()
	defer server.mu.Unlock()

	jobs := make([]JobInfo, 0, len(server.jobs))
	for _, current := range server.jobs {
		jobs = append(jobs, current.info())
	}

	return jobs
}

func (server *Server) handleJobs(response http.ResponseWriter, request *http.Request) {
	fingerprint, err := tlsutil.PeerFingerprint(request.TLS)
	if err != nil {
		http.Error(response, err.Error(), http.StatusUnauthorized)
		return
	}

	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var spec model.JobSpec
	if err := json.NewDecoder(io.LimitReader(request.Body, 4<<20)).Decode(&spec); err != nil {
		http.Error(response, "invalid job: "+err.Error(), http.StatusBadRequest)
		return
	}
	if spec.ID == "" || spec.DrvPath == "" || spec.System == "" {
		http.Error(response, "job is missing id, drv path, or system", http.StatusBadRequest)
		return
	}
	if spec.Client.ID != "" && spec.Client.ID != fingerprint {
		http.Error(response, "client identity does not match the certificate", http.StatusForbidden)
		return
	}
	spec.Client.ID = fingerprint

	if server.Authorize != nil {
		if err := server.Authorize(request.Context(), fingerprint, spec.Client); err != nil {
			http.Error(response, err.Error(), http.StatusForbidden)
			return
		}
	}

	job, err := server.create(spec)
	if err != nil {
		if errors.Is(err, errBusy) {
			http.Error(response, err.Error(), http.StatusTooManyRequests)
			return
		}
		http.Error(response, err.Error(), http.StatusConflict)
		return
	}

	server.stream(response, request, job, 0)
}

func (server *Server) handleJob(response http.ResponseWriter, request *http.Request) {
	fingerprint, err := tlsutil.PeerFingerprint(request.TLS)
	if err != nil {
		http.Error(response, err.Error(), http.StatusUnauthorized)
		return
	}

	path := strings.TrimPrefix(request.URL.Path, "/v1/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(response, request)
		return
	}
	id := parts[0]

	server.mu.Lock()
	current, ok := server.jobs[id]
	server.mu.Unlock()
	if !ok {
		http.NotFound(response, request)
		return
	}
	if current.client != fingerprint {
		http.Error(response, "job belongs to another client", http.StatusForbidden)
		return
	}

	if server.Authorize != nil {
		if err := server.Authorize(request.Context(), fingerprint, current.spec.Client); err != nil {
			http.Error(response, err.Error(), http.StatusForbidden)
			return
		}
	}

	if len(parts) == 1 && request.Method == http.MethodDelete {
		current.cancelJob()
		response.WriteHeader(http.StatusAccepted)
		return
	}

	if len(parts) == 2 && parts[1] == "attach" && request.Method == http.MethodGet {
		offset := 0
		if raw := request.URL.Query().Get("offset"); raw != "" {
			fmt.Sscanf(raw, "%d", &offset)
		}
		server.stream(response, request, current, offset)
		return
	}

	if len(parts) == 2 && parts[1] == "outputs" && request.Method == http.MethodGet {
		server.outputs(response, request, current)
		return
	}

	http.NotFound(response, request)
}

func (server *Server) create(spec model.JobSpec) (*Job, error) {
	server.mu.Lock()
	defer server.mu.Unlock()

	if existing, ok := server.jobs[spec.ID]; ok {
		if existing.client != spec.Client.ID {
			return nil, fmt.Errorf("job id belongs to another client")
		}
		return existing, nil
	}

	if server.active >= server.Max {
		return nil, errBusy
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		spec:        spec,
		client:      spec.Client.ID,
		log:         &bytes.Buffer{},
		subscribers: map[chan model.JobEvent]struct{}{},
		cancel:      cancel,
		grace:       server.Grace,
	}

	server.jobs[spec.ID] = job
	server.active++

	go server.run(ctx, job)

	return job, nil
}

func (server *Server) run(ctx context.Context, job *Job) {
	if err := server.Runner.Validate(ctx, job.spec); err != nil {
		job.finish(nil, err)
		server.done(job)
		return
	}

	outputs, err := server.Runner.Run(ctx, job.spec, job)
	job.finish(outputs, err)
	server.done(job)
}

func (server *Server) done(job *Job) {
	server.mu.Lock()
	server.active--
	server.mu.Unlock()

	time.AfterFunc(server.Grace, func() {
		server.mu.Lock()
		delete(server.jobs, job.spec.ID)
		server.mu.Unlock()
	})
}

func (server *Server) stream(response http.ResponseWriter, request *http.Request, job *Job, offset int) {
	history, events, done := job.subscribe(offset)

	flusher, _ := response.(http.Flusher)
	response.Header().Set("Content-Type", "application/x-ndjson")
	response.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(response)
	for _, event := range history {
		if err := encoder.Encode(event); err != nil {
			job.unsubscribe(events)
			return
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	if done {
		return
	}

	for {
		select {
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := encoder.Encode(event); err != nil {
				job.unsubscribe(events)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		case <-request.Context().Done():
			job.unsubscribe(events)
			return
		}
	}
}

func (server *Server) outputs(response http.ResponseWriter, request *http.Request, job *Job) {
	outputs, done, err := job.result()
	if !done {
		http.Error(response, "job is not finished", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(response, err.Error(), http.StatusConflict)
		return
	}

	server.Logger.Info("exporting outputs", "job", job.spec.ID, "outputs", outputs)

	reader, err := server.Runner.Export(request.Context(), outputs)
	if err != nil {
		server.Logger.Warn("export outputs", "job", job.spec.ID, "error", err)
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	response.Header().Set("Content-Type", "application/x-nix-archive")
	written, err := io.Copy(response, reader)
	if err != nil {
		server.Logger.Warn("copy outputs", "job", job.spec.ID, "error", err)
	}
	server.Logger.Info("outputs exported", "job", job.spec.ID, "bytes", written)
}

var errBusy = errors.New("builder is at its job cap")

// Job is one derivation accepted by the builder.
type Job struct {
	spec   model.JobSpec
	client string
	grace  time.Duration

	mu          sync.Mutex
	log         *bytes.Buffer
	base        int
	written     int
	done        bool
	outputs     []string
	err         string
	subscribers map[chan model.JobEvent]struct{}
	cancel      context.CancelFunc
	graceTimer  *time.Timer
}

func (job *Job) Write(data []byte) (int, error) {
	job.appendLog(data)
	return len(data), nil
}

func (job *Job) appendLog(data []byte) {
	job.mu.Lock()
	defer job.mu.Unlock()

	start := job.written
	job.written += len(data)
	job.log.Write(data)
	if job.log.Len() > logLimit {
		trim := job.log.Len() - logLimit
		job.log.Next(trim)
		job.base += trim
	}

	event := model.JobEvent{Type: model.EventLog, Log: string(data), Offset: start}
	job.broadcastLocked(event)
}

func (job *Job) finish(outputs []string, err error) {
	job.mu.Lock()
	defer job.mu.Unlock()

	if job.done {
		return
	}
	job.done = true
	job.outputs = outputs
	if err != nil {
		job.err = err.Error()
	}

	event := job.resultEventLocked()
	job.broadcastLocked(event)

	for channel := range job.subscribers {
		close(channel)
		delete(job.subscribers, channel)
	}
}

func (job *Job) resultEventLocked() model.JobEvent {
	if job.err != "" {
		return model.JobEvent{Type: model.EventError, Error: job.err}
	}
	return model.JobEvent{Type: model.EventResult, Outputs: job.outputs}
}

func (job *Job) broadcastLocked(event model.JobEvent) {
	for channel := range job.subscribers {
		select {
		case channel <- event:
		default:
		}
	}
}

func (job *Job) subscribe(offset int) ([]model.JobEvent, chan model.JobEvent, bool) {
	job.mu.Lock()
	defer job.mu.Unlock()

	if job.graceTimer != nil {
		job.graceTimer.Stop()
		job.graceTimer = nil
	}

	history := []model.JobEvent{}

	if offset < job.base {
		offset = job.base
	}
	if offset > job.written {
		offset = job.written
	}
	if offset < job.written {
		start := offset - job.base
		history = append(history, model.JobEvent{
			Type:   model.EventLog,
			Log:    job.log.String()[start:],
			Offset: offset,
		})
	}

	if job.done {
		history = append(history, job.resultEventLocked())
		return history, nil, true
	}

	events := make(chan model.JobEvent, 256)
	job.subscribers[events] = struct{}{}

	return history, events, false
}

func (job *Job) unsubscribe(events chan model.JobEvent) {
	if events == nil {
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()

	if _, ok := job.subscribers[events]; !ok {
		return
	}
	delete(job.subscribers, events)
	close(events)

	if len(job.subscribers) > 0 || job.done {
		return
	}
	job.graceTimer = time.AfterFunc(job.grace, func() {
		job.mu.Lock()
		expired := !job.done && len(job.subscribers) == 0
		job.mu.Unlock()
		if expired {
			job.cancelJob()
		}
	})
}

func (job *Job) result() ([]string, bool, error) {
	job.mu.Lock()
	defer job.mu.Unlock()

	if !job.done {
		return nil, false, nil
	}
	if job.err != "" {
		return nil, true, errors.New(job.err)
	}

	return job.outputs, true, nil
}

func (job *Job) cancelJob() {
	job.mu.Lock()
	cancel := job.cancel
	job.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

type JobInfo struct {
	ID      string    `json:"id"`
	System  string    `json:"system"`
	DrvPath string    `json:"drv_path"`
	Client  string    `json:"client"`
	State   string    `json:"state"`
	Started time.Time `json:"started"`
}

func (job *Job) info() JobInfo {
	job.mu.Lock()
	defer job.mu.Unlock()

	state := "running"
	if job.done {
		state = "done"
		if job.err != "" {
			state = "failed"
		}
	}

	return JobInfo{
		ID:      job.spec.ID,
		System:  job.spec.System,
		DrvPath: job.spec.DrvPath,
		Client:  job.client,
		State:   state,
	}
}
