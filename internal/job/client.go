package job

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/tlsutil"
)

// RemoteError is a build failure reported by the builder.
type RemoteError struct {
	Message string
}

func (err *RemoteError) Error() string {
	return err.Message
}

// RefusedError is a refusal before a job starts.
type RefusedError struct {
	Status  int
	Message string
}

func (err *RefusedError) Error() string {
	return fmt.Sprintf("builder refused (%d): %s", err.Status, err.Message)
}

// Client submits jobs to a builder.
type Client struct {
	Certificate tls.Certificate
}

func NewClient(certificate tls.Certificate) *Client {
	return &Client{Certificate: certificate}
}

func (client *Client) endpoint(peer model.Peer) string {
	return "https://" + net.JoinHostPort(peer.Address, strconv.Itoa(peer.BuildPort))
}

func (client *Client) httpClient(peer model.Peer) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig:       tlsutil.ClientConfig(client.Certificate, peer.ID),
		},
	}
}

func (client *Client) Run(ctx context.Context, peer model.Peer, spec model.JobSpec, offset int, onLog func(string)) ([]string, error) {
	body, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint(peer)+"/v1/jobs", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	return client.stream(ctx, peer, request, onLog)
}

func (client *Client) Attach(ctx context.Context, peer model.Peer, id string, offset int, onLog func(string)) ([]string, error) {
	url := client.endpoint(peer) + "/v1/jobs/" + id + "/attach?offset=" + strconv.Itoa(offset)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return client.stream(ctx, peer, request, onLog)
}

func (client *Client) stream(ctx context.Context, peer model.Peer, request *http.Request, onLog func(string)) ([]string, error) {
	response, err := client.httpClient(peer).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, &RefusedError{
			Status:  response.StatusCode,
			Message: strings.TrimSpace(string(message)),
		}
	}

	decoder := json.NewDecoder(response.Body)
	for {
		var event model.JobEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}

		switch event.Type {
		case model.EventLog:
			if onLog != nil {
				onLog(event.Log)
			}
		case model.EventResult:
			return event.Outputs, nil
		case model.EventError:
			return nil, &RemoteError{Message: event.Error}
		}
	}
}

func (client *Client) Outputs(ctx context.Context, peer model.Peer, id string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	_ = cancel

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint(peer)+"/v1/jobs/"+id+"/outputs", nil)
	if err != nil {
		return nil, err
	}

	response, err := client.httpClient(peer).Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		return nil, &RefusedError{Status: response.StatusCode, Message: strings.TrimSpace(string(message))}
	}

	return response.Body, nil
}
