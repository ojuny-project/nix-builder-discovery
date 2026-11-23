package info

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
)

const (
	Version = "1"
	path    = "/.nix-builder-discovery/v1/info"

	// TimestampTolerance is how far the payload clock may drift.
	TimestampTolerance = 10 * time.Minute
)

// Payload is the public-plane description of one device.
type Payload struct {
	ID         string
	Hostname   string
	Systems    []string
	InfoPort   int
	BuildPort  int
	CacheURL   string
	State      string
	BusyReason string
	Accepting  bool
	Slots      int
	Key        string
	Timestamp  int64
}

func Path() string {
	return path
}

func (payload Payload) Body() []byte {
	var builder strings.Builder

	fmt.Fprintf(&builder, "id=%s\n", payload.ID)
	fmt.Fprintf(&builder, "version=%s\n", Version)
	fmt.Fprintf(&builder, "hostname=%s\n", payload.Hostname)
	fmt.Fprintf(&builder, "systems=%s\n", strings.Join(payload.Systems, ","))
	fmt.Fprintf(&builder, "info-port=%d\n", payload.InfoPort)
	fmt.Fprintf(&builder, "build-port=%d\n", payload.BuildPort)
	fmt.Fprintf(&builder, "cache-url=%s\n", payload.CacheURL)
	fmt.Fprintf(&builder, "state=%s\n", payload.State)
	fmt.Fprintf(&builder, "busy-reason=%s\n", payload.BusyReason)
	fmt.Fprintf(&builder, "accepting=%d\n", boolInt(payload.Accepting))
	fmt.Fprintf(&builder, "slots=%d\n", payload.Slots)
	fmt.Fprintf(&builder, "key=%s\n", payload.Key)
	fmt.Fprintf(&builder, "timestamp=%d", payload.Timestamp)

	return []byte(builder.String())
}

// Sign returns the body followed by the detached signature line.
func (payload Payload) Sign(device *identity.Identity) []byte {
	body := payload.Body()
	signature := device.Sign(body)

	return append(body, []byte("\nsig="+base64.StdEncoding.EncodeToString(signature)+"\n")...)
}

// Parse verifies the signature and returns the payload.
func Parse(data []byte) (Payload, error) {
	trimmed := strings.TrimSuffix(string(data), "\n")
	index := strings.LastIndex(trimmed, "\nsig=")
	if index < 0 {
		return Payload{}, fmt.Errorf("info: missing signature")
	}

	body := trimmed[:index]
	signature, err := base64.StdEncoding.DecodeString(trimmed[index+len("\nsig="):])
	if err != nil {
		return Payload{}, fmt.Errorf("info: decode signature: %w", err)
	}

	fields := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Payload{}, fmt.Errorf("info: malformed line %q", line)
		}
		fields[key] = value
	}

	if fields["version"] != Version {
		return Payload{}, fmt.Errorf("info: version %q is not supported", fields["version"])
	}

	publicKey, err := identity.ParsePublicKey(fields["key"])
	if err != nil {
		return Payload{}, err
	}
	if !identity.Verify(publicKey, []byte(body), signature) {
		return Payload{}, fmt.Errorf("info: signature does not verify")
	}
	if fields["id"] != identity.FingerprintOf(publicKey) {
		return Payload{}, fmt.Errorf("info: id does not match key")
	}

	timestamp, err := strconv.ParseInt(fields["timestamp"], 10, 64)
	if err != nil {
		return Payload{}, fmt.Errorf("info: timestamp: %w", err)
	}
	drift := time.Since(time.Unix(timestamp, 0))
	if drift > TimestampTolerance || drift < -TimestampTolerance {
		return Payload{}, fmt.Errorf("info: timestamp is outside the tolerance")
	}

	infoPort, err := strconv.Atoi(fields["info-port"])
	if err != nil {
		return Payload{}, fmt.Errorf("info: info-port: %w", err)
	}
	buildPort, err := strconv.Atoi(fields["build-port"])
	if err != nil {
		return Payload{}, fmt.Errorf("info: build-port: %w", err)
	}
	slots, err := strconv.Atoi(fields["slots"])
	if err != nil {
		return Payload{}, fmt.Errorf("info: slots: %w", err)
	}

	systems := []string{}
	if fields["systems"] != "" {
		systems = strings.Split(fields["systems"], ",")
	}

	return Payload{
		ID:         fields["id"],
		Hostname:   fields["hostname"],
		Systems:    systems,
		InfoPort:   infoPort,
		BuildPort:  buildPort,
		CacheURL:   fields["cache-url"],
		State:      fields["state"],
		BusyReason: fields["busy-reason"],
		Accepting:  fields["accepting"] == "1",
		Slots:      slots,
		Key:        fields["key"],
		Timestamp:  timestamp,
	}, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
