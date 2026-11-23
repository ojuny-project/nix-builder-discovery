package hook

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/ojuny-project/nix-builder-discovery/internal/control"
)

const maxFrame = 16 << 20

// ImportHelper is set at build time to the absolute path of nbd-import.
var ImportHelper = ""

type jobRequest struct {
	system   string
	drvPath  string
	features []string
}

// Run implements Nix's build-hook protocol on the given streams.
func Run(ctx context.Context, socket, nix string, stdin io.Reader, protocol io.Writer, log io.Writer) error {
	source := &source{reader: bufio.NewReader(stdin)}

	if err := source.readSettings(); err != nil {
		return err
	}

	request, err := source.readJob()
	if err != nil {
		return err
	}

	client := control.NewClient(socket)

	var (
		decision string
		jobID    string
	)

	prepareErr := client.Do(ctx, control.Request{
		Command:  "job.prepare",
		System:   request.system,
		DrvPath:  request.drvPath,
		Features: request.features,
	}, func(event control.Event) error {
		switch event.Type {
		case control.EventDecision:
			decision = event.Decision
			jobID = event.JobID
		case control.EventError:
			return errors.New(event.Error)
		}
		return nil
	})

	if prepareErr != nil {
		fmt.Fprint(protocol, "# decline\n")
		return nil
	}

	switch decision {
	case "accept":
	case "postpone":
		fmt.Fprint(protocol, "# postpone\n")
		return nil
	default:
		fmt.Fprint(protocol, "# decline\n")
		return nil
	}

	if len(jobID) >= 8 {
		fmt.Fprintf(protocol, "# accept\nnbd:%s\n", jobID[:8])
	} else {
		fmt.Fprintf(protocol, "# accept\nnbd:%s\n", jobID)
	}

	inputs, err := source.readStrings()
	if err != nil {
		return err
	}
	outputs, err := source.readStrings()
	if err != nil {
		return err
	}

	derivation, err := derivationJSON(ctx, nix, request.drvPath)
	if err != nil {
		return err
	}

	var result control.Event

	runErr := client.Do(ctx, control.Request{
		Command: "job.run",
		JobID:   jobID,
		System:  request.system,
		DrvPath: request.drvPath,
		DrvJSON: derivation,
		Inputs:  inputs,
		Outputs: outputs,
	}, func(event control.Event) error {
		switch event.Type {
		case control.EventLog:
			_, _ = io.WriteString(log, event.Log)
		case control.EventResult:
			result = event
		case control.EventError:
			return errors.New(event.Error)
		}
		return nil
	})

	if runErr != nil {
		return runErr
	}

	return importOutputs(ctx, nix, result, log)
}

func derivationJSON(ctx context.Context, nix, drvPath string) ([]byte, error) {
	command := exec.CommandContext(ctx, nix,
		"--extra-experimental-features", "nix-command flakes",
		"derivation", "show", drvPath)
	command.Stderr = os.Stderr

	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("nix derivation show: %w", err)
	}

	var document struct {
		Derivations map[string]json.RawMessage `json:"derivations"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, fmt.Errorf("parse derivation: %w", err)
	}
	if len(document.Derivations) != 1 {
		return nil, fmt.Errorf("expected one derivation, got %d", len(document.Derivations))
	}

	for _, raw := range document.Derivations {
		return raw, nil
	}

	return nil, errors.New("derivation is missing")
}

func importOutputs(ctx context.Context, nix string, result control.Event, log io.Writer) error {
	if len(result.Outputs) == 0 {
		return nil
	}

	if result.CacheURL != "" {
		args := []string{
			"--extra-experimental-features", "nix-command flakes",
			"copy", "--from", result.CacheURL,
		}
		args = append(args, result.Outputs...)

		command := exec.CommandContext(ctx, nix, args...)
		command.Stderr = log
		if err := command.Run(); err != nil {
			return fmt.Errorf("nix copy: %w", err)
		}
		return nil
	}

	if result.ExportPath == "" {
		return errors.New("builder returned outputs without a transfer path")
	}

	helper := ImportHelper
	if helper == "" {
		var err error
		helper, err = exec.LookPath("nbd-import")
		if err != nil {
			return fmt.Errorf("find nbd-import: %w", err)
		}
	}

	arguments := append([]string{result.ExportPath}, result.Outputs...)
	command := exec.CommandContext(ctx, helper, arguments...)
	command.Stdout = log
	command.Stderr = log
	if err := command.Run(); err != nil {
		return fmt.Errorf("nbd-import: %w", err)
	}

	_ = os.Remove(result.ExportPath)

	for _, output := range result.Outputs {
		if _, err := os.Stat(output); err != nil {
			return fmt.Errorf("imported output %s is missing: %w", output, err)
		}
	}

	return nil
}

type source struct {
	reader *bufio.Reader
}

func (source *source) readSettings() error {
	for {
		kind, err := source.readUint64()
		if err != nil {
			return err
		}
		if kind == 0 {
			return nil
		}

		if _, err := source.readString(); err != nil {
			return err
		}
		if _, err := source.readString(); err != nil {
			return err
		}
	}
}

func (source *source) readJob() (jobRequest, error) {
	kind, err := source.readString()
	if err != nil {
		return jobRequest{}, err
	}
	if kind != "try" {
		return jobRequest{}, fmt.Errorf("unexpected build hook request %q", kind)
	}

	if _, err := source.readUint64(); err != nil {
		return jobRequest{}, err
	}
	system, err := source.readString()
	if err != nil {
		return jobRequest{}, err
	}
	drvPath, err := source.readString()
	if err != nil {
		return jobRequest{}, err
	}
	features, err := source.readStrings()
	if err != nil {
		return jobRequest{}, err
	}

	return jobRequest{system: system, drvPath: drvPath, features: features}, nil
}

func (source *source) readUint64() (uint64, error) {
	var buffer [8]byte
	if _, err := io.ReadFull(source.reader, buffer[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buffer[:]), nil
}

func (source *source) readString() (string, error) {
	size, err := source.readUint64()
	if err != nil {
		return "", err
	}
	if size > maxFrame {
		return "", fmt.Errorf("build hook frame is too large")
	}

	buffer := make([]byte, size)
	if _, err := io.ReadFull(source.reader, buffer); err != nil {
		return "", err
	}

	padding := (8 - size%8) % 8
	if padding > 0 {
		if _, err := io.CopyN(io.Discard, source.reader, int64(padding)); err != nil {
			return "", err
		}
	}

	return string(buffer), nil
}

func (source *source) readStrings() ([]string, error) {
	count, err := source.readUint64()
	if err != nil {
		return nil, err
	}
	if count > maxFrame {
		return nil, fmt.Errorf("build hook set is too large")
	}

	values := make([]string, 0, count)
	for range count {
		value, err := source.readString()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	return values, nil
}

// LogWriter returns fd 4, the daemon's log pipe, or stderr when the hook is
// run by hand.
func LogWriter() io.Writer {
	file := os.NewFile(4, "nbd-build-log")
	if file == nil {
		return os.Stderr
	}
	if _, err := file.Stat(); err != nil {
		return os.Stderr
	}
	return file
}
