package job

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/model"
)

// Runner executes a derivation and exports its outputs.
type Runner interface {
	Validate(ctx context.Context, spec model.JobSpec) error
	Run(ctx context.Context, spec model.JobSpec, log io.Writer) ([]string, error)
	Export(ctx context.Context, outputs []string) (io.ReadCloser, error)
}

// NixRunner uses the local Nix installation.
type NixRunner struct {
	Nix string
	Env []string
}

func NewNixRunner(nix string, env []string) *NixRunner {
	if nix == "" {
		nix = "nix"
	}
	return &NixRunner{Nix: nix, Env: env}
}

func (runner *NixRunner) environment() []string {
	env := append([]string{}, os.Environ()...)
	env = append(env, runner.Env...)
	return env
}

func (runner *NixRunner) Validate(ctx context.Context, spec model.JobSpec) error {
	if len(spec.DrvJSON) == 0 {
		return nil
	}

	command := exec.CommandContext(ctx, runner.Nix,
		"--extra-experimental-features", "nix-command flakes",
		"derivation", "add")
	command.Stdin = bytes.NewReader(spec.DrvJSON)
	command.Env = runner.environment()

	var stderr bytes.Buffer
	command.Stderr = &stderr

	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("nix derivation add: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	path := strings.TrimSpace(string(output))
	if path != spec.DrvPath {
		return fmt.Errorf("derivation path %s does not match %s", path, spec.DrvPath)
	}

	return nil
}

func (runner *NixRunner) Run(ctx context.Context, spec model.JobSpec, log io.Writer) ([]string, error) {
	command := exec.CommandContext(ctx, "nix-store", "--realise", spec.DrvPath)
	command.Env = runner.environment()
	command.Stderr = log

	var output bytes.Buffer
	command.Stdout = &output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	}
	command.WaitDelay = 5 * time.Second

	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("build failed: %w", err)
	}

	var outputs []string
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			outputs = append(outputs, line)
		}
	}

	return outputs, nil
}

func (runner *NixRunner) Export(ctx context.Context, outputs []string) (io.ReadCloser, error) {
	query := exec.CommandContext(ctx, "nix-store", append([]string{"--query", "--requisites"}, outputs...)...)
	query.Env = runner.environment()

	requisites, err := query.Output()
	if err != nil {
		return nil, fmt.Errorf("nix-store --query --requisites: %w", err)
	}

	paths := strings.Fields(string(requisites))
	if len(paths) == 0 {
		return nil, errors.New("no output paths to export")
	}

	command := exec.CommandContext(ctx, "nix-store", append([]string{"--export"}, paths...)...)
	command.Env = runner.environment()

	var stderr bytes.Buffer
	command.Stderr = &stderr

	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start export: %w", err)
	}

	go func() {
		_ = command.Wait()
	}()

	return pipe, nil
}
