package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ojuny-project/nix-builder-discovery/internal/control"
	"github.com/ojuny-project/nix-builder-discovery/internal/hook"
	"github.com/ojuny-project/nix-builder-discovery/internal/identity"
	"github.com/ojuny-project/nix-builder-discovery/internal/model"
	"github.com/ojuny-project/nix-builder-discovery/internal/service"
)

const version = "0.1.0"

const usageText = `nix-builder-discovery %s

Usage:
  nix-builder-discovery <command> [flags]

Commands:
  version            print the version
  fingerprint        print this device's identity
  serve              run discovery, trust, and the build service
  hook               run the Nix build hook
  status             show service status
  peers              list discovered devices
  pending            list pairing requests
  decide <id> <act>  answer a pairing request: trust, skip, or deny
  trust list         list trust records
  trust allow <id>   trust a device
  trust deny <id>    deny a device
  trust revoke <id>  remove a trust record
  trust revoke-default  remove records created by an allow default
  jobs               list active builder jobs

Common flags:
  --socket <path>    control socket, default ` + control.DefaultSocket + `
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}

	var err error

	switch os.Args[1] {
	case "version", "--version":
		fmt.Println(version)
	case "fingerprint":
		err = fingerprint(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	case "hook":
		err = runHook(os.Args[2:])
	case "status":
		err = status(os.Args[2:])
	case "peers":
		err = peers(os.Args[2:])
	case "pending":
		err = pending(os.Args[2:])
	case "decide":
		err = decide(os.Args[2:])
	case "trust":
		err = trustCommand(os.Args[2:])
	case "jobs":
		err = jobs(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultStateDir() string {
	if dir := os.Getenv("NBD_STATE_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/nix-builder-discovery"
}

func defaultSocket() string {
	if socket := os.Getenv("NBD_CONTROL_SOCKET"); socket != "" {
		return socket
	}
	return control.DefaultSocket
}

func fingerprint(args []string) error {
	flags := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	stateDir := flags.String("state-dir", defaultStateDir(), "directory holding the device identity")
	if err := flags.Parse(args); err != nil {
		return err
	}

	device, err := identity.LoadOrCreate(*stateDir)
	if err != nil {
		return err
	}

	fmt.Printf("short-id: %s\n", device.ShortID())
	fmt.Printf("fingerprint: %s\n", device.Fingerprint())
	fmt.Printf("public-key: %s\n", device.PublicKeyBase64())

	return nil
}

type stringList []string

func (list *stringList) String() string {
	return strings.Join(*list, ",")
}

func (list *stringList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*list = append(*list, item)
		}
	}
	return nil
}

func runHook(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nix := os.Getenv("NBD_NIX")
	if nix == "" {
		nix = "nix"
	}

	log := hook.LogWriter()
	if err := hook.Run(ctx, defaultSocket(), nix, os.Stdin, os.Stderr, log); err != nil {
		fmt.Fprintln(log, "nbd-build-hook:", err)
		return err
	}

	return nil
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)

	config := service.DefaultConfig()

	var (
		systems  stringList
		ranges   stringList
		incoming string
		outgoing string
		logLevel string
	)

	flags.StringVar(&config.StateDir, "state-dir", config.StateDir, "state directory")
	flags.StringVar(&config.RuntimeDir, "runtime-dir", config.RuntimeDir, "runtime directory")
	flags.StringVar(&config.Hostname, "hostname", "", "hostname advertised on the public plane")
	flags.Var(&systems, "system", "supported system, repeatable or comma separated")
	flags.IntVar(&config.InfoPort, "info-port", config.InfoPort, "public info port")
	flags.IntVar(&config.BuildPort, "build-port", config.BuildPort, "job API port")
	flags.StringVar(&config.CacheURL, "cache-url", "", "binary cache URL for inputs and outputs")
	flags.StringVar(&incoming, "incoming-default", string(config.Incoming), "incoming default: ask, allow, deny")
	flags.StringVar(&outgoing, "outgoing-default", string(config.Outgoing), "outgoing default: ask, allow, deny")
	flags.Var(&ranges, "discovery-range", "discovery prefix, repeatable or comma separated")
	flags.BoolVar(&config.AutoDiscover, "discovery-auto", false, "use the connected subnet")
	flags.DurationVar(&config.ScanInterval, "discovery-interval", config.ScanInterval, "time between scans")
	flags.DurationVar(&config.ScanTimeout, "discovery-timeout", config.ScanTimeout, "timeout per probe")
	flags.IntVar(&config.Workers, "discovery-workers", config.Workers, "concurrent probes")
	flags.IntVar(&config.MaxConnections, "max-connections", config.MaxConnections, "concurrent jobs")
	flags.BoolVar(&config.Wait, "wait", false, "wait when every eligible builder is busy")
	flags.DurationVar(&config.WaitTimeout, "wait-timeout", config.WaitTimeout, "maximum wait for a slot")
	flags.DurationVar(&config.PairTimeout, "pair-timeout", config.PairTimeout, "pairing request timeout")
	flags.DurationVar(&config.ReconnectGrace, "reconnect-grace", config.ReconnectGrace, "time a lost job is kept")
	flags.IntVar(&config.MaxAttempts, "max-attempts", config.MaxAttempts, "attempts per derivation")
	flags.BoolVar(&config.IdleSession, "idle-session", config.IdleSession, "require an idle local session")
	flags.BoolVar(&config.IdlePower, "idle-power", config.IdlePower, "require AC power when a battery exists")
	flags.StringVar(&config.Nix, "nix", "", "path to the nix command")
	flags.StringVar(&config.ControlSocket, "control-socket", config.ControlSocket, "control socket")
	flags.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	if err := flags.Parse(args); err != nil {
		return err
	}

	incomingPolicy, ok := parsePolicy(incoming)
	if !ok {
		return fmt.Errorf("invalid incoming default %q", incoming)
	}
	outgoingPolicy, ok := parsePolicy(outgoing)
	if !ok {
		return fmt.Errorf("invalid outgoing default %q", outgoing)
	}
	config.Incoming = incomingPolicy
	config.Outgoing = outgoingPolicy

	if len(systems) == 0 {
		systems = stringList{localSystem()}
	}
	config.Systems = []string(systems)

	if len(ranges) > 0 {
		config.Ranges = nil
		for _, raw := range ranges {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return err
			}
			config.Ranges = append(config.Ranges, prefix)
		}
	}

	logger := newLogger(logLevel)
	slog.SetDefault(logger)

	instance, err := service.New(config, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return instance.Run(ctx)
}

func status(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return control.NewClient(*socket).Do(ctx, control.Request{Command: "status"}, func(event control.Event) error {
		if event.Type == control.EventError {
			return fmt.Errorf("%s", event.Error)
		}
		if event.Type != control.EventStatus {
			return nil
		}

		status := event.Status
		fmt.Printf("id: %s\n", status.ID)
		fmt.Printf("hostname: %s\n", status.Hostname)
		fmt.Printf("state: %s (%s)\n", status.State, status.BusyReason)
		fmt.Printf("accepting: %t\n", status.Accepting)
		fmt.Printf("peers: %d\n", status.Peers)
		fmt.Printf("jobs: %d/%d\n", status.ActiveJobs, status.MaxJobs)
		fmt.Printf("systems: %s\n", strings.Join(status.Systems, ","))
		fmt.Printf("incoming: %s\n", status.Policy["incoming"])
		fmt.Printf("outgoing: %s\n", status.Policy["outgoing"])
		return nil
	})
}

func peers(args []string) error {
	flags := flag.NewFlagSet("peers", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return control.NewClient(*socket).Do(ctx, control.Request{Command: "peers"}, func(event control.Event) error {
		if event.Type == control.EventError {
			return fmt.Errorf("%s", event.Error)
		}
		if event.Type != control.EventPeers {
			return nil
		}
		for _, peer := range event.Peers {
			fmt.Printf("%s  %s  %s  %s  %s  accepting=%t\n",
				peer.ID[:8],
				peer.Hostname,
				peer.Address,
				strings.Join(peer.Systems, ","),
				peer.State,
				peer.Accepting,
			)
		}
		return nil
	})
}

func pending(args []string) error {
	flags := flag.NewFlagSet("pending", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return control.NewClient(*socket).Do(ctx, control.Request{Command: "pending"}, func(event control.Event) error {
		if event.Type == control.EventError {
			return fmt.Errorf("%s", event.Error)
		}
		if event.Type != control.EventPending {
			return nil
		}
		for _, request := range event.Pending {
			fmt.Printf("%s  %s  %s  %s\n", request.ID, request.Direction, request.Hostname, request.PeerID)
		}
		return nil
	})
}

func decide(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nix-builder-discovery decide <id> <trust|skip|deny>")
	}

	flags := flag.NewFlagSet("decide", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return control.NewClient(*socket).Do(ctx, control.Request{
		Command:  "decide",
		ID:       args[0],
		Decision: args[1],
	}, func(event control.Event) error {
		if event.Type == control.EventError {
			return fmt.Errorf("%s", event.Error)
		}
		return nil
	})
}

func trustCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: nix-builder-discovery trust <list|allow|deny|revoke|revoke-default>")
	}

	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	client := control.NewClient(*socket)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch args[0] {
	case "list":
		return client.Do(ctx, control.Request{Command: "trust.list"}, func(event control.Event) error {
			if event.Type == control.EventError {
				return fmt.Errorf("%s", event.Error)
			}
			if event.Type != control.EventTrust {
				return nil
			}
			for _, record := range event.Trust {
				fmt.Printf("%s  %s  %s  %s  %s\n",
					record.Fingerprint[:8],
					record.Hostname,
					record.State,
					record.Source,
					record.Address,
				)
			}
			return nil
		})
	case "allow", "deny":
		if len(args) < 2 {
			return fmt.Errorf("usage: nix-builder-discovery trust %s <fingerprint>", args[0])
		}
		state := "trusted"
		if args[0] == "deny" {
			state = "denied"
		}
		return client.Do(ctx, control.Request{
			Command:     "trust.set",
			Fingerprint: args[1],
			State:       state,
			Source:      "manual",
		}, errorOnly)
	case "revoke":
		if len(args) < 2 {
			return fmt.Errorf("usage: nix-builder-discovery trust revoke <fingerprint>")
		}
		return client.Do(ctx, control.Request{
			Command:     "trust.revoke",
			Fingerprint: args[1],
		}, errorOnly)
	case "revoke-default":
		return client.Do(ctx, control.Request{Command: "trust.revoke-default"}, errorOnly)
	default:
		return fmt.Errorf("unknown trust command %q", args[0])
	}
}

func jobs(args []string) error {
	flags := flag.NewFlagSet("jobs", flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket(), "control socket")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return control.NewClient(*socket).Do(ctx, control.Request{Command: "jobs"}, func(event control.Event) error {
		if event.Type == control.EventError {
			return fmt.Errorf("%s", event.Error)
		}
		if event.Type != control.EventJobs {
			return nil
		}
		for _, entry := range event.Jobs {
			fmt.Printf("%s  %s  %s  %s\n", entry.ID, entry.State, entry.System, entry.DrvPath)
		}
		return nil
	})
}

func errorOnly(event control.Event) error {
	if event.Type == control.EventError {
		return fmt.Errorf("%s", event.Error)
	}
	return nil
}

func parsePolicy(value string) (model.Policy, bool) {
	return model.ParsePolicy(value)
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		parsed = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parsed}))
}

func localSystem() string {
	architecture := runtime.GOARCH
	switch architecture {
	case "amd64":
		architecture = "x86_64"
	case "arm64":
		architecture = "aarch64"
	}
	return architecture + "-linux"
}
