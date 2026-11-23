package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ojuny-project/nix-builder-discovery/internal/control"
	"github.com/ojuny-project/nix-builder-discovery/internal/hook"
)

func main() {
	socket := os.Getenv("NBD_CONTROL_SOCKET")
	if socket == "" {
		socket = control.DefaultSocket
	}

	nix := os.Getenv("NBD_NIX")
	if nix == "" {
		nix = "nix"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := hook.LogWriter()

	if err := hook.Run(ctx, socket, nix, os.Stdin, os.Stderr, log); err != nil {
		fmt.Fprintln(log, "nbd-build-hook:", err)
		os.Exit(1)
	}
}
