package service

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type idleSnapshot struct {
	session    bool
	power      bool
	localBuild bool
}

type idleState struct {
	mu    sync.RWMutex
	value idleSnapshot
}

func (state *idleState) set(value idleSnapshot) {
	state.mu.Lock()
	defer state.mu.Unlock()

	state.value = value
}

func (state *idleState) snapshot() idleSnapshot {
	state.mu.RLock()
	defer state.mu.RUnlock()

	return state.value
}

func (service *Service) monitor(ctx context.Context) {
	service.updateIdle()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.updateIdle()
		}
	}
}

func (service *Service) updateIdle() {
	session := true
	if service.Config.IdleSession {
		session = sessionIdle()
	}

	power := true
	if service.Config.IdlePower {
		power = onAC()
	}

	service.idle.set(idleSnapshot{
		session:    session,
		power:      power,
		localBuild: localBuildRunning(),
	})
}

func sessionIdle() bool {
	output, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return true
	}

	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		show, err := exec.Command("loginctl", "show-session", fields[0], "-p", "IdleHint").Output()
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(show)) == "IdleHint=no" {
			return false
		}
	}

	return true
}

func onAC() bool {
	entries, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return true
	}

	hasBattery := false
	online := false

	for _, entry := range entries {
		base := filepath.Join("/sys/class/power_supply", entry.Name())

		kind, err := os.ReadFile(filepath.Join(base, "type"))
		if err != nil {
			continue
		}

		switch strings.TrimSpace(string(kind)) {
		case "Battery":
			hasBattery = true
		case "Mains", "USB":
			state, err := os.ReadFile(filepath.Join(base, "online"))
			if err == nil && strings.TrimSpace(string(state)) == "1" {
				online = true
			}
		}
	}

	if !hasBattery {
		return true
	}
	return online
}

func localBuildRunning() bool {
	groups := nixBuildGIDs()
	if len(groups) == 0 {
		return false
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "Gid:") && !strings.HasPrefix(line, "Groups:") {
				continue
			}
			fields := strings.Fields(line)
			for _, field := range fields[1:] {
				if groups[field] {
					return true
				}
			}
		}
	}

	return false
}

func nixBuildGIDs() map[string]bool {
	groups := map[string]bool{}

	group, err := user.LookupGroup("nixbld")
	if err != nil {
		return groups
	}
	groups[group.Gid] = true

	return groups
}
