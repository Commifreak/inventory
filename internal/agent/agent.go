package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// Collector produces the payload of one section.
type Collector func(ctx context.Context, st *State) (data any, warnings []string, err error)

// collectorTimeouts bounds collector run times.
var collectorTimeouts = map[string]time.Duration{
	protocol.CollectUpdates: 20 * time.Minute,
	protocol.CollectSMART:   5 * time.Minute,
}

// Collectors returns the collectors of this platform.
func Collectors() map[string]Collector { return platformCollectors() }

// Agent is the running agent.
type Agent struct {
	cfg    *Config
	state  *State
	client *Client
	log    *slog.Logger
	colls  map[string]Collector
}

// Run runs the agent until ctx is cancelled. It returns errRestart when the
// process should exit so that the service manager starts the new binary.
func Run(ctx context.Context, log *slog.Logger) error {
	cfg, err := LoadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInstalled
		}
		return fmt.Errorf("load config: %w", err)
	}
	a := &Agent{cfg: cfg, state: LoadState(), log: log, colls: Collectors()}
	a.client = NewClient(cfg.ServerURL, cfg.Credential)
	log.Info("agent starting", "version", Version, "os", runtime.GOOS, "arch", runtime.GOARCH, "server", cfg.ServerURL)
	if err := a.checkPendingUpdate(); err != nil {
		return err
	}
	return a.loop(ctx)
}

// ErrRestart asks the caller to exit so the service manager restarts the agent.
var ErrRestart = errors.New("restart requested")

func (a *Agent) loop(ctx context.Context) error {
	backoff := time.Minute
	for {
		next, err := a.cycle(ctx)
		if errors.Is(err, ErrRestart) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("cycle failed", "err", err, "retry_in", backoff)
			a.state.LastError = err.Error()
			_ = SaveState(a.state)
			next = backoff
			backoff = min(backoff*2, 30*time.Minute)
		} else {
			backoff = time.Minute
			a.state.LastError = ""
		}
		// Jitter avoids all agents hitting the server at once.
		next += time.Duration(rand.Int64N(int64(next/10) + 1))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(next):
		}
		debug.FreeOSMemory()
	}
}

func (a *Agent) enroll(ctx context.Context) error {
	if a.cfg.EnrollmentToken == "" {
		return errors.New("not enrolled and no enrollment token available - please reinstall the agent")
	}
	resp, err := a.client.Enroll(ctx, protocol.EnrollRequest{Token: a.cfg.EnrollmentToken, Identity: Identity(), AgentVersion: Version})
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	a.cfg.DeviceID = resp.DeviceID
	a.cfg.Credential = resp.Credential
	a.cfg.EnrollmentToken = "" // single use per installation
	if err := SaveConfig(a.cfg); err != nil {
		return err
	}
	a.client.Credential = resp.Credential
	a.state.ServerConfig = &resp.Config
	a.state.LastRun = map[string]time.Time{} // collect everything right away
	a.state.Revoked = false
	_ = SaveState(a.state)
	a.log.Info("enrolled", "device", resp.DeviceID)
	return nil
}

// cycle performs one check-in and runs due collectors. It returns the time
// to wait until the next cycle.
func (a *Agent) cycle(ctx context.Context) (time.Duration, error) {
	if a.cfg.Credential == "" {
		if err := a.enroll(ctx); err != nil {
			return 0, err
		}
	}
	req := protocol.CheckinRequest{AgentVersion: Version, Identity: Identity(), BootTime: BootTime(), AgentTime: time.Now(), LastCollected: a.state.LastRun, UpdateResult: a.state.UpdateResult}
	resp, err := a.client.Checkin(ctx, req)
	if errors.Is(err, ErrUnauthorized) {
		return 6 * time.Hour, errors.New("the server does not know this device any more (deleted?) - reinstall the agent to enroll it again")
	}
	if err != nil {
		return 0, err
	}
	a.state.LastCheckin = time.Now()
	a.state.UpdateResult = nil
	a.state.ServerConfig = &resp.Config
	if a.state.PendingUpdate != nil && a.state.PendingUpdate.To == Version {
		a.log.Info("update confirmed", "version", Version)
		a.state.PendingUpdate = nil
		removeOldBinary()
		platformAfterUpdate()
	}
	if resp.Revoked {
		if !a.state.Revoked {
			a.log.Warn("device was revoked on the server - reporting stopped")
		}
		a.state.Revoked = true
		_ = SaveState(a.state)
		return 6 * time.Hour, nil
	}
	a.state.Revoked = false
	_ = SaveState(a.state)

	if err := a.collectAndReport(ctx, resp.CollectNow); err != nil {
		a.log.Warn("report failed", "err", err)
	}

	if resp.Update != nil && resp.Update.Version != Version {
		if err := a.update(ctx, resp.Update); err != nil {
			if errors.Is(err, ErrRestart) {
				return 0, err
			}
			a.log.Error("update failed", "to", resp.Update.Version, "err", err)
			a.state.UpdateResult = &protocol.UpdateResult{FromVersion: Version, ToVersion: resp.Update.Version, Success: false, Error: err.Error(), Time: time.Now()}
			_ = SaveState(a.state)
		}
	}
	return a.nextWait(), nil
}

func (a *Agent) config() protocol.AgentConfig {
	if a.state.ServerConfig != nil && a.state.ServerConfig.CheckinIntervalSec > 0 {
		return *a.state.ServerConfig
	}
	return protocol.DefaultConfig()
}

// nextWait returns the time until the next check-in or due collector.
func (a *Agent) nextWait() time.Duration {
	cfg := a.config()
	wait := time.Duration(cfg.CheckinIntervalSec) * time.Second
	now := time.Now()
	for name := range a.colls {
		iv := cfg.Intervals[name]
		if iv <= 0 {
			continue
		}
		due := a.state.LastRun[name].Add(time.Duration(iv) * time.Second)
		if d := due.Sub(now); d < wait {
			wait = d
		}
	}
	return max(wait, 30*time.Second)
}

// collectAndReport runs due collectors and uploads their output.
func (a *Agent) collectAndReport(ctx context.Context, now []string) error {
	cfg := a.config()
	var due []string
	for _, name := range protocol.AllCollectors {
		if _, ok := a.colls[name]; !ok {
			continue
		}
		iv := cfg.Intervals[name]
		forced := slices.Contains(now, name)
		if iv <= 0 && !forced {
			continue
		}
		if forced || time.Since(a.state.LastRun[name]) >= time.Duration(iv)*time.Second {
			due = append(due, name)
		}
	}
	if len(due) == 0 {
		return nil
	}
	rep := protocol.Report{AgentVersion: Version, Sections: map[string]protocol.Section{}}
	eventsUntil := time.Now()
	for _, name := range due {
		rep.Sections[name] = a.runCollector(ctx, name)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := a.client.Report(ctx, rep); err != nil {
		return err
	}
	for name, sec := range rep.Sections {
		if sec.Error == "" {
			a.state.LastRun[name] = sec.CollectedAt
		} else {
			// Retry failed collectors after a quarter of their interval.
			iv := time.Duration(cfg.Intervals[name]) * time.Second
			a.state.LastRun[name] = sec.CollectedAt.Add(-iv + iv/4)
		}
	}
	if sec, ok := rep.Sections[protocol.CollectEvents]; ok && sec.Error == "" {
		a.state.EventsSince = eventsUntil.Add(-time.Hour) // overlap; the server deduplicates
	}
	return SaveState(a.state)
}

func (a *Agent) runCollector(ctx context.Context, name string) (sec protocol.Section) {
	timeout := collectorTimeouts[name]
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			sec = protocol.Section{CollectedAt: start, Error: fmt.Sprintf("collector panicked: %v", r)}
			a.log.Error("collector panic", "collector", name, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	data, warns, err := a.colls[name](cctx, a.state)
	sec = protocol.Section{CollectedAt: start, DurationMs: time.Since(start).Milliseconds(), Warnings: warns, Data: data}
	if err != nil {
		sec.Error = err.Error()
		sec.Data = nil
		a.log.Warn("collector failed", "collector", name, "err", err)
	} else {
		a.log.Debug("collector done", "collector", name, "ms", sec.DurationMs, "warnings", len(warns))
	}
	return sec
}

// CollectAll runs collectors once and returns their output (diagnostics).
func CollectAll(ctx context.Context, only []string) protocol.Report {
	a := &Agent{state: LoadState(), log: slog.New(slog.NewTextHandler(os.Stderr, nil)), colls: Collectors()}
	a.state.EventsSince = time.Time{}
	rep := protocol.Report{AgentVersion: Version, Sections: map[string]protocol.Section{}}
	for _, name := range protocol.AllCollectors {
		if _, ok := a.colls[name]; !ok || (len(only) > 0 && !slices.Contains(only, name)) {
			continue
		}
		rep.Sections[name] = a.runCollector(ctx, name)
	}
	return rep
}
