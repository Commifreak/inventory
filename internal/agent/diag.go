package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// The agent keeps its latest warnings and errors (diag.json in the data dir)
// and sends them with every check-in, so problems that happened while the
// server was unreachable show up on the server later.

const (
	diagMaxEntries = 20
	diagMaxAge     = 30 * 24 * time.Hour
	diagMaxMessage = 1000
)

type diagLog struct {
	mu      sync.Mutex
	path    func() string // nil: memory only (tests)
	loaded  bool
	entries []protocol.AgentLogEntry
}

var diag = &diagLog{path: diagPath}

func diagPath() string { return filepath.Join(DataDir(), "diag.json") }

func (d *diagLog) load() {
	if d.loaded {
		return
	}
	d.loaded = true
	if d.path == nil {
		return
	}
	if b, err := os.ReadFile(d.path()); err == nil {
		_ = json.Unmarshal(b, &d.entries)
	}
}

func (d *diagLog) add(e protocol.AgentLogEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.load()
	d.entries = append(d.entries, e)
	if n := len(d.entries) - diagMaxEntries; n > 0 {
		d.entries = append([]protocol.AgentLogEntry(nil), d.entries[n:]...)
	}
	if d.path == nil {
		return
	}
	if b, err := json.Marshal(d.entries); err == nil {
		_ = writeFileAtomic(d.path(), b, 0o600)
	}
}

// recent returns the entries of the last 30 days, oldest first.
func (d *diagLog) recent() []protocol.AgentLogEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.load()
	var out []protocol.AgentLogEntry
	for _, e := range d.entries {
		if time.Since(e.Time) < diagMaxAge {
			out = append(out, e)
		}
	}
	return out
}

// diagHandler passes records on and records warnings and errors.
type diagHandler struct {
	next  slog.Handler
	attrs []slog.Attr
	group string
	log   *diagLog
}

func newDiagHandler(next slog.Handler, log *diagLog) slog.Handler {
	return &diagHandler{next: next, log: log}
}

func (h *diagHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelWarn || h.next.Enabled(ctx, l)
}

func (h *diagHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		var b strings.Builder
		b.WriteString(r.Message)
		for _, a := range h.attrs {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve())
		}
		r.Attrs(func(a slog.Attr) bool {
			if !a.Equal(slog.Attr{}) {
				fmt.Fprintf(&b, " %s=%v", h.prefix()+a.Key, a.Value.Resolve())
			}
			return true
		})
		h.log.add(protocol.AgentLogEntry{Time: r.Time, Level: r.Level.String(), Message: truncateStr(b.String(), diagMaxMessage)})
	}
	if h.next.Enabled(ctx, r.Level) {
		return h.next.Handle(ctx, r)
	}
	return nil
}

func (h *diagHandler) prefix() string {
	if h.group == "" {
		return ""
	}
	return h.group + "."
}

// WithAttrs stores the attributes with the group prefix active at this point.
func (h *diagHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = slices.Clone(h.attrs)
	for _, a := range attrs {
		if !a.Equal(slog.Attr{}) {
			c.attrs = append(c.attrs, slog.Attr{Key: h.prefix() + a.Key, Value: a.Value})
		}
	}
	c.next = h.next.WithAttrs(attrs)
	return &c
}

func (h *diagHandler) WithGroup(name string) slog.Handler {
	c := *h
	if c.group != "" {
		name = c.group + "." + name
	}
	c.group = name
	c.next = h.next.WithGroup(name)
	return &c
}

// ProxyDescription describes the proxy the agent uses for target.
func ProxyDescription(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "invalid URL: " + target
	}
	p, source, err := ProxyFor(u)
	switch {
	case err != nil:
		return "error: " + err.Error()
	case p == nil:
		return "none (direct connection)"
	}
	return p.Redacted() + " (" + source + ")"
}

// diagnostics returns what the agent sends with a check-in.
func (a *Agent) diagnostics() *protocol.AgentDiagnostics {
	return &protocol.AgentDiagnostics{Proxy: ProxyDescription(a.cfg.ServerURL), Log: diag.recent()}
}
