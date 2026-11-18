// Package server implements the Inventory server: agent API, web UI,
// alerting and agent update distribution.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// Server is the application.
type Server struct {
	cfg     Config
	log     *slog.Logger
	store   *store.Store
	secrets *Secrets
	agents  *AgentRepo
	web     *webUI
	eol     *EOLData
	oidc    *oidcProvider
	mailer  Mailer

	limiter *rateLimiter

	alertKick chan string // device id ("" = all)
	wg        sync.WaitGroup
}

// New creates a server and runs first-start initialisation.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "inventory.db"))
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	sec, err := loadSecrets(cfg.DataDir, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	repo, err := newAgentRepo(cfg.AgentsDir, cfg.DataDir, log)
	if err != nil {
		return nil, fmt.Errorf("agent repository: %w", err)
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		store:     st,
		secrets:   sec,
		agents:    repo,
		limiter:   newRateLimiter(),
		alertKick: make(chan string, 256),
		eol:       newEOLData(cfg.DataDir, cfg.EOLFetch, log),
	}
	s.mailer = &smtpMailer{s: s}
	s.web, err = newWebUI(s)
	if err != nil {
		return nil, err
	}
	if cfg.OIDC.Enabled() {
		s.oidc = newOIDCProvider(s)
	}
	if err := s.ensureAdmin(context.Background()); err != nil {
		return nil, err
	}
	if err := s.ensureToken(context.Background()); err != nil {
		return nil, err
	}
	s.pruneAgents(context.Background())
	return s, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agent API (no interactive auth; agents use per-device credentials).
	mux.HandleFunc("POST "+protocol.APIPrefix+"/enroll", s.handleEnroll)
	mux.HandleFunc("POST "+protocol.APIPrefix+"/checkin", s.agentAuth(s.handleCheckin))
	mux.HandleFunc("POST "+protocol.APIPrefix+"/report", s.agentAuth(s.handleReport))
	mux.HandleFunc("GET "+protocol.APIPrefix+"/binary/{version}/{os}/{arch}", s.agentAuth(s.handleAgentBinary))
	mux.HandleFunc("GET "+protocol.APIPrefix+"/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server_time": time.Now().UTC()})
	})

	// Installer downloads authorised by an enrollment token in the URL.
	// They live below the agent prefix as well so that a single proxy rule
	// can exclude everything agents and installers need from forward auth.
	mux.HandleFunc("GET "+protocol.APIPrefix+"/install/{token}/install.sh", s.handleInstallScript)
	mux.HandleFunc("GET "+protocol.APIPrefix+"/install/{token}/agent/{os}/{arch}", s.handleInstallBinary)
	mux.HandleFunc("GET "+protocol.APIPrefix+"/install/{token}/windows/{file}", s.handleWindowsInstaller)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.DB.PingContext(r.Context()); err != nil {
			http.Error(w, "db: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})

	s.web.routes(mux)
	return securityHeaders(mux)
}

// Run serves HTTP until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	s.startBackground(ctx)
	errc := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", s.cfg.ListenAddr, "base_url", s.cfg.BaseURL, "version", s.cfg.Version)
		errc <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		s.wg.Wait()
		return s.store.Close()
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) startBackground(ctx context.Context) {
	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.alertLoop(ctx) }()
	go func() { defer s.wg.Done(); s.maintenanceLoop(ctx) }()
	go func() { defer s.wg.Done(); s.eol.loop(ctx) }()
}

// maintenanceLoop prunes old data and sessions.
func (s *Server) maintenanceLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		g := s.generalSettings(ctx)
		if err := s.store.Prune(ctx, time.Now().AddDate(0, 0, -g.RetentionDays)); err != nil && ctx.Err() == nil {
			s.log.Warn("prune failed", "err", err)
		}
		_ = s.store.PurgeExpiredSessions(ctx)
		s.limiter.cleanup()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pruneAgents keeps the newest agent versions plus every version in use.
func (s *Server) pruneAgents(ctx context.Context) {
	used := map[string]bool{}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return
	}
	for _, d := range devices {
		used[d.AgentVersion], used[d.PinnedVersion], used[d.UpdateNowVersion] = true, true, true
	}
	for _, v := range s.updatePolicy(ctx).RingVersions {
		used[v] = true
	}
	s.agents.Prune(5, func(v string) bool { return used[v] }, s.log)
}

// ensureToken creates a default enrollment token on first start.
func (s *Server) ensureToken(ctx context.Context) error {
	toks, err := s.store.ListTokens(ctx)
	if err != nil {
		return err
	}
	if len(toks) > 0 {
		return nil
	}
	areas, err := s.store.ListAreas(ctx)
	if err != nil || len(areas) == 0 {
		return err
	}
	_, err = s.store.CreateToken(ctx, randomToken(24), "Default", areas[0].ID)
	return err
}

// FirstActiveToken returns an active enrollment token (used by tests and tooling).
func (s *Server) FirstActiveToken(ctx context.Context) string {
	toks, _ := s.store.ListTokens(ctx)
	for _, t := range toks {
		if t.Active() {
			return t.Token
		}
	}
	return ""
}

// baseURL returns the public URL of the server: BASE_URL or derived from the request.
func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return s.cfg.BaseURL
	}
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if s.fromTrustedProxy(r) {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
			scheme = p
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return scheme + "://" + host
}

func (s *Server) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the client address, honouring X-Forwarded-For from trusted proxies.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.fromTrustedProxy(r) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		if xr := r.Header.Get("X-Real-Ip"); xr != "" {
			return strings.TrimSpace(xr)
		}
		return host
	}
	// Walk from the right, skipping trusted proxies.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		ip := net.ParseIP(p)
		if ip == nil {
			continue
		}
		trusted := false
		for _, n := range s.cfg.TrustedProxies {
			if n.Contains(ip) {
				trusted = true
				break
			}
		}
		if !trusted || i == 0 {
			return p
		}
	}
	return host
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if !strings.HasPrefix(r.URL.Path, protocol.APIPrefix) {
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		}
		next.ServeHTTP(w, r)
	})
}
