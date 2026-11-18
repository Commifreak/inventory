package server

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
	"github.com/commifreak/inventory/internal/tag"

	_ "embed"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, limit int64, v any) error {
	var body io.Reader = http.MaxBytesReader(nil, r.Body, limit)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer gz.Close()
		// Bound the decompressed size as well.
		body = io.LimitReader(gz, limit*8)
	}
	dec := json.NewDecoder(body)
	return dec.Decode(v)
}

// agentAuth authenticates "Authorization: Bearer <device id>.<secret>".
func (s *Server) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		cred, ok := strings.CutPrefix(auth, "Bearer ")
		id, secret, ok2 := strings.Cut(cred, ".")
		if !ok || !ok2 || id == "" || secret == "" {
			jsonError(w, http.StatusUnauthorized, "missing credentials")
			return
		}
		d, err := s.store.DeviceByID(r.Context(), id)
		if err != nil || subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(d.CredentialHash)) != 1 {
			if !s.limiter.allow("agentauth:"+s.clientIP(r), 20, 10) {
				jsonError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
			jsonError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxDevice, d)))
	}
}

func deviceFrom(ctx context.Context) *store.Device {
	d, _ := ctx.Value(ctxDevice).(*store.Device)
	return d
}

func newDeviceID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "d" + hex.EncodeToString(b)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.limiter.allow("enroll:"+ip, 10, 2) {
		if s.limiter.allow("enroll-log:"+ip, 1, 1) { // at most one log line per minute and IP
			s.log.Warn("enrollment rate limit exceeded", "ip", ip, "user_agent", r.UserAgent())
		}
		jsonError(w, http.StatusTooManyRequests, "too many enrollment attempts")
		return
	}
	var req protocol.EnrollRequest
	if err := readJSON(r, 1<<20, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	tok, err := s.store.TokenByValue(r.Context(), req.Token)
	if err != nil || !tok.Active() {
		id := req.Identity
		reason := s.rejectedToken(r, "enrollment", req.Token, tok, err,
			fmt.Sprintf("host %q (%s/%s, agent %s, hardware ID %s)", id.Hostname, id.OS, id.Arch, req.AgentVersion, id.HardwareID))
		jsonError(w, http.StatusForbidden, reason)
		return
	}
	id := req.Identity
	if id.Hostname == "" || !validOS(id.OS) || id.Arch == "" {
		jsonError(w, http.StatusBadRequest, "incomplete identity")
		return
	}
	secret := randomToken(32)
	ctx := r.Context()
	// Only devices of the token's area are recognised (no takeover across areas).
	d, err := s.store.FindDeviceByIdentity(ctx, tok.AreaID, id.HardwareID, id.MachineID)
	switch {
	case err == nil:
		if err := s.store.ReEnrollDevice(ctx, d.ID, hashToken(secret), id.Hostname, id.OS, id.Arch, req.AgentVersion, tok.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "database error")
			return
		}
		s.store.AuditArea(ctx, d.AreaID, "", "device.reenrolled", fmt.Sprintf("%s (%s) from %s", id.Hostname, d.ID, ip))
		s.log.Info("device re-enrolled", "device", d.ID, "hostname", id.Hostname, "ip", ip)
	case errors.Is(err, store.ErrNotFound):
		d = &store.Device{ID: newDeviceID(), Hostname: id.Hostname, OS: id.OS, Arch: id.Arch, HardwareID: id.HardwareID, MachineID: id.MachineID,
			CredentialHash: hashToken(secret), EnrollmentTokenID: tok.ID, EnrolledAt: time.Now(), AgentVersion: req.AgentVersion, Ring: RingStable, AreaID: tok.AreaID}
		if err := s.store.CreateDevice(ctx, d); err != nil {
			jsonError(w, http.StatusInternalServerError, "database error")
			return
		}
		s.store.AuditArea(ctx, d.AreaID, "", "device.enrolled", fmt.Sprintf("%s (%s) from %s", id.Hostname, d.ID, ip))
		s.log.Info("device enrolled", "device", d.ID, "hostname", id.Hostname, "ip", ip)
	default:
		jsonError(w, http.StatusInternalServerError, "database error")
		return
	}
	_ = s.store.UseToken(ctx, tok.ID)
	_ = s.store.Checkin(ctx, d.ID, time.Now(), ip, id.Hostname, req.AgentVersion, id.HardwareID, id.MachineID, time.Time{}, 0)
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{DeviceID: d.ID, Credential: d.ID + "." + secret, Config: s.collectionConfig(ctx)})
}

func validOS(os string) bool {
	return os == protocol.OSWindows || os == protocol.OSLinux || os == protocol.OSDarwin
}

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	d := deviceFrom(r.Context())
	ctx := r.Context()
	now := time.Now()
	if !d.RevokedAt.IsZero() {
		writeJSON(w, http.StatusOK, protocol.CheckinResponse{Revoked: true, ServerTime: now.UTC(), Config: s.collectionConfig(ctx)})
		return
	}
	var req protocol.CheckinRequest
	if err := readJSON(r, 1<<20, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var skew int64
	if !req.AgentTime.IsZero() {
		skew = int64(req.AgentTime.Sub(now).Seconds())
	}
	hostname := req.Identity.Hostname
	if hostname == "" {
		hostname = d.Hostname
	}
	wasOffline := !d.LastSeenAt.IsZero() && now.Sub(d.LastSeenAt) > 2*time.Duration(s.collectionConfig(ctx).CheckinIntervalSec)*time.Second
	if err := s.store.Checkin(ctx, d.ID, now, s.clientIP(r), hostname, req.AgentVersion, req.Identity.HardwareID, req.Identity.MachineID, req.BootTime, skew); err != nil {
		jsonError(w, http.StatusInternalServerError, "database error")
		return
	}
	d.AgentVersion = req.AgentVersion
	if m := truncate(req.Managed, 50); m != d.Managed {
		_ = s.store.SetManaged(ctx, d.ID, m)
		d.Managed = m
	}
	if diag := req.Diagnostics; diag != nil {
		_ = s.store.PutAgentDiagnostics(ctx, d.ID, now, sanitizeDiagnostics(*diag))
	}

	// Update bookkeeping.
	if ur := req.UpdateResult; ur != nil {
		_ = s.store.LogAgentUpdate(ctx, d.ID, ur.FromVersion, ur.ToVersion, ur.Success, ur.Error, ur.Time)
		if ur.Success {
			_ = s.store.SetUpdateState(ctx, d.ID, ur.ToVersion, updDone, "")
		} else {
			_ = s.store.SetUpdateState(ctx, d.ID, ur.ToVersion, updFailed, ur.Error)
			d.UpdateState, d.UpdateTarget, d.UpdateChangedAt = updFailed, ur.ToVersion, now
		}
	}
	if d.UpdateNowVersion != "" && d.UpdateNowVersion == req.AgentVersion {
		_ = s.store.SetUpdateNow(ctx, d.ID, "")
		d.UpdateNowVersion = ""
	}
	if d.UpdateState == updOffered && d.UpdateTarget == req.AgentVersion {
		_ = s.store.SetUpdateState(ctx, d.ID, d.UpdateTarget, updDone, "")
	}

	resp := protocol.CheckinResponse{Config: s.collectionConfig(ctx), ServerTime: now.UTC()}
	if target, _ := TargetVersion(d, s.updatePolicy(ctx), s.agents); target != "" && target != req.AgentVersion {
		// Back off after a failed attempt at the same version.
		backoff := d.UpdateState == updFailed && d.UpdateTarget == target && now.Sub(d.UpdateChangedAt) < 6*time.Hour
		if !backoff {
			if b, _, ok := s.agents.Binary(target, d.OS, d.Arch); ok {
				resp.Update = &protocol.UpdateOffer{
					Version:   target,
					URL:       fmt.Sprintf("%s/binary/%s/%s/%s", protocol.APIPrefix, target, d.OS, d.Arch),
					SHA256:    b.SHA256,
					Signature: b.Signature,
					Size:      b.Size,
				}
				if d.UpdateState != updOffered || d.UpdateTarget != target {
					_ = s.store.SetUpdateState(ctx, d.ID, target, updOffered, "")
				}
			}
		}
	}
	if d.CollectNow != "" {
		resp.CollectNow = strings.Split(d.CollectNow, ",")
		_ = s.store.SetCollectNow(ctx, d.ID, "")
	}
	writeJSON(w, http.StatusOK, resp)
	if wasOffline {
		s.kickAlerts(d.ID)
	}
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	d := deviceFrom(r.Context())
	if !d.RevokedAt.IsZero() {
		jsonError(w, http.StatusGone, "device revoked")
		return
	}
	var rep struct {
		AgentVersion string                     `json:"agent_version"`
		Sections     map[string]json.RawMessage `json:"sections"`
	}
	if err := readJSON(r, 32<<20, &rep); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid report: "+err.Error())
		return
	}
	if err := s.ingest(r.Context(), d, rep.Sections); err != nil {
		s.log.Error("ingest failed", "device", d.ID, "err", err)
		jsonError(w, http.StatusInternalServerError, "ingest failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	s.kickAlerts(d.ID)
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	s.serveBinary(w, r, r.PathValue("version"), r.PathValue("os"), r.PathValue("arch"))
}

func (s *Server) serveBinary(w http.ResponseWriter, r *http.Request, version, goos, goarch string) {
	b, path, ok := s.agents.Binary(version, goos, goarch)
	if !ok {
		jsonError(w, http.StatusNotFound, "no such agent binary")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		jsonError(w, http.StatusNotFound, "binary missing")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Agent-SHA256", b.SHA256)
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(b.File))
	http.ServeContent(w, r, b.File, st.ModTime(), f)
}

// ---------------------------------------------------------------------------
// installers
// ---------------------------------------------------------------------------

func (s *Server) installToken(w http.ResponseWriter, r *http.Request) (*store.EnrollmentToken, bool) {
	if !s.limiter.allow("install:"+s.clientIP(r), 30, 10) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return nil, false
	}
	tok, err := s.store.TokenByValue(r.Context(), r.PathValue("token"))
	if err != nil || !tok.Active() {
		reason := s.rejectedToken(r, "installer download", r.PathValue("token"), tok, err, "")
		http.Error(w, reason, http.StatusForbidden)
		return nil, false
	}
	return tok, true
}

// rejectedToken logs an attempt with an unknown or revoked enrollment token
// (server log and audit log) and returns the reason for the client. Only a
// short prefix of the presented token is recorded.
func (s *Server) rejectedToken(r *http.Request, what, presented string, tok *store.EnrollmentToken, lookupErr error, details string) string {
	reason, kind := "unknown enrollment token", "unknown token"
	if lookupErr == nil && tok != nil {
		reason, kind = "revoked enrollment token", fmt.Sprintf("revoked token %q", tok.Name)
	} else if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
		s.log.Error("enrollment token lookup failed", "err", lookupErr)
	}
	prefix := presented
	if len(prefix) > 6 {
		prefix = prefix[:6] + "…"
	}
	ip := s.clientIP(r)
	s.log.Warn("rejected "+what, "reason", kind, "token_prefix", prefix, "ip", ip, "user_agent", r.UserAgent(), "details", details)
	msg := fmt.Sprintf("%s %s from %s", kind, prefix, ip)
	if details != "" {
		msg += " – " + details
	}
	action := "enrollment.rejected"
	if what != "enrollment" {
		action = "installer.rejected"
	}
	var area int64
	if tok != nil {
		area = tok.AreaID // revoked token: the area it belonged to
	}
	s.store.AuditArea(r.Context(), area, "", action, msg)
	return reason
}

func (s *Server) handleInstallBinary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.installToken(w, r); !ok {
		return
	}
	goos, goarch := r.PathValue("os"), r.PathValue("arch")
	v := s.agents.Latest(goos, goarch, false)
	if v == "" {
		http.Error(w, "no agent available for "+goos+"/"+goarch, http.StatusNotFound)
		return
	}
	s.serveBinary(w, r, v, goos, goarch)
}

// handleWindowsInstaller serves the agent .exe with the install tag appended.
// file is "inventory-agent-setup-<arch>.exe".
func (s *Server) handleWindowsInstaller(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.installToken(w, r)
	if !ok {
		return
	}
	file := r.PathValue("file")
	arch := strings.TrimSuffix(strings.TrimPrefix(file, "inventory-agent-setup-"), ".exe")
	if arch != "amd64" && arch != "arm64" {
		http.Error(w, "unknown architecture", http.StatusNotFound)
		return
	}
	s.writeWindowsInstaller(w, r, tok, arch)
}

func (s *Server) writeWindowsInstaller(w http.ResponseWriter, r *http.Request, tok *store.EnrollmentToken, arch string) {
	v := s.agents.Latest(protocol.OSWindows, arch, false)
	if v == "" {
		http.Error(w, "no Windows agent available for "+arch, http.StatusNotFound)
		return
	}
	_, path, _ := s.agents.Binary(v, protocol.OSWindows, arch)
	bin, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "binary missing", http.StatusInternalServerError)
		return
	}
	tagged, err := tag.Append(bin, protocol.InstallTag{ServerURL: s.baseURL(r), EnrollmentToken: tok.Token})
	if err != nil {
		http.Error(w, "cannot build installer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="inventory-agent-setup-%s.exe"`, arch))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(tagged)))
	_, _ = w.Write(tagged)
}

//go:embed install.sh.tmpl
var installScriptTmpl string

var installScript = template.Must(template.New("install").Parse(installScriptTmpl))

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.installToken(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = installScript.Execute(w, map[string]string{
		"ServerURL": s.baseURL(r),
		"Token":     tok.Token,
		"APIPrefix": protocol.APIPrefix,
	})
}

// sanitizeDiagnostics limits what an agent can store.
func sanitizeDiagnostics(d protocol.AgentDiagnostics) protocol.AgentDiagnostics {
	const maxEntries, maxLen = 50, 2000
	if n := len(d.Log) - maxEntries; n > 0 {
		d.Log = d.Log[n:]
	}
	clip := func(s string) string {
		if len(s) > maxLen {
			return strings.ToValidUTF8(s[:maxLen], "") + "…"
		}
		return s
	}
	d.Proxy = clip(d.Proxy)
	for i := range d.Log {
		d.Log[i].Message = clip(d.Log[i].Message)
		d.Log[i].Level = clip(d.Log[i].Level)
	}
	return d
}
