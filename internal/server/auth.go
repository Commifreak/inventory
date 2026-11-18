package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/commifreak/inventory/internal/server/store"
)

const sessionCookie = "inventory_session"

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
	ctxDevice
	ctxAccess
	ctxImpersonator
)

// impersonatorFrom returns the superadmin signed in as the current user (support session).
func impersonatorFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(ctxImpersonator).(*store.User)
	return u
}

func userFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(ctxUser).(*store.User)
	return u
}

func sessionFrom(ctx context.Context) *store.Session {
	s, _ := ctx.Value(ctxSession).(*store.Session)
	return s
}

// ensureAdmin creates the initial "admin" user on first start.
func (s *Server) ensureAdmin(ctx context.Context) error {
	n, err := s.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	pw := s.cfg.InitialAdminPassword
	generated := pw == ""
	if generated {
		pw = randomPassword()
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return err
	}
	admin := &store.User{Username: "admin", PasswordHash: hash, MustChangePassword: true, Superadmin: true}
	if err := s.store.CreateUser(ctx, admin); err != nil {
		return err
	}
	// Member of the first area, so its tokens show up as "your tokens".
	if areas, err := s.store.ListAreas(ctx); err == nil && len(areas) > 0 {
		_ = s.store.SetMemberships(ctx, admin.ID, store.MemberManual, []int64{areas[0].ID})
	}
	if generated {
		// Printed once to the container log on purpose.
		fmt.Printf("\n================================================================\n"+
			" Initial login\n   user:     admin\n   password: %s\n"+
			" You will be asked to change the password after the first login.\n"+
			"================================================================\n\n", pw)
	} else {
		s.log.Info("created user admin with INITIAL_ADMIN_PASSWORD")
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

func checkPassword(hash, pw string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// dummyHash is compared against when a user does not exist, to keep timing uniform.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), 12)

func validatePassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters long")
	}
	if len(pw) > 72 {
		return errors.New("password must be at most 72 characters long")
	}
	return nil
}

// newSession creates a session and sets the cookie.
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, u *store.User) error {
	return s.newSessionAs(w, r, u, 0)
}

// newSessionAs creates a session for u; impersonatorID != 0 makes it a
// support session of that superadmin (no login time is recorded for u).
func (s *Server) newSessionAs(w http.ResponseWriter, r *http.Request, u *store.User, impersonatorID int64) error {
	token := randomToken(32)
	now := time.Now()
	sess := &store.Session{IDHash: hashToken(token), UserID: u.ID, CSRF: randomToken(24), CreatedAt: now, ExpiresAt: now.Add(s.cfg.SessionLifetime),
		ImpersonatorID: impersonatorID}
	if err := s.store.CreateSession(r.Context(), sess, s.clientIP(r), truncate(r.UserAgent(), 200)); err != nil {
		return err
	}
	if impersonatorID == 0 {
		_ = s.store.TouchLogin(r.Context(), u.ID)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.baseURL(r), "https://"),
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// loadSession resolves the session cookie.
func (s *Server) loadSession(r *http.Request) (*store.User, *store.Session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, err := s.store.SessionByHash(r.Context(), hashToken(c.Value))
	if err != nil || time.Now().After(sess.ExpiresAt) {
		return nil, nil
	}
	u, err := s.store.UserByID(r.Context(), sess.UserID)
	if err != nil || u.Disabled {
		return nil, nil
	}
	// Sliding expiration, at most once per 10 minutes.
	if time.Until(sess.ExpiresAt) < s.cfg.SessionLifetime-10*time.Minute {
		exp := time.Now().Add(s.cfg.SessionLifetime)
		if s.store.ExtendSession(r.Context(), sess.IDHash, exp) == nil {
			sess.ExpiresAt = exp
		}
	}
	return u, sess
}

// requireUser protects UI routes. Unsafe methods need a valid CSRF token.
func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, sess := s.loadSession(r)
		if u == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+safeNext(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "not logged in", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.checkCSRF(r, sess) {
				http.Error(w, "invalid CSRF token, please reload the page", http.StatusForbidden)
				return
			}
		}
		// Support session: the superadmin must still be an active superadmin.
		var imp *store.User
		if sess.ImpersonatorID != 0 {
			imp, _ = s.store.UserByID(r.Context(), sess.ImpersonatorID)
			if imp == nil || imp.Disabled || !imp.Superadmin {
				s.clearSession(w, r)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}
		if imp == nil && u.MustChangePassword && u.PasswordHash != "" && r.URL.Path != "/account/password" && r.URL.Path != "/logout" {
			http.Redirect(w, r, "/account/password", http.StatusSeeOther)
			return
		}
		// Rights are read on every request: changes apply immediately.
		acc, err := s.loadAccess(r.Context(), u)
		if err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if !acc.Super && len(acc.Areas) == 0 {
			s.clearSession(w, r)
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?error="+urlQuery(errNoArea), http.StatusSeeOther)
				return
			}
			http.Error(w, errNoArea, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxSession, sess)
		ctx = context.WithValue(ctx, ctxAccess, acc)
		if imp != nil {
			ctx = context.WithValue(ctx, ctxImpersonator, imp)
		}
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) checkCSRF(r *http.Request, sess *store.Session) bool {
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" {
		tok = r.PostFormValue("csrf")
	}
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) == 1
}

// safeNext only allows local redirect targets.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
		return "/"
	}
	return next
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------------------
// rate limiting (login attempts, enrollment)
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter() *rateLimiter { return &rateLimiter{buckets: map[string]*bucket{}} }

// allow implements a token bucket: burst tokens, refilled at perMinute.
func (l *rateLimiter) allow(key string, burst, perMinute float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * perMinute
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if time.Since(b.last) > time.Hour {
			delete(l.buckets, k)
		}
	}
}
