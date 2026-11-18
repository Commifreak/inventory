package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/commifreak/inventory/internal/server/store"
)

const oidcStateCookie = "inventory_oidc"

// oidcProvider implements login via OpenID Connect (Authentik, Authelia, Keycloak, ...).
// Discovery happens lazily so the server starts even if the IdP is down.
type oidcProvider struct {
	s        *Server
	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func newOIDCProvider(s *Server) *oidcProvider { return &oidcProvider{s: s} }

func (o *oidcProvider) init(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, o.verifier, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := discoverProvider(ctx, o.s.cfg.OIDC.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	o.provider = p
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.s.cfg.OIDC.ClientID})
	return o.provider, o.verifier, nil
}

func (o *oidcProvider) oauthConfig(r *http.Request, p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.s.cfg.OIDC.ClientID,
		ClientSecret: o.s.cfg.OIDC.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  o.s.baseURL(r) + "/auth/oidc/callback",
		Scopes:       o.s.cfg.OIDC.Scopes,
	}
}

type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Expires  int64  `json:"e"`
}

func (o *oidcProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	p, _, err := o.init(r.Context())
	if err != nil {
		o.s.log.Error("oidc", "err", err)
		o.s.web.renderLogin(w, r, "Single sign-on is currently unavailable: "+err.Error())
		return
	}
	st := oidcState{State: randomToken(24), Nonce: randomToken(24), Verifier: oauth2.GenerateVerifier(), Next: safeNext(r.URL.Query().Get("next")), Expires: time.Now().Add(10 * time.Minute).Unix()}
	raw, _ := json.Marshal(st)
	enc, err := o.s.secrets.Encrypt(string(raw))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(enc)), Path: "/auth/oidc/",
		HttpOnly: true, Secure: strings.HasPrefix(o.s.baseURL(r), "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	url := o.oauthConfig(r, p).AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

func (o *oidcProvider) handleCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string, err error) {
		o.s.log.Warn("oidc login failed", "reason", msg, "err", err, "ip", o.s.clientIP(r))
		o.s.web.renderLogin(w, r, msg)
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail("Single sign-on failed: "+e+" "+r.URL.Query().Get("error_description"), nil)
		return
	}
	c, err := r.Cookie(oidcStateCookie)
	if err != nil {
		fail("Login session expired, please try again.", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/auth/oidc/", MaxAge: -1})
	encB, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		fail("Invalid login state.", err)
		return
	}
	raw, err := o.s.secrets.Decrypt(string(encB))
	var st oidcState
	if err != nil || json.Unmarshal([]byte(raw), &st) != nil || time.Now().Unix() > st.Expires || r.URL.Query().Get("state") != st.State {
		fail("Invalid or expired login state, please try again.", err)
		return
	}
	p, verifier, err := o.init(r.Context())
	if err != nil {
		fail("Single sign-on is currently unavailable.", err)
		return
	}
	tok, err := o.oauthConfig(r, p).Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		fail("Could not complete single sign-on.", err)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(r.Context(), rawID)
	if err != nil {
		fail("Invalid ID token.", err)
		return
	}
	if idt.Nonce != st.Nonce {
		fail("Invalid ID token nonce.", nil)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail("Invalid ID token claims.", err)
		return
	}
	// Some providers (e.g. Authelia 4.39+) put groups, user name and e-mail
	// only into the userinfo response.
	groups := claimStrings(claims[o.s.cfg.OIDC.GroupsClaim])
	_, hasName := claims["preferred_username"]
	_, hasEmail := claims["email"]
	if (len(groups) == 0 && o.s.cfg.OIDC.AdminGroup != "") || !hasName || !hasEmail {
		if ui, err := p.UserInfo(r.Context(), oauth2.StaticTokenSource(tok)); err == nil {
			var uc map[string]any
			if ui.Claims(&uc) == nil {
				groups = claimStrings(uc[o.s.cfg.OIDC.GroupsClaim])
				for k, v := range uc {
					if _, ok := claims[k]; !ok {
						claims[k] = v
					}
				}
			}
		}
	}
	if g := o.s.cfg.OIDC.AdminGroup; g != "" && !slices.Contains(groups, g) {
		fail("Your account is not a member of the group required for this application.", errors.New("missing group "+g))
		return
	}
	u, err := o.s.oidcUser(r.Context(), idt.Subject, claims)
	if err != nil {
		fail("Could not create user: "+err.Error(), err)
		return
	}
	if u.Disabled {
		fail("Your account is disabled.", nil)
		return
	}
	if err := o.s.newSession(w, r, u); err != nil {
		fail("Could not create session.", err)
		return
	}
	o.s.store.Audit(r.Context(), u.Username, "login.oidc", o.s.clientIP(r))
	http.Redirect(w, r, st.Next, http.StatusSeeOther)
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Fields(strings.ReplaceAll(t, ",", " "))
	}
	return nil
}

// oidcUser finds or creates the user for an OIDC subject. Existing local
// users are never linked automatically, to avoid account takeover.
func (s *Server) oidcUser(ctx context.Context, sub string, claims map[string]any) (*store.User, error) {
	email, _ := claims["email"].(string)
	if u, err := s.store.UserBySubject(ctx, sub); err == nil {
		if email != "" && u.Email != email {
			_ = s.store.UpdateUserOIDC(ctx, u.ID, sub, email)
		}
		return u, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	name, _ := claims["preferred_username"].(string)
	if name == "" {
		name, _ = claims["name"].(string)
	}
	if name == "" {
		name = email
	}
	if name == "" {
		h := sha256.Sum256([]byte(sub))
		name = "sso-" + base64.RawURLEncoding.EncodeToString(h[:6])
	}
	candidate := name
	for i := 0; i < 20; i++ {
		if _, err := s.store.UserByName(ctx, candidate); errors.Is(err, store.ErrNotFound) {
			u := &store.User{Username: candidate, OIDCSubject: sub, Email: email}
			if err := s.store.CreateUser(ctx, u); err != nil {
				return nil, err
			}
			s.store.Audit(ctx, candidate, "user.created.oidc", "")
			return s.store.UserByID(ctx, u.ID)
		}
		candidate = fmt.Sprintf("%s-sso%d", name, i+1)
		if i == 0 {
			candidate = name + "-sso"
		}
	}
	return nil, errors.New("no free user name")
}

// discoverProvider loads the provider configuration. The issuer must match
// the discovery document exactly; Authentik's issuer ends with "/", others
// do not, so the variant with/without the trailing slash is tried as well.
func discoverProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err == nil || !strings.Contains(err.Error(), "did not match") {
		return p, err
	}
	alt := issuer + "/"
	if strings.HasSuffix(issuer, "/") {
		alt = strings.TrimRight(issuer, "/")
	}
	if p2, err2 := oidc.NewProvider(ctx, alt); err2 == nil {
		return p2, nil
	}
	return nil, err
}
