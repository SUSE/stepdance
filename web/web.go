package web

import (
	"github.com/SUSE/stepdance/cert"
	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

type Stepdance struct {
	Oauth2Config   oauth2.Config
	OidcConfig     *oidc.Config
	OidcProvider   *oidc.Provider
	Ctx            context.Context
	Verifier       *oidc.IDTokenVerifier
	templates      *Templates
	sessionManager *scs.SessionManager
	Step           *cert.Step
}

func InitStepdance(s *Stepdance, bind string) {
	s.sessionManager = newSessionManager()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/callback", s.callbackHandler)
	mux.HandleFunc("/certificate/download", s.downloadHandler)
	mux.HandleFunc("/certificate/request", s.certReqHandler)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static"))))

	var tok bool
	s.templates, tok = readTemplates()
	if !tok {
		return
	}

	slog.Info("Starting to listen ...", "bind", bind)
	panic(http.ListenAndServe(bind, s.sessionManager.LoadAndSave(mux)))
}

func (s *Stepdance) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Add("Content-Type", "text/html")
	p := PageData{Subject: s.sessionManager.GetString(r.Context(), "subject")}
	s.templates.Index.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) checkState(w http.ResponseWriter, r *http.Request) bool {
	if s.sessionManager.GetString(r.Context(), "state") != r.URL.Query().Get("state") {
		s.templates.Index.ExecuteTemplate(w, "base", nil)
		return false
	}

	return true
}

func (s *Stepdance) loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	s.sessionManager.Put(r.Context(), "state", state)
	s.sessionManager.Put(r.Context(), "nonce", nonce)

	http.Redirect(w, r, s.Oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (s *Stepdance) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if !s.checkState(w, r) {
		return
	}

	code := r.URL.Query().Get("code")

	if code == "" {
		s.templates.MissingCode.ExecuteTemplate(w, "base", nil)
		return
	}

	oauth2Token, err := s.Oauth2Config.Exchange(s.Ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := s.Verifier.Verify(s.Ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce := s.sessionManager.GetString(r.Context(), "nonce")
	if idToken.Nonce != nonce {
		http.Error(w, "Nonce does not match", http.StatusBadRequest)
		return
	}

	s.sessionManager.Put(r.Context(), "token", oauth2Token.AccessToken)
	ui, err := s.OidcProvider.UserInfo(s.Ctx, s.Oauth2Config.TokenSource(s.Ctx, oauth2Token))
	if err != nil {
		slog.Error("Failed to query userinfo", "error", err)
		http.Error(w, "Cannot determine subject", http.StatusInternalServerError)
		return
	}

	slog.Info("Authenticated user", "subject", ui.Subject)
	s.sessionManager.Put(r.Context(), "subject", ui.Subject)

	path := s.sessionManager.GetString(r.Context(), "origPath")
	if path == "" {
		path = "/"
	}

	http.Redirect(w, r, path, http.StatusFound)
}

func (s *Stepdance) certReqHandler(w http.ResponseWriter, r *http.Request) {
	s.sessionManager.Put(r.Context(), "origPath", "/certificate/request")

	// TOOD: validate session?
	// currently it will just fail if a bogus token is passed, better would be to return early

	accessToken := s.sessionManager.GetString(r.Context(), "token")
	if accessToken == "" {
		slog.Debug("certificate request attempted without token")
		s.templates.MissingCode.ExecuteTemplate(w, "base", nil)
		return
	}

	c, k := s.Step.MakeCertAndKey(accessToken)
	if c == nil || k == nil {
		http.Error(w, "Certificate or key generation failed", http.StatusBadRequest)
		return
	}

	s.sessionManager.Put(r.Context(), "c", c)
	s.sessionManager.Put(r.Context(), "k", k)

	w.Header().Add("Content-Type", "text/html")
	p := PageData{State: s.sessionManager.GetString(r.Context(), "state")}
	s.templates.CertificateRequest.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) downloadHandler(w http.ResponseWriter, r *http.Request) {
	s.sessionManager.Put(r.Context(), "origPath", "/certificate/download")

	if !s.checkState(w, r) {
		return
	}

	want := r.URL.Query().Get("data")
	var data []byte
	var ok bool
	if want == "certificate" {
		data, ok = s.sessionManager.Get(r.Context(), "c").([]byte)
		w.Header().Add("Content-Disposition", "attachment; filename=crt.pem")
	} else if want == "key" {
		data, ok = s.sessionManager.Get(r.Context(), "k").([]byte)
		w.Header().Add("Content-Disposition", "attachment; filename=key.pem")
	}

	if data == nil || !ok {
		http.Error(w, "No data", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	w.Write(data)
}
