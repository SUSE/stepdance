package main

import (
	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/smallstep/certificates/ca"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"time"
)

var sessionManager *scs.SessionManager

type Stepdance struct {
	oauth2Config oauth2.Config
	oidcConfig   *oidc.Config
	ctx          context.Context
	step         *ca.Client
	verifier     *oidc.IDTokenVerifier
}

func initStepdance(s *Stepdance, bind string) {
	sessionManager = scs.New()
	sessionManager.Lifetime = 60 * time.Second
	sessionManager.Cookie.Secure = true
	sessionManager.Cookie.HttpOnly = true
	//sessionManager.Cookie.SameSite = http.SameSiteStrictMode

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/callback", s.callbackHandler)
	mux.HandleFunc("/download", s.downloadHandler)

	slog.Info("Starting to listen ...", "bind", bind)
	panic(http.ListenAndServe(bind, sessionManager.LoadAndSave(mux)))
}

func (s *Stepdance) indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.Write([]byte(`
		<html><body><a href="/login">Login</a></body></html>
	`))
}

func checkState(r *http.Request) bool {
	if sessionManager.GetString(r.Context(), "state") != r.URL.Query().Get("state") {
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

	sessionManager.Put(r.Context(), "state", state)
	sessionManager.Put(r.Context(), "nonce", nonce)

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (s *Stepdance) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if !checkState(r) {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oauth2Config.Exchange(s.ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := s.verifier.Verify(s.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce := sessionManager.GetString(r.Context(), "nonce")
	if idToken.Nonce != nonce {
		http.Error(w, "Nonce does not match", http.StatusBadRequest)
		return
	}

	c, k := s.makeCertAndKey(oauth2Token.AccessToken)
	if c == nil || k == nil {
		http.Error(w, "Certificate or key generation failed", http.StatusBadRequest)
		return
	}

	sessionManager.Put(r.Context(), "c", c)
	sessionManager.Put(r.Context(), "k", k)

	w.Header().Add("Content-Type", "text/html")
	state := sessionManager.GetString(r.Context(), "state")
	w.Write([]byte(`
		<html>
		<body>
		<a href="/download?state=` + state + `&data=certificate">Download certificate</a>
		<br>
		<a href="/download?state=` + state + `&data=key">Download private key</a>
		</body>
		</html>
	`))
}

func (s *Stepdance) downloadHandler(w http.ResponseWriter, r *http.Request) {
	if !checkState(r) {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	want := r.URL.Query().Get("data")
	var data []byte
	var ok bool
	if want == "certificate" {
		data, ok = sessionManager.Get(r.Context(), "c").([]byte)
		w.Header().Add("Content-Disposition", "attachment; filename=crt.pem")
	} else if want == "key" {
		data, ok = sessionManager.Get(r.Context(), "k").([]byte)
		w.Header().Add("Content-Disposition", "attachment; filename=key.pem")
	}

	if data == nil || !ok {
		http.Error(w, "No data", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	w.Write(data)
}
