package web

import (
	"encoding/gob"
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

// these two should be in web_test.go, but "st" is currently used to change things needed for testing
type steptest struct {
	s       *Stepdance
	srv     *http.Server
	oidcsrv *http.Server
	c       *http.Client
}

var st *steptest

const (
	SD_ERR_MISC  = 0 // internal issue
	SD_ERR_CODE  = 1 // no or unexpected code value in session
	SD_ERR_STATE = 2 // no or unexpected state value in session
	SD_ERR_TOKEN = 3 // no or unexpected token value in session
	SD_ERR_PARAM = 4 // missing query parameters
	SD_ERR_ILLEG = 5 // operation on data not owned by requestor
)

func InitStepdance(s *Stepdance, bind string) *http.Server {
	s.sessionManager = newSessionManager()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.IndexHandler)
	mux.HandleFunc("/login/init", s.loginHandler)
	mux.HandleFunc("/login/callback", s.callbackHandler)
	mux.HandleFunc("/certificate/download", s.downloadHandler)
	mux.HandleFunc("/certificate/request", s.certReqHandler)
	mux.HandleFunc("/certificate/revoke", s.certRevHandler)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static"))))

	var tok bool
	s.templates, tok = readTemplates()
	if !tok {
		return nil
	}

	gob.Register(&oauth2.Token{})

	srv := &http.Server{
		Addr:    bind,
		Handler: s.sessionManager.LoadAndSave(mux),
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	slog.Info("Listening ...", "bind", bind)

	return srv
}

func (s *Stepdance) errorHandler(w http.ResponseWriter, r *http.Request, sdErr int, text string) {
	p := new(PageData)
	if text != "" {
		p = newErrorData(text)
	}

	switch sdErr {
	case SD_ERR_MISC:
		w.WriteHeader(http.StatusInternalServerError)
		s.templates.InternalError.ExecuteTemplate(w, "base", p)
	case SD_ERR_CODE:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingCode.ExecuteTemplate(w, "base", p)
	case SD_ERR_PARAM:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingParameter.ExecuteTemplate(w, "base", p)
	case SD_ERR_STATE:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.BadState.ExecuteTemplate(w, "base", p)
	case SD_ERR_TOKEN:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingToken.ExecuteTemplate(w, "base", p)
	case SD_ERR_ILLEG:
		w.WriteHeader(http.StatusForbidden)
		s.templates.Illegal.ExecuteTemplate(w, "base", p)
	}
}

func (s *Stepdance) tokenValidator(w http.ResponseWriter, r *http.Request) (*oauth2.Token, bool) {
	var token *oauth2.Token
	if s.sessionManager.Exists(r.Context(), "token") {
		s.sessionManager.Put(r.Context(), "token_used", true)

		token = s.sessionManager.Get(r.Context(), "token").(*oauth2.Token)
		if !token.Valid() {
			slog.Debug("Invalid token")
			s.errorHandler(w, r, SD_ERR_TOKEN, "")
			return nil, false
		}

		tokenSource := s.Oauth2Config.TokenSource(r.Context(), token)
		newToken, err := tokenSource.Token()
		if err != nil {
			slog.Error("Failed to get new token", "error", err)
			return nil, false

		}
		if newToken.AccessToken != token.AccessToken {
			slog.Debug("Writing new token")
			s.sessionManager.Put(r.Context(), "token", newToken)
			s.sessionManager.Put(r.Context(), "token_used", false)
			token = newToken
		}

	} else {
		slog.Debug("Missing token")
		s.errorHandler(w, r, SD_ERR_TOKEN, "")
		return nil, false
	}

	return token, true
}

func (s *Stepdance) setOrigPath(r *http.Request) {
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}
	slog.Debug("setting origPath", "path", path)
	s.sessionManager.Put(r.Context(), "origPath", path)
}

func (s *Stepdance) getOrigPath(r *http.Request) string {
	path := s.sessionManager.GetString(r.Context(), "origPath")
	if path == "" {
		path = "/"
	}

	return path
}

func (s *Stepdance) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Add("Content-Type", "text/html")

	subject := s.sessionManager.GetString(r.Context(), "subject")
	p := PageData{Subject: subject}
	certCache := s.Step.Certificates.Load()
	if subject != "" && certCache != nil {
		p.Certificates = s.Step.Certificates.Load().Certificates.Filter(subject, "", 0)
	}
	s.templates.Index.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) checkState(w http.ResponseWriter, r *http.Request) bool {
	if s.sessionManager.GetString(r.Context(), "state") != r.URL.Query().Get("state") {
		s.errorHandler(w, r, SD_ERR_STATE, "")
		return false
	}

	return true
}

func (s *Stepdance) loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		slog.Error("randString() failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "")
		return
	}
	nonce, err := randString(16)
	if err != nil {
		slog.Error("randString() failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "")
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
		s.errorHandler(w, r, SD_ERR_CODE, "")
		return
	}

	oauth2Token, err := s.Oauth2Config.Exchange(s.Ctx, code)
	if err != nil {
		slog.Error("Token exchange failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "Token exchange failed.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		slog.Error("No id_token field in oauth2 token")
		s.errorHandler(w, r, SD_ERR_MISC, "Missing id_token field.")
		return
	}

	idToken, err := s.Verifier.Verify(s.Ctx, rawIDToken)
	if err != nil {
		slog.Error("ID token verification failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "ID token verification failed.")
		return
	}

	nonce := s.sessionManager.GetString(r.Context(), "nonce")
	if idToken.Nonce != nonce {
		slog.Error("Nonce does not match")
		s.errorHandler(w, r, SD_ERR_MISC, "Nonce verification failed.")
		return
	}

	err = s.sessionManager.RenewToken(r.Context())
	if err != nil {
		slog.Error("Failed to renew session token", "error", err)
		if err := s.sessionManager.Destroy(r.Context()); err != nil {
			slog.Error("Failed to destroy session", "error", err)
		}
		s.errorHandler(w, r, SD_ERR_MISC, "Session renewal failed.")
		return
	}

	s.sessionManager.Put(r.Context(), "token", oauth2Token)
	s.sessionManager.Put(r.Context(), "token_used", false)
	ui, err := s.OidcProvider.UserInfo(s.Ctx, s.Oauth2Config.TokenSource(s.Ctx, oauth2Token))
	if err != nil || ui.Subject == "" {
		slog.Error("Failed to query userinfo for subject", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "Subject query failed.")
		return
	}

	slog.Info("Authenticated user", "subject", ui.Subject)
	s.sessionManager.Put(r.Context(), "subject", ui.Subject)

	http.Redirect(w, r, s.getOrigPath(r), http.StatusFound)
}

func (s *Stepdance) certReqHandler(w http.ResponseWriter, r *http.Request) {
	s.setOrigPath(r)

	// TOOD: validate session?
	// currently it will just fail if a bogus token is passed, better would be to return early

	slog.Debug("req session", "status", s.sessionManager.Status(r.Context()), "token", s.sessionManager.Token(r.Context()))

	if s.sessionManager.GetBool(r.Context(), "token_used") {
		slog.Debug("token already used")
		http.Redirect(w, r, "/login/init", http.StatusFound)
		return
	}

	token, tok := s.tokenValidator(w, r)
	if !tok {
		return
	}

	subject := s.sessionManager.GetString(r.Context(), "subject")
	certCache := s.Step.Certificates.Load()
	var certificates cert.DbCertificates
	if subject != "" && certCache != nil {
		certificates = s.Step.Certificates.Load().Certificates.Filter(subject, "", 0)
	}

	ok := true
	for _, c := range certificates {
		if !c.Revoked {
			ok = false
			break
		}
	}

	if !ok {
		s.templates.CertificateRequestNA.ExecuteTemplate(w, "base",
			newErrorData(`
			You are only allowed to have one active certificate at a time.
			<br>
			Please revoke all valid certificates before requesting a new one.
			`),
		)
		return
	}

	c, k := s.Step.MakeCertAndKey(token.AccessToken)
	if c == nil || k == nil {
		slog.Error("Generated certificate or key is empty")
		s.errorHandler(w, r, SD_ERR_MISC, "Certificate/key generation failed.")
		return
	}

	s.sessionManager.Put(r.Context(), "c", c)
	s.sessionManager.Put(r.Context(), "k", k)

	w.Header().Add("Content-Type", "text/html")
	p := PageData{State: s.sessionManager.GetString(r.Context(), "state")}
	s.templates.CertificateRequest.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) certRevHandler(w http.ResponseWriter, r *http.Request) {
	s.setOrigPath(r)

	// TODO: better session validation?

	slog.Debug("rev session", "status", s.sessionManager.Status(r.Context()), "token", s.sessionManager.Token(r.Context()))

	token, tok := s.tokenValidator(w, r)
	if !tok {
		return
	}

	serial := r.URL.Query().Get("serial")

	if serial == "" {
		slog.Debug("Certificate revocation attempted without serial")
		s.errorHandler(w, r, SD_ERR_PARAM, "")
		return
	}

	subject := s.sessionManager.GetString(r.Context(), "subject")
	if subject == "" {
		slog.Error("Certificate revocation attempted without subject")
		s.errorHandler(w, r, SD_ERR_MISC, "Missing subject.")
		return
	}

	certCache := s.Step.Certificates.Load()
	if certCache == nil {
		slog.Error("Certificate revocation attempted with empty cache")
		s.errorHandler(w, r, SD_ERR_MISC, "Cache not yet populated.")
		return
	}

	certificates := certCache.Certificates.Filter("", serial, 1)
	for _, c := range certificates {
		if c.CN != subject {
			slog.Warn("Certificate revocation attempted for certificate not matching subject", "subject", subject, "cn", c.CN)
			s.errorHandler(w, r, SD_ERR_ILLEG, "")
			return
		}
	}

	ok := s.Step.RevokeCert(serial, token.AccessToken)

	if !ok {
		s.errorHandler(w, r, SD_ERR_MISC, "Revocation failed.")
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Stepdance) downloadHandler(w http.ResponseWriter, r *http.Request) {
	s.setOrigPath(r)

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
		slog.Error("Incomplete data to offer for download")
		s.errorHandler(w, r, SD_ERR_MISC, "No download data.")
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	w.Write(data)
}
