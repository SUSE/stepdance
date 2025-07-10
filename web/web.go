/*
   Stepdance - a client certificate management portal
   Copyright (C) 2025  SUSE LLC <georg.pfuetzenreuter@suse.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package web

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/SUSE/stepdance/cert"
)

func (s *Stepdance) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/login/init", s.loginHandler)
	mux.HandleFunc("/login/callback", s.callbackHandler)
	mux.HandleFunc("/certificate/download", s.downloadHandler)
	mux.HandleFunc("/certificate/request", s.certReqHandler)
	mux.HandleFunc("/certificate/revoke", s.certRevHandler)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(getWebDir("static")))))

	return mux
}

func (s *Stepdance) tokenValidator(w http.ResponseWriter, r *http.Request) (*oauth2.Token, bool) {
	var token *oauth2.Token
	if s.sessionManager.Exists(r.Context(), "token") {
		s.sessionManager.Put(r.Context(), "token_used", true)

		token = s.sessionManager.Get(r.Context(), "token").(*oauth2.Token)
		if !token.Valid() {
			slog.DebugContext(r.Context(), "Invalid token")
			s.errorHandler(w, r, SD_ERR_TOKEN, "")
			return nil, false
		}

		tokenSource := s.Oauth2Config.TokenSource(r.Context(), token)
		newToken, err := tokenSource.Token()
		if err != nil {
			slog.ErrorContext(r.Context(), "Failed to get new token", "error", err)
			return nil, false

		}
		if newToken.AccessToken != token.AccessToken {
			slog.DebugContext(r.Context(), "Writing new token")
			s.sessionManager.Put(r.Context(), "token", newToken)
			s.sessionManager.Put(r.Context(), "token_used", false)
			token = newToken
		}

	} else {
		slog.DebugContext(r.Context(), "Missing token")
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
	slog.DebugContext(r.Context(), "setting origPath", "path", path)
	s.sessionManager.Put(r.Context(), "origPath", path)
}

func (s *Stepdance) getOrigPath(r *http.Request) string {
	path := s.sessionManager.GetString(r.Context(), "origPath")
	if path == "" {
		path = "/"
	}

	return path
}

func (s *Stepdance) getSessionId(r *http.Request) string {
	return s.sessionManager.GetString(r.Context(), "id")
}

func (s *Stepdance) initHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		had_session_id := true

		session_id := s.getSessionId(r)
		if session_id == "" {
			had_session_id = false

			var err error
			session_id, err = randString(12, false)
			if err != nil {
				slog.ErrorContext(r.Context(), "session id generation failed", "error", err)
				s.errorHandler(w, r, SD_ERR_MISC, "")
				return
			}

			// for display on error pages
			s.sessionManager.Put(r.Context(), "id", session_id)
		}

		// for logging
		r = r.WithContext(context.WithValue(r.Context(), "session_id", session_id))

		if !had_session_id {
			slog.DebugContext(r.Context(), "Initialized session")
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Stepdance) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Add("Content-Type", "text/html")

	subject := s.sessionManager.GetString(r.Context(), "subject")
	p := PageData{Subject: subject, SessionId: s.getSessionId(r)}
	certCache := s.Step.Certificates.Load()
	if subject != "" && certCache != nil && s.checkSession(w, r) {
		p.Certificates = s.Step.Certificates.Load().Certificates.Filter(subject, "", 0)
	}
	s.templates.Index.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) getSubject(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := s.sessionManager.Get(r.Context(), "token").(*oauth2.Token)
	if token == nil {
		slog.ErrorContext(r.Context(), "Subject query attempted without token")
		s.errorHandler(w, r, SD_ERR_MISC, "Subject query failed (no token).")
	}

	ui, err := s.OidcProvider.UserInfo(s.Ctx, s.Oauth2Config.TokenSource(s.Ctx, token))
	if err != nil || ui.Subject == "" {
		slog.ErrorContext(r.Context(), "Failed to query userinfo for subject", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "Subject query failed (failed to query user info).")
		return "", false
	}

	return ui.Subject, true
}

func (s *Stepdance) checkSession(w http.ResponseWriter, r *http.Request) bool {
	subject_session := s.sessionManager.GetString(r.Context(), "subject")

	if subject_session == "" || s.sessionManager.GetString(r.Context(), "state") == "" || s.sessionManager.GetString(r.Context(), "nonce") == "" {
		slog.DebugContext(r.Context(), "Privileged action attempted without login")
		s.errorHandler(w, r, SD_ERR_STATE, "")
		return false
	}

	subject_userinfo, ok := s.getSubject(w, r)
	if !ok {
		return false
	}

	if subject_session != subject_userinfo {
		slog.WarnContext(r.Context(), "Privileged action attempted with mismatching subject", "subject_session", subject_session, "subject_userinfo", subject_userinfo)
		s.errorHandler(w, r, SD_ERR_ILLEG, "")
		return false
	}

	return true
}

func (s *Stepdance) checkState(w http.ResponseWriter, r *http.Request) bool {
	if s.sessionManager.GetString(r.Context(), "state") != r.URL.Query().Get("state") {
		s.errorHandler(w, r, SD_ERR_STATE, "")
		return false
	}

	return true
}

func (s *Stepdance) loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16, true)
	if err != nil {
		slog.ErrorContext(r.Context(), "randString() failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "")
		return
	}
	nonce, err := randString(16, true)
	if err != nil {
		slog.ErrorContext(r.Context(), "randString() failed", "error", err)
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
		slog.ErrorContext(r.Context(), "Token exchange failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "Token exchange failed.")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		slog.ErrorContext(r.Context(), "No id_token field in oauth2 token")
		s.errorHandler(w, r, SD_ERR_MISC, "Missing id_token field.")
		return
	}

	idToken, err := s.Verifier.Verify(s.Ctx, rawIDToken)
	if err != nil {
		slog.ErrorContext(r.Context(), "ID token verification failed", "error", err)
		s.errorHandler(w, r, SD_ERR_MISC, "ID token verification failed.")
		return
	}

	nonce := s.sessionManager.GetString(r.Context(), "nonce")
	if idToken.Nonce != nonce {
		slog.ErrorContext(r.Context(), "Nonce does not match")
		s.errorHandler(w, r, SD_ERR_MISC, "Nonce verification failed.")
		return
	}

	err = s.sessionManager.RenewToken(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to renew session token", "error", err)
		if err := s.sessionManager.Destroy(r.Context()); err != nil {
			slog.ErrorContext(r.Context(), "Failed to destroy session", "error", err)
		}
		s.errorHandler(w, r, SD_ERR_MISC, "Session renewal failed.")
		return
	}

	s.sessionManager.Put(r.Context(), "token", oauth2Token)
	s.sessionManager.Put(r.Context(), "token_used", false)
	subject, ok := s.getSubject(w, r)
	if !ok {
		return
	}

	slog.InfoContext(r.Context(), "Authenticated user", "subject", subject)
	s.sessionManager.Put(r.Context(), "subject", subject)

	if !s.checkSession(w, r) {
		return
	}

	http.Redirect(w, r, s.getOrigPath(r), http.StatusFound)
}

func (s *Stepdance) certReqHandler(w http.ResponseWriter, r *http.Request) {
	s.setOrigPath(r)

	if !s.checkSession(w, r) {
		return
	}

	slog.DebugContext(r.Context(), "req session", "status", s.sessionManager.Status(r.Context()), "token", s.sessionManager.Token(r.Context()))

	if s.sessionManager.GetBool(r.Context(), "token_used") {
		slog.DebugContext(r.Context(), "token already used")
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
			`, s.getSessionId(r)),
		)
		return
	}

	c, k := s.Step.MakeCertAndKey(token.AccessToken)
	if c == nil || k == nil {
		slog.ErrorContext(r.Context(), "Generated certificate or key is empty")
		s.errorHandler(w, r, SD_ERR_MISC, "Certificate/key generation failed.")
		return
	}

	s.sessionManager.Put(r.Context(), "c", c)
	s.sessionManager.Put(r.Context(), "k", k)

	w.Header().Add("Content-Type", "text/html")
	p := PageData{State: s.sessionManager.GetString(r.Context(), "state"), SessionId: s.getSessionId(r)}
	s.templates.CertificateRequest.ExecuteTemplate(w, "base", p)
}

func (s *Stepdance) certRevHandler(w http.ResponseWriter, r *http.Request) {
	s.setOrigPath(r)

	if !s.checkSession(w, r) {
		return
	}

	slog.DebugContext(r.Context(), "rev session", "status", s.sessionManager.Status(r.Context()), "token", s.sessionManager.Token(r.Context()))

	token, tok := s.tokenValidator(w, r)
	if !tok {
		return
	}

	serial := r.URL.Query().Get("serial")

	if serial == "" {
		slog.DebugContext(r.Context(), "Certificate revocation attempted without serial")
		s.errorHandler(w, r, SD_ERR_PARAM, "")
		return
	}

	subject := s.sessionManager.GetString(r.Context(), "subject")
	if subject == "" {
		slog.ErrorContext(r.Context(), "Certificate revocation attempted without subject")
		s.errorHandler(w, r, SD_ERR_MISC, "Missing subject.")
		return
	}

	certCache := s.Step.Certificates.Load()
	if certCache == nil {
		slog.ErrorContext(r.Context(), "Certificate revocation attempted with empty cache")
		s.errorHandler(w, r, SD_ERR_MISC, "Cache not yet populated.")
		return
	}

	certificates := certCache.Certificates.Filter("", serial, 1)
	found := false
	for _, c := range certificates {
		if c.CN != subject {
			slog.WarnContext(r.Context(), "Certificate revocation attempted for certificate not matching subject", "subject", subject, "cn", c.CN, "serial", serial)
			s.errorHandler(w, r, SD_ERR_ILLEG, "")
			return
		}

		found = true
	}

	if !found {
		slog.WarnContext(r.Context(), "Certificate revocation attempted for nonexistent certificate", "subject", subject, "serial", serial)
		s.errorHandler(w, r, SD_ERR_ILLEG, "")
		return
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

	if !s.checkSession(w, r) {
		return
	}

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
		slog.ErrorContext(r.Context(), "Incomplete data to offer for download")
		s.errorHandler(w, r, SD_ERR_MISC, "No download data.")
		return
	}

	w.Header().Add("Content-Type", "text/plain")
	w.Write(data)
}
