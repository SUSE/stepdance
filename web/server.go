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
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/SUSE/stepdance/cert"
	"github.com/SUSE/stepdance/core"
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

func NewStepdance(c core.Config) (*Stepdance, string) {
	s := new(Stepdance)
	s.Ctx = context.Background()

	s.Step = cert.NewStep(c.CaUrl, c.CaHash, c.CaDbUrl, c.CaAdminProv, c.CaPass)

	slog.Debug("Initializing OIDC provider ...")

	provider, err := oidc.NewProvider(s.Ctx, c.OidcBaseUrl)
	if err != nil {
		panic(err)
	}

	s.OidcConfig = &oidc.Config{
		ClientID: c.ClientId,
	}

	s.OidcProvider = provider

	s.Verifier = provider.Verifier(s.OidcConfig)

	// todo: IPv6 wrap
	bind := fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort)

	slog.Debug("Initializing Oauth2 ...")

	abu := c.AppBaseUrl
	if abu == "" {
		abu = "http://" + bind
	}

	s.Oauth2Config = oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  abu + "/login/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return s, bind
}

func InitStepdance(s *Stepdance, bind string) *http.Server {
	s.sessionManager = newSessionManager()

	mux := s.newMux()

	s.templates = readTemplates()

	gob.Register(&oauth2.Token{})

	srv := &http.Server{
		Addr:    bind,
		Handler: s.sessionManager.LoadAndSave(s.initHandler(mux)),
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
