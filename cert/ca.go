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

package cert

import (
	"database/sql"
	"log/slog"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/smallstep/certificates/ca"
)

type Step struct {
	client       *ca.Client
	db           *sql.DB
	Certificates atomic.Pointer[DbCertificateCache]
	provisioner  *ca.Provisioner
}

func (s *Step) Token(subject string) string {
	token, err := s.provisioner.Token(subject)
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		return ""
	}

	slog.Debug("have token", "token", token)
	return token
}

func NewStep(caurl string, hash string, dburl string, adminprov string, adminpass string) *Step {
	s := new(Step)

	slog.Debug("Initializing CA client ...")

	client, err := ca.NewClient(caurl, ca.WithRootSHA256(hash))
	if err != nil {
		slog.Error("Could not initiate CA client", "error", err)
		os.Exit(1)
	}

	health, err := client.Health()
	if err != nil {
		slog.Error("CA is not healthy", "error", err)
		os.Exit(1)
	}

	slog.Debug("Got CA health response", "status", health.Status)

	s.client = client

	if adminprov == "" {
		adminprov = "Admin JWK"
	}

	prov, err := ca.NewProvisioner(adminprov, "", caurl, []byte(adminpass), ca.WithRootSHA256(hash))
	if err != nil {
		slog.Error("Could not initiate CA admin provisioner", "error", err)
	}

	u, err := url.Parse(prov.GetCaURL())
	if err == nil {
		prov.SetAudience(u.ResolveReference(&url.URL{Path: "/1.0/revoke"}).String())
	} else {
		slog.Error("Could not parse CA URL", "error", err)
	}

	s.provisioner = prov

	if dburl != "" {
		s.db = NewDb(dburl)
	}

	return s
}
