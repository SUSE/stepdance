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
	"html/template"

	"github.com/SUSE/stepdance/cert"
)

type PageData struct {
	Certificates cert.DbCertificates
	Subject      string
	State        string
	Error        template.HTML
	SessionId    string
}

func newErrorData(text string, id string) *PageData {
	p := PageData{}

	if text != "" {
		p.Error = template.HTML(text)
	}

	if id != "" {
		p.SessionId = id
	}

	return &p
}

//go:generate ./mktemplatesgo.sh
