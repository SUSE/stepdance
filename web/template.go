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

type Templates struct {
	BadState             *template.Template
	CertificateRequest   *template.Template
	CertificateRequestNA *template.Template
	Index                *template.Template
	Illegal              *template.Template
	InternalError        *template.Template
	MissingCode          *template.Template
	MissingParameter     *template.Template
	MissingToken         *template.Template
}

type PageData struct {
	Certificates cert.DbCertificates
	Subject      string
	State        string
	Error        template.HTML
}

func readTemplates() (*Templates, bool) {
	// TODO: find root automatically instead of assuming working directory
	tmpldir := "./web/templates/"
	if st != nil {
		tmpldir = "./templates/"
	}
	tmpls := new(Templates)

	tmpls.BadState = template.Must(template.ParseFiles(tmpldir+"bad_state.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.CertificateRequest = template.Must(template.ParseFiles(tmpldir+"certificate_request.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.CertificateRequestNA = template.Must(template.ParseFiles(tmpldir+"certificate_request_notallowed.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.Illegal = template.Must(template.ParseFiles(tmpldir+"illegal.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.Index = template.Must(template.ParseFiles(tmpldir+"index.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.InternalError = template.Must(template.ParseFiles(tmpldir+"internal_error.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingCode = template.Must(template.ParseFiles(tmpldir+"missing_code.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingParameter = template.Must(template.ParseFiles(tmpldir+"missing_parameter.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingToken = template.Must(template.ParseFiles(tmpldir+"missing_token.html", tmpldir+"top.html", tmpldir+"base.html"))

	return tmpls, true
}

func newErrorData(text string) *PageData {
	return &PageData{Error: template.HTML(text)}
}
