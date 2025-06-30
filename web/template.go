package web

import (
	"html/template"

	"github.com/SUSE/stepdance/cert"
)

type Templates struct {
	BadState           *template.Template
	CertificateRequest *template.Template
	Index              *template.Template
	InternalError      *template.Template
	MissingCode        *template.Template
	MissingParameter   *template.Template
	MissingToken       *template.Template
}

type PageData struct {
	Certificates cert.DbCertificates
	Subject      string
	State        string
	Error        string
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
	tmpls.Index = template.Must(template.ParseFiles(tmpldir+"index.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.InternalError = template.Must(template.ParseFiles(tmpldir+"internal_error.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingCode = template.Must(template.ParseFiles(tmpldir+"missing_code.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingParameter = template.Must(template.ParseFiles(tmpldir+"missing_parameter.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingToken = template.Must(template.ParseFiles(tmpldir+"missing_token.html", tmpldir+"top.html", tmpldir+"base.html"))

	return tmpls, true
}
