package web

import (
	"html/template"
)

type Templates struct {
	Index              *template.Template
	StateMismatch      *template.Template
	MissingCode        *template.Template
	CertificateRequest *template.Template
}

type PageData struct {
	Subject string
	State   string
}

func readTemplates() (*Templates, bool) {
	tmpldir := "./web/templates/"
	tmpls := new(Templates)

	tmpls.Index = template.Must(template.ParseFiles(tmpldir+"index.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.StateMismatch = template.Must(template.ParseFiles(tmpldir+"state_mismatch.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.MissingCode = template.Must(template.ParseFiles(tmpldir+"missing_code.html", tmpldir+"top.html", tmpldir+"base.html"))
	tmpls.CertificateRequest = template.Must(template.ParseFiles(tmpldir+"certificate_request.html", tmpldir+"top.html", tmpldir+"base.html"))

	return tmpls, true
}
