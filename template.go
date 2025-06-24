package main

import (
	"html/template"
	"log/slog"
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
	tmpldir := "./templates/"
	tmpls := new(Templates)

	// pretty sure there's a better way to do all these

	t, err := template.ParseFiles(tmpldir + "index.html")
	if err != nil {
		slog.Error("Template parsing failed", "template", "index.html", "error", err)
		return nil, false
	}
	tmpls.Index = t

	t, err = template.ParseFiles(tmpldir + "state_mismatch.html")
	if err != nil {
		slog.Error("Template parsing failed", "template", "state_mismatch.html", "error", err)
		return nil, false
	}
	tmpls.StateMismatch = t

	t, err = template.ParseFiles(tmpldir + "missing_code.html")
	if err != nil {
		slog.Error("Template parsing failed", "template", "missing_code.html", "error", err)
		return nil, false
	}
	tmpls.MissingCode = t

	t, err = template.ParseFiles(tmpldir + "certificate_request.html")
	if err != nil {
		slog.Error("Template parsing failed", "template", "certificate_request.html", "error", err)
		return nil, false
	}
	tmpls.CertificateRequest = t

	return tmpls, true
}
