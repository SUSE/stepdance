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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"strings"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
)

const timeFormat = time.RFC3339

type DbCertificate struct {
	Raw     x509.Certificate
	CN      string
	Serial  string
	SerialH string  // human friendly representation
	Revoked bool
	// store converted timestamps already as these fields are only used for display in HTML
	NotBefore string
	NotAfter  string
}

type DbCertificates []*DbCertificate

type DbCertificateCache struct {
	Certificates DbCertificates
	lastUpdate   time.Time
}

func (d *DbCertificates) Filter(cn string, serial string, limit int) DbCertificates {
	out := DbCertificates{}

	found := 0
	for _, c := range *d {
		if (cn != "" && c.CN == cn) || (serial != "" && c.Serial == serial) {
			out = append(out, c)

			found = found + 1
			if limit > 0 && found == limit {
				break
			}
		}
	}

	return out
}

func (s *Step) GetCertificates() DbCertificates {
	rows, err := s.db.Query(`
		SELECT
			convert_from(x.nkey, 'utf-8'),
			convert_from(rx.nkey, 'utf-8') IS NOT NULL,
			x.nvalue
			FROM x509_certs AS x
			LEFT JOIN revoked_x509_certs AS rx
			ON x.nkey = rx.nkey
	`)
	if err != nil {
		slog.Error("Database query failed", "error", err)
		return nil
	}
	defer rows.Close()

	out := DbCertificates{}

	for rows.Next() {
		var (
			serial  string
			revoked bool
			rawCrt  []byte
		)

		if err := rows.Scan(&serial, &revoked, &rawCrt); err != nil {
			slog.Error("scan failed", "error", err)
			return nil
		}

		crt, cerr := x509.ParseCertificate(rawCrt)
		if cerr != nil {
			slog.Error("certificate parsing failed", "error", err)
		}

		if serial != crt.SerialNumber.String() {
			slog.Error("corrupted certificate (serial mismatch) in database, skipping", "error", err)
			continue
		}

		c := DbCertificate{
			Raw:       *crt,
			CN:        crt.Subject.CommonName,
			Serial:    crt.SerialNumber.String(),
			SerialH:   strings.ToUpper(crt.SerialNumber.Text(16)),
			Revoked:   revoked,
			NotBefore: crt.NotBefore.Format(timeFormat),
			NotAfter:  crt.NotAfter.Format(timeFormat),
		}

		out = append(out, &c)
	}

	return out
}

func (s *Step) RefreshCertificates() {
	oldData := s.Certificates.Load()

	if oldData != nil && time.Now().Before(oldData.lastUpdate) {
		slog.Warn("certificates update already happened in the future")
		return
	}

	newData := new(DbCertificateCache)

	newData.Certificates = s.GetCertificates()
	if newData.Certificates == nil {
		slog.Debug("nil certificates, not updating cache")
		return
	}

	newData.lastUpdate = time.Now()

	s.Certificates.Store(newData)
}

func (s *Step) MakeCertAndKey(token string) ([]byte, []byte) {
	req, key, err := ca.CreateSignRequest(token)
	if err != nil {
		slog.Error("failed to create signrequest", "error", err)
		return nil, nil
	}

	signresp, err := s.client.Sign(req)
	if err != nil {
		slog.Error("failed to sign certificate", "error", err)
		return nil, nil
	}

	cert, err := ca.TLSCertificate(signresp, key)
	if err != nil {
		slog.Error("failed to generate certificate", "error", err)
		return nil, nil
	}

	intKey, _ := key.(*ecdsa.PrivateKey)
	rawKey, err := x509.MarshalECPrivateKey(intKey)
	if err != nil {
		slog.Error("failed to marshal private key", "error", err)
		return nil, nil
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: rawKey,
	}
	pemKey := pem.EncodeToMemory(block)

	s.RefreshCertificates()

	return cert.Certificate[0], pemKey
}

func (s *Step) RevokeCert(serial string, ott string) bool {
	request := &api.RevokeRequest{
		Serial:     serial,
		OTT:        s.Token(serial),
		ReasonCode: 1,
		Passive:    true, // TODO
	}

	err := request.Validate()
	if err != nil {
		slog.Error("certificate revocation request construction failed", "error", err)
		return false
	}

	result, err := s.client.Revoke(request, nil)
	if err != nil {
		slog.Error("certificate revocation failed", "error", err)
		return false
	}

	certs := s.Certificates.Load().Certificates.Filter("", serial, 0)
	for i, _ := range certs {
		certs[i].Revoked = true
	}

	slog.Info("certificate revoked", "status", result)

	return true
}
