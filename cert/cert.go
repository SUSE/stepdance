package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/smallstep/certificates/ca"
	"log/slog"
	"time"
)

type DbCertificate struct {
	CN      string
	Serial  string // some sort of integer might make more sense but the default big.Int was difficult to read
	Revoked bool
}

type DbCertificates []*DbCertificate

type DbCertificateCache struct {
	Certificates DbCertificates
	lastUpdate   time.Time
}

func (d *DbCertificates) Filter(cn string, limit int) DbCertificates {
	out := DbCertificates{}

	for i, c := range *d {
		if limit > 0 && i > limit {
			break
		}

		if c.CN == cn {
			out = append(out, c)
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
			CN:      crt.Subject.CommonName,
			Serial:  crt.SerialNumber.String(),
			Revoked: revoked,
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

	return cert.Certificate[0], pemKey
}
