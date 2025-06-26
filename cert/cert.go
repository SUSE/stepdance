package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/smallstep/certificates/ca"
	"log/slog"
)

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
