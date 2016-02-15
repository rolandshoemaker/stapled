package stapled

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificate parses a certificate from either it's PEM
// or DER form
func ParseCertificate(contents []byte) (*x509.Certificate, error) {
	certBytes := []byte{}
	block, _ := pem.Decode(contents)
	if block == nil {
		certBytes = contents
	} else {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Invalid PEM type '%s'", block.Type)
		}
		certBytes = block.Bytes
	}
	return x509.ParseCertificate(certBytes)
}
