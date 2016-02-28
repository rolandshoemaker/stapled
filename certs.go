package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
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

func ReadCertificate(filename string) (*x509.Certificate, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(contents)
}

func HashNameAndPKI(h hash.Hash, name, pki []byte) ([]byte, []byte, error) {
	h.Write(name)
	nameHash := h.Sum(nil)
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pki, &publicKeyInfo); err != nil {
		return nil, nil, err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	pkiHash := h.Sum(nil)
	return nameHash[:], pkiHash[:], nil
}
