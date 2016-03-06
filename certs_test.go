package main

import (
	"bytes"
	"crypto"
	"testing"
)

func TestReadCertificate(t *testing.T) {
	_, err := ReadCertificate("testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read DER certificate: %s", err)
	}
	_, err = ReadCertificate("testdata/test-issuer.pem")
	if err != nil {
		t.Fatalf("Failed to read PEM certificate: %s", err)
	}
}

func TestHashNameAndPKI(t *testing.T) {
	issuer, err := ReadCertificate("testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read test issuer: %s", err)
	}
	nameHash, pkiHash, err := hashNameAndPKI(crypto.SHA1.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("Failed to hash subject and public key info: %s", err)
	}
	expectedNameHash := []byte{188, 87, 114, 226, 121, 124, 86, 227, 153, 148, 89, 141, 117, 164, 163, 210, 76, 76, 133, 197}
	expectedPKIHash := []byte{168, 74, 106, 99, 4, 125, 221, 186, 230, 209, 57, 183, 166, 69, 101, 239, 243, 168, 236, 161}
	if bytes.Compare(expectedNameHash, nameHash) != 0 {
		t.Fatalf("Didn't get expected subject hash: wanted %X, got %X", expectedNameHash, nameHash)
	}
	if bytes.Compare(expectedPKIHash, pkiHash) != 0 {
		t.Fatalf("Didn't get expected pki hash: wanted %X, got %X", expectedPKIHash, pkiHash)
	}
}
