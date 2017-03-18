package common

import (
	"bytes"
	"crypto"
	"net/url"
	"testing"
	"time"
)

func TestReadCertificate(t *testing.T) {
	_, err := ReadCertificate("../testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read DER certificate: %s", err)
	}
	_, err = ReadCertificate("../testdata/test-issuer.pem")
	if err != nil {
		t.Fatalf("Failed to read PEM certificate: %s", err)
	}
}

func TestHashNameAndPKI(t *testing.T) {
	issuer, err := ReadCertificate("../testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read test issuer: %s", err)
	}
	nameHash, pkiHash, err := HashNameAndPKI(crypto.SHA1.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
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

func TestHumanDuration(t *testing.T) {
	for _, tc := range []struct {
		duration time.Duration
		expected string
	}{
		{0, "instantly"},
		{time.Second, "1 second"},
		{2 * time.Second, "2 seconds"},
		{time.Minute, "1 minute"},
		{2 * time.Minute, "2 minutes"},
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{2 * time.Minute, "2 minutes"},
		{24 * time.Hour, "1 day"},
		{48 * time.Hour, "2 days"},
		{(48 * time.Hour) + (2 * time.Hour) + (2 * time.Minute) + (2 * time.Second), "2 days 2 hours 2 minutes 2 seconds"},
	} {
		humanized := HumanDuration(tc.duration)
		if humanized != tc.expected {
			t.Fatalf("Got unexpected results: expected %q, got %q", tc.expected, humanized)
		}
	}
}

func TestRandomURL(t *testing.T) {
	urlA, _ := url.Parse("http://a")
	urlB, _ := url.Parse("http://b")
	list := []*url.URL{urlA, urlB}
	random := randomURL(list)
	if !(random.String() == "http://a" || random.String() == "http://b") {
		t.Fatalf("randomURL returned URL not in provided list: %s", random.String())
	}
}

func TestProxyFuncy(t *testing.T) {
	pf, err := ProxyFunc([]string{"http://a", "http://b"})
	if err != nil {
		t.Fatalf("Failed to create the proxy choosing function: %s", err)
	}
	random, err := pf(nil)
	if err != nil {
		t.Fatalf("Function returned from ProxyFunc returned an error: %s", err)
	}
	if !(random.String() == "http://a" || random.String() == "http://b") {
		t.Fatalf("Function returned from ProxyFunc returned URL not in provided list: %s", random.String())
	}
}
