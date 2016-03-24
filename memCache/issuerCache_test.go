package memCache

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/rolandshoemaker/stapled/common"
)

func TestIssuerCache(t *testing.T) {
	tester := func(ic *issuerCache, issuer *x509.Certificate) {
		if issuer := ic.getFromCertificate(issuer.RawSubject, issuer.SubjectKeyId); issuer == nil {
			t.Fatal("Failed to retrieve issuer from cache using subject + skid")
		}
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			issuerSubjectHash, spkiHash, err := common.HashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
			if err != nil {
				t.Fatalf("Failed to hash subject and subject public key info: %s", err)
			}
			if issuer := ic.getFromRequest(issuerSubjectHash, spkiHash); issuer == nil {
				t.Fatal("Failed to retrieve issuer from cache using subject hash + spki hash")
			}
		}
	}

	testIssuer, err := common.ReadCertificate("../testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read ../testdata/test-issuer.der: %s", err)
	}

	ic := newIssuerCache(nil)
	err = ic.add(testIssuer)
	if err != nil {
		t.Fatalf("Failed to add test issuer to cache: %s", err)
	}
	tester(ic, testIssuer)

	ic = newIssuerCache([]*x509.Certificate{testIssuer})
	tester(ic, testIssuer)
}
