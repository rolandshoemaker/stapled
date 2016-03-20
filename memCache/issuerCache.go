package memCache

import (
	"crypto/sha256"
	"crypto/x509"
	"sync"
)

type issuerCache struct {
	hashed map[[32]byte]*x509.Certificate
	mu     sync.RWMutex
}

func newIssuerCache(issuers []*x509.Certificate) *issuerCache {
	ic := &issuerCache{hashed: make(map[[32]byte]*x509.Certificate)}
	for _, issuer := range issuers {
		ic.add(issuer)
	}
	return ic
}

func (ic *issuerCache) get(issuerSubject, akid []byte) *x509.Certificate {
	hashed := sha256.Sum256(append(issuerSubject, akid...))
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.hashed[hashed]
}

func (ic *issuerCache) add(issuer *x509.Certificate) error {
	// work around for a bug of sorts in encoding/asn1
	// https://github.com/golang/go/issues/14882
	subj := make([]byte, len(issuer.RawSubject))
	copy(subj, issuer.RawSubject)
	hashed := sha256.Sum256(append(subj, issuer.SubjectKeyId...))
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.hashed[hashed] = issuer
	return nil
}
