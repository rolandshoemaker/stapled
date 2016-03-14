package memCache

import (
	"crypto/sha256"
	"crypto/x509"
	"sync"

	"github.com/rolandshoemaker/stapled/common"
)

type issuerCache struct {
	hashed map[[32]byte]*x509.Certificate
	mu     sync.RWMutex
}

func (ic *issuerCache) get(hash [32]byte) *x509.Certificate {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.hashed[hash]
}

func (ic *issuerCache) add(issuer *x509.Certificate) error {
	nameHash, pkiHash, err := common.HashNameAndPKI(sha256.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(append(nameHash[:], pkiHash[:]...))
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.hashed[hashed] = issuer
	return nil
}
