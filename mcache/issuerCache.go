package mcache

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"sync"

	"github.com/rolandshoemaker/stapled/common"
)

type issuerCache struct {
	subjectPlusSKID map[[32]byte]*x509.Certificate
	subjectPlusSPKI map[[32]byte]*x509.Certificate
	mu              sync.RWMutex
}

func newIssuerCache(issuers []*x509.Certificate) *issuerCache {
	ic := &issuerCache{
		subjectPlusSKID: make(map[[32]byte]*x509.Certificate),
		subjectPlusSPKI: make(map[[32]byte]*x509.Certificate),
	}
	for _, issuer := range issuers {
		ic.add(issuer)
	}
	return ic
}

func (ic *issuerCache) getFromCertificate(issuerSubject, akid []byte) *x509.Certificate {
	subj := make([]byte, len(issuerSubject))
	copy(subj, issuerSubject)
	hashed := sha256.Sum256(append(subj, akid...))
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.subjectPlusSKID[hashed]
}

func (ic *issuerCache) getFromRequest(issuerSubjectHash, spkiHash []byte) *x509.Certificate {
	hashed := sha256.Sum256(append(issuerSubjectHash, spkiHash...))
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.subjectPlusSPKI[hashed]
}

func allIssuerHashes(i *x509.Certificate) ([][32]byte, error) {
	hashes := [][32]byte{}
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		name, spki, err := common.HashNameAndPKI(h.New(), i.RawSubject, i.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, sha256.Sum256(append(name, spki...)))
	}
	return hashes, nil
}

func (ic *issuerCache) add(issuer *x509.Certificate) error {
	// work around for a bug of sorts in encoding/asn1
	// https://github.com/golang/go/issues/14882
	subj := make([]byte, len(issuer.RawSubject))
	copy(subj, issuer.RawSubject)
	spskid := sha256.Sum256(append(subj, issuer.SubjectKeyId...))
	otherHashes, err := allIssuerHashes(issuer)
	if err != nil {
		return err
	}
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.subjectPlusSKID[spskid] = issuer
	for _, h := range otherHashes {
		ic.subjectPlusSPKI[h] = issuer
	}
	return nil
}
