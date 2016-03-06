package main

import (
	"bytes"
	"crypto"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
)

func TestCache(t *testing.T) {
	c := newCache(NewLogger("", "", 10, clock.Default()), time.Minute)

	issuer, err := ReadCertificate("testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read test issuer", err)
	}
	e := &Entry{
		mu:       new(sync.RWMutex),
		name:     "test.der",
		serial:   big.NewInt(1337),
		issuer:   issuer,
		response: []byte{5, 0, 1},
	}

	err = c.addMulti(e)
	if err != nil {
		t.Fatalf("Failed to add entry to cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := hashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("Failed to hash subject and public key info: %s", err)
		}
		req := &ocsp.Request{h, nameHash, pkHash, e.serial}
		foundEntry, present := c.lookup(req)
		if !present {
			t.Fatal("Didn't find entry that should be in cache")
		}
		if foundEntry != e {
			t.Fatal("Cache returned wrong entry")
		}
		response, present := c.lookupResponse(req)
		if !present {
			t.Fatal("Didn't find response that should be in cache")
		}
		if bytes.Compare(response, e.response) != 0 {
			t.Fatal("Cache returned wrong response")
		}
	}

	err = c.remove("test.der")
	if err != nil {
		t.Fatalf("Failed to remove entry from cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := hashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("Failed to hash subject and public key info: %s", err)
		}
		_, present := c.lookup(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found entry that should've been removed from cache")
		}
		_, present = c.lookupResponse(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found response that should've been removed from cache")
		}
	}
}
