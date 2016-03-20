package memCache

import (
	"bytes"
	"crypto"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/log"
)

func TestEntryCache(t *testing.T) {
	c := NewEntryCache(clock.Default(), log.NewLogger("", "", 10, clock.Default()), time.Minute, nil, nil, time.Minute, nil)

	issuer, err := common.ReadCertificate("../testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read test issuer: %s", err)
	}
	e := &Entry{
		mu:       new(sync.RWMutex),
		name:     "test.der",
		serial:   big.NewInt(1337),
		issuer:   issuer,
		response: []byte{5, 0, 1},
	}

	err = c.add(e)
	if err != nil {
		t.Fatalf("Failed to add entry to cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := common.HashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
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
		response, present := c.LookupResponse(req)
		if !present {
			t.Fatal("Didn't find response that should be in cache")
		}
		if bytes.Compare(response, e.response) != 0 {
			t.Fatal("Cache returned wrong response")
		}
	}

	err = c.Remove("test.der")
	if err != nil {
		t.Fatalf("Failed to remove entry from cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := common.HashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("Failed to hash subject and public key info: %s", err)
		}
		_, present := c.lookup(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found entry that should've been removed from cache")
		}
		_, present = c.LookupResponse(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found response that should've been removed from cache")
		}
	}
}
