// Logic for reading and writing to and from the cache
// (should probably have an interface and a default
// on disk cache + the in-memory one?).

package stapled

import (
	"crypto"
	"crypto/sha256"
	"hash"
	"math/big"
	"sync"

	"golang.org/x/crypto/ocsp"
)

type cache struct {
	entries   map[[32]byte]*entry
	lookupMap map[[32]byte]*entry
	mu        *sync.RWMutex
}

func hashEntry(h hash.Hash, name, publicKey []byte, serial *big.Int) [32]byte {
	h.Write(name)
	issuerNameHash := h.Sum(nil)
	h.Reset()
	h.Write(publicKey)
	issuerKeyHash := h.Sum(nil)
	serialHash := sha256.Sum256(serial.Bytes())
	return sha256.Sum256(append(append(issuerNameHash[:], issuerKeyHash[:]...), serialHash[:]...))
}

func allHashes(e *entry, serial *big.Int) ([32]byte, [32]byte, [32]byte, [32]byte) {
	results := [][32]byte{}
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		results = append(results, hashEntry(h.New(), e.issuer.RawSubject, e.issuer.RawSubjectPublicKeyInfo, serial))
	}
	return results[0], results[1], results[2], results[3]
}

func hashRequest(request ocsp.Request) [32]byte {
	serialHash := sha256.Sum256(request.SerialNumber.Bytes())
	return sha256.Sum256(append(append(request.IssuerNameHash, request.IssuerKeyHash...), serialHash[:]...))
}

func (c *cache) lookup(request *ocsp.Request) (*entry, bool) {
	serialHash := sha256.Sum256(request.SerialNumber.Bytes())
	hash := sha256.Sum256(append(append(request.IssuerNameHash, request.IssuerKeyHash...), serialHash[:]...))
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, present := c.entries[hash]
	return e, present
}

func (c *cache) lookupResponse(request *ocsp.Request) ([]byte, bool) {
	e, present := c.lookup(request)
	if present {
		e.mu.RLock()
		defer e.mu.RUnlock()
		resp := e.response
		return resp, present
	}
	return nil, present
}

// this cache structure seems kind of gross but... idk i think it's prob
// best for now (until I can think of something better :/)
func (c *cache) add(e *entry, serial *big.Int) {
	sha1Hash, sha256Hash, sha384Hash, sha512Hash := allHashes(e, serial)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[sha256Hash]; present {
		// log overwriting or fail...?
	}
	c.entries[sha256Hash] = e
	for _, h := range [][32]byte{sha1Hash, sha256Hash, sha384Hash, sha512Hash} {
		c.lookupMap[h] = e
	}
}
