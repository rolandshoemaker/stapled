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
	entries   map[[32]byte]*Entry
	lookupMap map[[32]byte]*Entry
	mu        *sync.RWMutex
}

func hashEntry(h hash.Hash, name, pkiBytes []byte, serial *big.Int) ([32]byte, error) {
	issuerNameHash, issuerKeyHash, err := HashNameAndPKI(h, name, pkiBytes)
	if err != nil {
		return [32]byte{}, err
	}
	serialHash := sha256.Sum256(serial.Bytes())
	return sha256.Sum256(append(append(issuerNameHash, issuerKeyHash...), serialHash[:]...)), nil
}

func allHashes(e *Entry) ([32]byte, [32]byte, [32]byte, [32]byte, error) {
	results := [][32]byte{}
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		hashed, err := hashEntry(h.New(), e.issuer.RawSubject, e.issuer.RawSubjectPublicKeyInfo, e.serial)
		if err != nil {
			return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, err
		}
		results = append(results, hashed)
	}
	return results[0], results[1], results[2], results[3], nil
}

func hashRequest(request ocsp.Request) [32]byte {
	serialHash := sha256.Sum256(request.SerialNumber.Bytes())
	return sha256.Sum256(append(append(request.IssuerNameHash, request.IssuerKeyHash...), serialHash[:]...))
}

func (c *cache) lookup(request *ocsp.Request) (*Entry, bool) {
	serialHash := sha256.Sum256(request.SerialNumber.Bytes())
	hash := sha256.Sum256(append(append(request.IssuerNameHash, request.IssuerKeyHash...), serialHash[:]...))
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, present := c.lookupMap[hash]
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
func (c *cache) add(e *Entry) error {
	sha1Hash, sha256Hash, sha384Hash, sha512Hash, err := allHashes(e)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[sha256Hash]; present {
		// log overwriting or fail...?
	}
	c.entries[sha256Hash] = e
	for _, h := range [][32]byte{sha1Hash, sha256Hash, sha384Hash, sha512Hash} {
		c.lookupMap[h] = e
	}
	return nil
}
