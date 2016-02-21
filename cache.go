// Logic for reading and writing to and from the cache
// (should probably have an interface and a default
// on disk cache + the in-memory one?).

package stapled

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"golang.org/x/crypto/ocsp"
)

type cache struct {
	log       *Logger
	entries   map[string]*Entry
	lookupMap map[[32]byte]*Entry
	mu        *sync.RWMutex
}

func newCache(log *Logger) *cache {
	return &cache{log, make(map[string]*Entry), make(map[[32]byte]*Entry), new(sync.RWMutex)}
}

func hashEntry(h hash.Hash, name, pkiBytes []byte, serial *big.Int) ([32]byte, error) {
	issuerNameHash, issuerKeyHash, err := HashNameAndPKI(h, name, pkiBytes)
	if err != nil {
		return [32]byte{}, err
	}
	serialHash := sha256.Sum256(serial.Bytes())
	return sha256.Sum256(append(append(issuerNameHash, issuerKeyHash...), serialHash[:]...)), nil
}

func allHashes(e *Entry) ([][32]byte, error) {
	results := [][32]byte{}
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		hashed, err := hashEntry(h.New(), e.issuer.RawSubject, e.issuer.RawSubjectPublicKeyInfo, e.serial)
		if err != nil {
			return nil, err
		}
		results = append(results, hashed)
	}
	return results, nil
}

func hashRequest(request *ocsp.Request) [32]byte {
	serialHash := sha256.Sum256(request.SerialNumber.Bytes())
	return sha256.Sum256(append(append(request.IssuerNameHash, request.IssuerKeyHash...), serialHash[:]...))
}

func (c *cache) lookup(request *ocsp.Request) (*Entry, bool) {
	hash := hashRequest(request)
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
		return e.response, present
	}
	return nil, present
}

// this cache structure seems kind of gross but... idk i think it's prob
// best for now (until I can think of something better :/)
func (c *cache) add(e *Entry) error {
	hashes, err := allHashes(e)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[e.name]; present {
		// log or fail...?
		c.log.Warning("[cache] Overwriting cache entry")
	}
	c.entries[e.name] = e
	for _, h := range hashes {
		c.lookupMap[h] = e
	}
	c.log.Info("[cache] New entry for '%s' added", e.name)
	return nil
}

func (c *cache) remove(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[name]
	if !present {
		return fmt.Errorf("Entry '%s' is not in the cache", name)
	}
	e.mu.Lock()
	delete(c.entries, name)
	hashes, err := allHashes(e)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		delete(c.lookupMap, h)
	}
	c.log.Info("[cache] Removed entry for '%s' from cache", name)
	return nil
}
