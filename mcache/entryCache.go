package mcache

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"

	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/config"
	"github.com/rolandshoemaker/stapled/log"
	stapledOCSP "github.com/rolandshoemaker/stapled/ocsp"
	"github.com/rolandshoemaker/stapled/scache"
)

// Entry represents a cache entry
type Entry struct {
	name     string
	log      *log.Logger
	clk      clock.Clock
	lastSync time.Time

	// cert related
	serial *big.Int
	issuer *x509.Certificate

	// request related
	responders []string
	timeout    time.Duration
	request    []byte

	// response related
	maxAge           time.Duration
	eTag             string
	response         []byte
	responseFilename string
	nextUpdate       time.Time
	thisUpdate       time.Time

	mu *sync.RWMutex
}

// NewEntry creates a basic unpopulated Entry
func NewEntry(log *log.Logger, clk clock.Clock) *Entry {
	return &Entry{
		log: log,
		clk: clk,
		mu:  new(sync.RWMutex),
	}
}

func (e *Entry) init(ctx context.Context, stableBackings []scache.Cache, client *http.Client) error {
	if e.issuer == nil {
		return errors.New("entry must have non-nil issuer")
	}
	if e.request == nil {
		issuerNameHash, issuerKeyHash, err := common.HashNameAndPKI(
			crypto.SHA1.New(),
			e.issuer.RawSubject,
			e.issuer.RawSubjectPublicKeyInfo,
		)
		if err != nil {
			return err
		}
		ocspRequest := &ocsp.Request{
			HashAlgorithm:  crypto.SHA1,
			IssuerNameHash: issuerNameHash,
			IssuerKeyHash:  issuerKeyHash,
			SerialNumber:   e.serial,
		}
		e.request, err = ocspRequest.Marshal()
		if err != nil {
			return err
		}
	}
	for i := range e.responders {
		e.responders[i] = strings.TrimSuffix(e.responders[i], "/")
	}
	for _, s := range stableBackings {
		resp, respBytes := s.Read(e.name, e.serial, e.issuer)
		if resp == nil {
			continue
		}
		e.updateResponse("", 0, resp, respBytes, nil)
		return nil // return first response from a stable cache backing
	}
	err := e.refreshResponse(ctx, stableBackings, client)
	if err != nil {
		return err
	}

	return nil
}

// info makes a Info log.Logger call tagged with the entry name
func (e *Entry) info(msg string, args ...interface{}) {
	e.log.Info(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

// info makes a Err log.Logger call tagged with the entry name
func (e *Entry) err(msg string, args ...interface{}) {
	e.log.Err(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

// updateResponse updates the actual response body/metadata
// stored in the entry
func (e *Entry) updateResponse(eTag string, maxAge int, resp *ocsp.Response, respBytes []byte, stableBackings []scache.Cache) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.eTag = eTag
	e.maxAge = time.Second * time.Duration(maxAge)
	e.lastSync = e.clk.Now()
	if resp != nil {
		e.info("Updating with new response, expires in %s", common.HumanDuration(resp.NextUpdate.Sub(e.clk.Now())))
		e.response = respBytes
		e.nextUpdate = resp.NextUpdate
		e.thisUpdate = resp.ThisUpdate
		for _, s := range stableBackings {
			s.Write(e.name, e.response) // logging is internal
		}
	}
}

// refreshResponse fetches and verifies a response and replaces
// the current response if it is valid and newer
func (e *Entry) refreshResponse(ctx context.Context, stableBackings []scache.Cache, client *http.Client) error {
	if !e.timeToUpdate() {
		return nil
	}
	resp, respBytes, eTag, maxAge, err := stapledOCSP.Fetch(
		ctx,
		e.log,
		e.responders,
		client,
		e.request,
		e.eTag,
		e.issuer,
	)
	if err != nil {
		return err
	}

	if resp != nil {
		err = stapledOCSP.VerifyResponse(e.clk.Now(), e.serial, resp)
		if err != nil {
			return err
		}
	}

	e.mu.RLock()
	if resp == nil || bytes.Compare(respBytes, e.response) == 0 {
		e.mu.RUnlock()
		e.info("Response hasn't changed since last sync")
		e.updateResponse(eTag, maxAge, nil, nil, stableBackings)
		return nil
	}
	e.mu.RUnlock()

	e.updateResponse(eTag, maxAge, resp, respBytes, stableBackings)
	e.info("Response has been refreshed")
	return nil
}

// refreshAndLog is a small wrapper around refreshResponse
// for when a caller wants to run it in a goroutine and doesn't
// want to handle the returned error itself
func (e *Entry) refreshAndLog(ctx context.Context, stableBackings []scache.Cache, client *http.Client) {
	err := e.refreshResponse(ctx, stableBackings, client)
	if err != nil {
		e.err("Failed to refresh response", err)
	}
}

// timeToUpdate checks if a current entry should be refreshed
// because cache parameters expired or it is in it's update window
func (e *Entry) timeToUpdate() bool {
	now := e.clk.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.response == nil {
		// not fetched anything previously
		return true
	}
	if e.nextUpdate.Before(now) {
		e.info("Stale response, updating immediately")
		return true
	}
	if e.maxAge > 0 {
		// cache max age has expired
		if e.lastSync.Add(e.maxAge).Before(now) {
			e.info("max-age has expired, updating immediately")
			return true
		}
	}

	// update window is last quarter of NextUpdate - ThisUpdate
	// TODO: support using NextPublish instead of ThisUpdate if provided
	// in responses
	windowSize := e.nextUpdate.Sub(e.thisUpdate) / 4
	updateWindowStarts := e.nextUpdate.Add(-windowSize)
	if updateWindowStarts.After(now) {
		return false
	}

	// randomly pick time in update window
	updateTime := updateWindowStarts.Add(time.Second * time.Duration(mrand.Intn(int(windowSize.Seconds()))))
	if updateTime.Before(now) {
		e.info("Time to update")
		return true
	}
	return false
}

// EntryCache holds the entry and issuer caches with various other
// required state
type EntryCache struct {
	log            *log.Logger
	clk            clock.Clock
	requestTimeout time.Duration
	entries        map[string]*Entry   // one-to-one map keyed on name -> entry
	lookupMap      map[[32]byte]*Entry // many-to-one map keyed on sha256 hashed OCSP requests -> entry
	StableBackings []scache.Cache
	issuers        *issuerCache
	client         *http.Client
	hashes         config.SupportedHashes
	mu             sync.RWMutex
}

// NewEntryCache constructs a EntryCache, starts the monitor, and returns it
func NewEntryCache(clk clock.Clock, logger *log.Logger, monitorTick time.Duration, stableBackings []scache.Cache, client *http.Client, timeout time.Duration, issuers []*x509.Certificate, supportedHashes config.SupportedHashes, disableMonitor bool) *EntryCache {
	c := &EntryCache{
		log:            logger,
		entries:        make(map[string]*Entry),
		lookupMap:      make(map[[32]byte]*Entry),
		StableBackings: stableBackings,
		client:         client,
		requestTimeout: timeout,
		clk:            clk,
		issuers:        newIssuerCache(issuers, supportedHashes),
		hashes:         supportedHashes,
	}
	if !disableMonitor {
		go c.monitor(monitorTick)
	}
	return c
}

func hashEntry(h hash.Hash, name, pkiBytes []byte, serial *big.Int) ([32]byte, error) {
	issuerNameHash, issuerKeyHash, err := common.HashNameAndPKI(h, name, pkiBytes)
	if err != nil {
		return [32]byte{}, err
	}
	serialHash := sha256.Sum256(serial.Bytes())
	return sha256.Sum256(append(append(issuerNameHash, issuerKeyHash...), serialHash[:]...)), nil
}

func allHashes(e *Entry, supportedHashes config.SupportedHashes) ([][32]byte, error) {
	results := [][32]byte{}
	// these should be configurable in case people don't care about
	// supporting all of these hash algs
	for _, h := range supportedHashes {
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

func (c *EntryCache) lookup(request *ocsp.Request) (*Entry, bool) {
	hash := hashRequest(request)
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, present := c.lookupMap[hash]
	return e, present
}

// LookupResponse looks up a entry in the cache and returns it's
// response if the entry exists
func (c *EntryCache) LookupResponse(request *ocsp.Request) ([]byte, bool) {
	e, present := c.lookup(request)
	if present {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return e.response, present
	}
	return nil, present
}

func (c *EntryCache) addSingle(e *Entry, key [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[e.name]; present {
		c.log.Warning("[cache] Entry for '%s' already exists in cache", e.name)
		return
	}
	c.log.Info("[cache] Adding entry for '%s'", e.name)
	c.entries[e.name] = e
	c.lookupMap[key] = e
}

// this cache structure seems kind of gross but... idk i think it's prob
// best for now (until I can think of something better :/)
func (c *EntryCache) add(e *Entry) error {
	hashes, err := allHashes(e, c.hashes)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.entries[e.name]; present {
		// log or fail...?
		c.log.Warning("[cache] Overwriting cache entry '%s'", e.name)
	} else {
		c.log.Info("[cache] Adding entry for '%s'", e.name)
	}
	c.entries[e.name] = e
	for _, h := range hashes {
		c.lookupMap[h] = e
	}
	return nil
}

func getIssuer(uri string) (*x509.Certificate, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return common.ParseCertificate(body)
}

// AddFromCertificate creates an entry from a certificate on disk and
// adds it to the cache, a issuer or set of OCSP responders can be
// provided
func (c *EntryCache) AddFromCertificate(filename string, issuer *x509.Certificate, responders []string) error {
	e := NewEntry(c.log, c.clk)
	e.name = strings.TrimSuffix(
		filepath.Base(filename),
		filepath.Ext(filename),
	)
	cert, err := common.ReadCertificate(filename)
	if err != nil {
		return err
	}
	e.serial = cert.SerialNumber
	e.responders = cert.OCSPServer
	if len(responders) > 0 {
		e.responders = responders
	}
	e.issuer = issuer
	if e.issuer == nil {
		// check issuer cache
		if e.issuer = c.issuers.getFromCertificate(cert.RawIssuer, cert.AuthorityKeyId); e.issuer == nil {
			// fetch from AIA
			for _, issuerURL := range cert.IssuingCertificateURL {
				e.issuer, err = getIssuer(issuerURL)
				if err != nil {
					e.log.Err("Failed to retrieve issuer from '%s': %s", issuerURL, err)
					continue
				}
				c.issuers.add(e.issuer)
				break
			}
		}
	} else {
		c.issuers.add(issuer)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	defer cancel()
	err = e.init(ctx, c.StableBackings, c.client)
	if err != nil {
		return err
	}
	return c.add(e)
}

// AddFromRequest creates an entry from a OCSP request and adds it to
// the cache, a set of upstream OCSP responders can be provided
func (c *EntryCache) AddFromRequest(req *ocsp.Request, upstream []string) ([]byte, error) {
	e := NewEntry(c.log, c.clk)
	e.serial = req.SerialNumber
	var err error
	e.request, err = req.Marshal()
	if err != nil {
		return nil, err
	}
	e.responders = upstream
	serialHash := sha256.Sum256(e.serial.Bytes())
	key := sha256.Sum256(append(append(req.IssuerNameHash, req.IssuerKeyHash...), serialHash[:]...))
	e.name = fmt.Sprintf("%X", key)
	e.issuer = c.issuers.getFromRequest(req.IssuerNameHash, req.IssuerKeyHash)
	if e.issuer == nil {
		return nil, errors.New("No issuer in cache for request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	defer cancel()
	err = e.init(ctx, c.StableBackings, c.client)
	if err != nil {
		return nil, err
	}
	c.addSingle(e, key)
	return e.response, nil
}

// Remove removes a entry from the cache
func (c *EntryCache) Remove(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[name]
	if !present {
		return fmt.Errorf("entry '%s' is not in the cache", name)
	}
	e.mu.Lock()
	delete(c.entries, name)
	hashes, err := allHashes(e, c.hashes)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		delete(c.lookupMap, h)
	}
	c.log.Info("[cache] Removed entry for '%s' from cache", name)
	return nil
}

func (c *EntryCache) monitor(tick time.Duration) {
	ticker := time.NewTicker(tick)
	for range ticker.C {
		c.mu.RLock()
		defer c.mu.RUnlock()
		for _, entry := range c.entries {
			go func(e *Entry) {
				ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
				defer cancel()
				e.refreshAndLog(ctx, c.StableBackings, c.client)
			}(entry)
		}
	}
}
