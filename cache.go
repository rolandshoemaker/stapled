package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"

	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/log"
	stapledOCSP "github.com/rolandshoemaker/stapled/ocsp"
	"github.com/rolandshoemaker/stapled/stableCache"
)

type cache struct {
	log            *log.Logger
	entries        map[string]*Entry   // one-to-one map keyed on name -> entry
	lookupMap      map[[32]byte]*Entry // many-to-one map keyed on sha256 hashed OCSP requests -> entry
	StableBackings []stableCache.Cache
	client         *http.Client
	mu             sync.RWMutex
}

func newCache(log *log.Logger, monitorTick time.Duration, stableBackings []stableCache.Cache, client *http.Client) *cache {
	c := &cache{
		log:            log,
		entries:        make(map[string]*Entry),
		lookupMap:      make(map[[32]byte]*Entry),
		StableBackings: stableBackings,
		client:         client,
	}
	go c.monitor(monitorTick)
	return c
}

func hashEntry(h hash.Hash, name, pkiBytes []byte, serial *big.Int) ([32]byte, error) {
	issuerNameHash, issuerKeyHash, err := hashNameAndPKI(h, name, pkiBytes)
	if err != nil {
		return [32]byte{}, err
	}
	serialHash := sha256.Sum256(serial.Bytes())
	return sha256.Sum256(append(append(issuerNameHash, issuerKeyHash...), serialHash[:]...)), nil
}

func allHashes(e *Entry) ([][32]byte, error) {
	results := [][32]byte{}
	// these should be configurable in case people don't care about
	// supporting all of these hash algs
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

func (c *cache) addSingle(e *Entry, key [32]byte) {
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
func (c *cache) addMulti(e *Entry) error {
	hashes, err := allHashes(e)
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

func (c *cache) remove(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[name]
	if !present {
		return fmt.Errorf("entry '%s' is not in the cache", name)
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

func (c *cache) monitor(tick time.Duration) {
	ticker := time.NewTicker(tick)
	for range ticker.C {
		c.mu.RLock()
		defer c.mu.RUnlock()
		for _, entry := range c.entries {
			go entry.refreshAndLog(c.StableBackings, c.client)
		}
	}
}

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

func NewEntry(log *log.Logger, clk clock.Clock, timeout time.Duration) *Entry {
	return &Entry{
		log:     log,
		clk:     clk,
		timeout: timeout,
		mu:      new(sync.RWMutex),
	}
}

func proxyFunc(proxies []string) func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) {
		return url.Parse(common.RandomString(proxies))
	}
}

func (e *Entry) loadCertificate(filename string) error {
	e.name = strings.TrimSuffix(
		filepath.Base(filename),
		filepath.Ext(filename),
	)
	cert, err := ReadCertificate(filename)
	if err != nil {
		return err
	}
	e.serial = cert.SerialNumber
	e.responders = cert.OCSPServer
	if e.issuer == nil && len(cert.IssuingCertificateURL) > 0 {
		for _, issuerURL := range cert.IssuingCertificateURL {
			// this should be its own function
			resp, err := http.Get(issuerURL)
			if err != nil {
				e.log.Err("Failed to retrieve issuer from '%s': %s", issuerURL, err)
				continue
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				e.log.Err("Failed to read issuer body from '%s': %s", issuerURL, err)
				continue
			}
			e.issuer, err = ParseCertificate(body)
			if err != nil {
				e.log.Err("Failed to parse issuer body from '%s': %s", issuerURL, err)
				continue
			}
		}
	}
	return nil
}

func (e *Entry) loadCertificateInfo(name, serial string) error {
	e.name = name
	e.responseFilename = name + ".resp"
	serialBytes, err := hex.DecodeString(serial)
	if err != nil {
		return fmt.Errorf("failed to decode serial '%s': %s", e.serial, err)
	}
	e.serial = e.serial.SetBytes(serialBytes)
	return nil
}

// blergh
func (e *Entry) FromCertDef(def CertDefinition, globalUpstream []string) error {
	if def.Issuer != "" {
		var err error
		e.issuer, err = ReadCertificate(def.Issuer)
		if err != nil {
			return err
		}
	}
	if def.Certificate != "" {
		err := e.loadCertificate(def.Certificate)
		if err != nil {
			return err
		}
	} else if def.Name != "" && def.Serial != "" {
		err := e.loadCertificateInfo(def.Name, def.Serial)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("either certificate or name and serial must be provided")
	}
	if e.issuer == nil {
		return fmt.Errorf("either issuer or a certificate containing issuer AIA information must be provided")
	}
	if len(globalUpstream) > 0 && !def.OverrideGlobalUpstream {
		e.responders = globalUpstream
	} else if len(def.Responders) > 0 {
		e.responders = def.Responders
	}
	return nil
}

func (e *Entry) Init(stableBackings []stableCache.Cache, client *http.Client) error {
	if e.request == nil {
		if e.issuer == nil {
			return errors.New("if request isn't provided issuer must be non-nil")
		}
		issuerNameHash, issuerKeyHash, err := hashNameAndPKI(
			crypto.SHA1.New(),
			e.issuer.RawSubject,
			e.issuer.RawSubjectPublicKeyInfo,
		)
		if err != nil {
			return err
		}
		ocspRequest := &ocsp.Request{
			crypto.SHA1,
			issuerNameHash,
			issuerKeyHash,
			e.serial,
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
	err := e.refreshResponse(stableBackings, client)
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
func (e *Entry) updateResponse(eTag string, maxAge int, resp *ocsp.Response, respBytes []byte, stableBackings []stableCache.Cache) {
	e.info("Updating with new response, expires in %s", common.HumanDuration(resp.NextUpdate.Sub(e.clk.Now())))
	e.mu.Lock()
	defer e.mu.Unlock()
	e.eTag = eTag
	e.maxAge = time.Second * time.Duration(maxAge)
	e.lastSync = e.clk.Now()
	if resp != nil {
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
func (e *Entry) refreshResponse(stableBackings []stableCache.Cache, client *http.Client) error {
	if !e.timeToUpdate() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
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

	e.mu.RLock()
	if resp == nil || bytes.Compare(respBytes, e.response) == 0 {
		e.mu.RUnlock()
		e.info("Response hasn't changed since last sync")
		e.updateResponse(eTag, maxAge, nil, nil, stableBackings)
		return nil
	}
	e.mu.RUnlock()
	err = stapledOCSP.VerifyResponse(e.clk.Now(), e.serial, resp)
	if err != nil {
		return err
	}
	e.updateResponse(eTag, maxAge, resp, respBytes, stableBackings)
	e.info("Response has been refreshed")
	return nil
}

// refreshAndLog is a small wrapper around refreshResponse
// for when a caller wants to run it in a goroutine and doesn't
// want to handle the returned error itself
func (e *Entry) refreshAndLog(stableBackings []stableCache.Cache, client *http.Client) {
	err := e.refreshResponse(stableBackings, client)
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
