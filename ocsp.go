// Logic for fetching and verifiying OCSP responses, as
// well as deciding if a response should be updated.

package stapled

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
)

var statusToString = map[int]string{
	0: "Success",
	1: "Malformed",
	2: "InternalError",
	3: "TryLater",
	5: "SignatureRequired",
	6: "Unauthorized",
}

type Entry struct {
	name        string
	monitorTick time.Duration
	log         *Logger
	clk         clock.Clock

	// cert related
	serial *big.Int
	issuer *x509.Certificate

	// request related
	responders  []string
	client      *http.Client
	timeout     time.Duration
	baseBackoff time.Duration
	request     []byte

	// response related
	lastSync         time.Time
	maxAge           time.Duration
	eTag             string
	response         []byte
	responseFilename string
	nextUpdate       time.Time
	thisUpdate       time.Time

	mu *sync.RWMutex
}

type EntryDefinition struct {
	Log         *Logger
	Clk         clock.Clock
	Name        string
	CacheFolder string
	Response    []byte
	Issuer      *x509.Certificate
	Serial      *big.Int
	Responders  []string
	Timeout     time.Duration
	Backoff     time.Duration
	Proxy       func(*http.Request) (*url.URL, error)
}

func NewEntry(def *EntryDefinition) (*Entry, error) {
	issuerNameHash, issuerKeyHash, err := HashNameAndPKI(
		crypto.SHA1.New(),
		def.Issuer.RawSubject,
		def.Issuer.RawSubjectPublicKeyInfo,
	)
	if err != nil {
		return nil, err
	}
	ocspRequest := &ocsp.Request{
		crypto.SHA1,
		issuerNameHash,
		issuerKeyHash,
		def.Serial,
	}
	request, err := ocspRequest.Marshal()
	if err != nil {
		return nil, err
	}
	for i := range def.Responders {
		def.Responders[i] = strings.TrimSuffix(def.Responders[i], "/")
	}
	client := new(http.Client)
	if def.Proxy != nil {
		// default transport + proxy
		client.Transport = &http.Transport{
			Proxy: def.Proxy,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
	responseFilename := ""
	if def.CacheFolder != "" {
		responseFilename = path.Join(
			def.CacheFolder,
			fmt.Sprintf(
				"%s.resp",
				strings.TrimSuffix(
					filepath.Base(def.Name),
					filepath.Ext(def.Name),
				),
			),
		)
	}
	e := &Entry{
		name:             def.Name,
		log:              def.Log,
		clk:              def.Clk,
		serial:           def.Serial,
		issuer:           def.Issuer,
		client:           client,
		request:          request,
		responders:       def.Responders,
		timeout:          def.Timeout,
		baseBackoff:      def.Backoff,
		response:         def.Response,
		mu:               new(sync.RWMutex),
		lastSync:         def.Clk.Now(),
		monitorTick:      1 * time.Minute,
		responseFilename: responseFilename,
	}
	if e.responseFilename != "" {
		err = e.readFromDisk()
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	if e.response == nil {
		err = e.refreshResponse()
		if err != nil {
			return nil, err
		}
	}
	go e.monitor()
	return e, nil
}

func (e *Entry) info(msg string, args ...interface{}) {
	e.log.Info(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

func (e *Entry) err(msg string, args ...interface{}) {
	e.log.Err(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

func (e *Entry) verifyResponse(resp *ocsp.Response) error {
	if resp.ThisUpdate.After(e.clk.Now()) {
		return errors.New("Malformed OCSP response: ThisUpdate is in the future")
	}
	if resp.ThisUpdate.After(resp.NextUpdate) {
		return errors.New("Malformed OCSP response: NextUpdate is before ThisUpate")
	}
	if e.serial.Cmp(resp.SerialNumber) != 0 {
		return errors.New("Malformed OCSP response: Serial numbers don't match")
	}
	// check signing cert is still valid? (this could
	// probably also be taken care of somewhere else...)
	e.info("New response is valid")
	return nil
}

func (e *Entry) randomResponder() string {
	return e.responders[mrand.Intn(len(e.responders))]
}

func parseCacheControl(h string) int {
	maxAge := 0
	h = strings.Replace(h, " ", "", -1)
	for _, p := range strings.Split(h, ",") {
		if strings.HasPrefix(p, "max-age=") {
			maxAge, _ = strconv.Atoi(p[8:])
		}
	}
	return maxAge
}

func (e *Entry) fetchResponse(ctx context.Context) (*ocsp.Response, []byte, string, int, error) {
	backoffSeconds := 0
	for {
		if backoffSeconds > 0 {
			e.info("Request failed, backing off for %d seconds", backoffSeconds)
		}
		select {
		case <-ctx.Done():
			return nil, nil, "", 0, ctx.Err()
		case <-time.NewTimer(time.Duration(backoffSeconds) * time.Second).C:
		}
		if backoffSeconds > 0 {
			backoffSeconds = 0
		}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf(
				"%s/%s",
				e.randomResponder(),
				url.QueryEscape(base64.StdEncoding.EncodeToString(e.request)),
			),
			nil,
		)
		if err != nil {
			return nil, nil, "", 0, err
		}
		if e.eTag != "" {
			req.Header.Set("If-None-Match", e.eTag)
		}
		e.info("Sending request to '%s'", req.URL)
		resp, err := e.client.Do(req)
		if err != nil {
			e.err("Request for '%s' failed: %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			if resp.StatusCode == 304 {
				e.info("Response for '%s' hasn't changed", req.URL)
				eTag, cacheControl := resp.Header.Get("ETag"), parseCacheControl(resp.Header.Get("Cache-Control"))
				return nil, nil, eTag, cacheControl, nil
			}
			e.err("Request for '%s' got a non-200 response: %d", req.URL, resp.StatusCode)
			backoffSeconds = 10
			if resp.StatusCode == 503 {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, err := strconv.Atoi(retryAfter); err == nil {
						backoffSeconds = seconds
					}
				}
			}
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			e.err("Failed to read response body from '%s': %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		ocspResp, err := ocsp.ParseResponse(body, e.issuer)
		if err != nil {
			e.err("Failed to parse response body from '%s': %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		if ocspResp.Status == int(ocsp.Success) {
			eTag, cacheControl := resp.Header.Get("ETag"), parseCacheControl(resp.Header.Get("Cache-Control"))
			return ocspResp, body, eTag, cacheControl, nil
		}
		e.err("Request for '%s' got a invalid OCSP response status: %s", req.URL, statusToString[ocspResp.Status])
		backoffSeconds = 10
	}
}

// writeToDisk assumes the caller holds a lock
func (e *Entry) writeToDisk() error {
	tmpName := fmt.Sprintf("%s.tmp", e.responseFilename)
	err := ioutil.WriteFile(tmpName, e.response, os.ModePerm)
	if err != nil {
		return err
	}
	err = os.Rename(tmpName, e.responseFilename)
	if err != nil {
		return err
	}
	e.info("Written new response to %s", e.responseFilename)
	return nil
}

func (e *Entry) readFromDisk() error {
	respBytes, err := ioutil.ReadFile(e.responseFilename)
	if err != nil {
		return err
	}
	e.info("Read response from %s", e.responseFilename)
	resp, err := ocsp.ParseResponse(respBytes, e.issuer)
	if err != nil {
		return err
	}
	err = e.verifyResponse(resp)
	if err != nil {
		return err
	}
	e.updateResponse("", 0, resp, respBytes)
	return nil
}

func (e *Entry) updateResponse(eTag string, maxAge int, resp *ocsp.Response, respBytes []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.response = respBytes
	e.eTag = eTag
	e.maxAge = time.Second * time.Duration(maxAge)
	e.nextUpdate = resp.NextUpdate
	e.thisUpdate = resp.ThisUpdate
	e.lastSync = e.clk.Now()
	if e.responseFilename != "" {
		err := e.writeToDisk()
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Entry) refreshResponse() error {
	e.info("Attempting to refresh response")
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	resp, respBytes, eTag, maxAge, err := e.fetchResponse(ctx)
	if err != nil {
		return err
	}

	e.mu.RLock()
	if respBytes == nil || bytes.Compare(respBytes, e.response) == 0 {
		e.mu.RUnlock()
		e.info("Response has not changed since last sync")
		e.updateResponse(eTag, maxAge, nil, nil)
		return nil
	}
	e.mu.RUnlock()
	err = e.verifyResponse(resp)
	if err != nil {
		return err
	}
	e.updateResponse(eTag, maxAge, resp, respBytes)
	e.info("Response has been refreshed")
	return nil
}

var instantly = time.Duration(0)

func (e *Entry) timeToUpdate() *time.Duration {
	now := e.clk.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()
	// no response or nextUpdate is in the past
	if e.response == nil || e.nextUpdate.Before(now) {
		e.info("Stale response, updating immediately")
		return &instantly
	}
	if e.maxAge > 0 {
		// cache max age has expired
		if e.lastSync.Add(e.maxAge).Before(now) {
			e.info("max-age has expired, updating immediately")
			return &instantly
		}
	}

	half := e.nextUpdate.Sub(e.thisUpdate) / 2
	halfWay := e.thisUpdate.Add(half)
	if halfWay.After(now) {
		return nil
	}
	updateTime := halfWay.Add(time.Second * time.Duration(mrand.Intn(int(half.Seconds()))))
	if updateTime.Before(now) {
		e.info("Update time was in the past, updating immediately")
		return &instantly
	}
	updateIn := updateTime.Sub(now)
	e.info("Updating response in %s", updateIn)
	return &updateIn
}

func (e *Entry) monitor() {
	for {
		if updateIn := e.timeToUpdate(); updateIn != nil {
			e.clk.Sleep(*updateIn)
			err := e.refreshResponse()
			if err != nil {
				e.err("Failed to update entry: %s", err)
			}
		}
		e.clk.Sleep(e.monitorTick)
	}
}
