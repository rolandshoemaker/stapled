// Logic for fetching and verifiying OCSP responses, as
// well as deciding if a response should be updated.

package stapled

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

func humanDuration(d time.Duration) string {
	maybePluralize := func(input string, num int) string {
		if num == 1 {
			return input
		}
		return input + "s"
	}
	nanos := time.Duration(d.Nanoseconds())
	days := int(nanos / (time.Hour * 24))
	nanos %= time.Hour * 24
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds := int(nanos / time.Second)
	s := ""
	if days > 0 {
		s += fmt.Sprintf("%d %s ", days, maybePluralize("day", days))
	}
	if hours > 0 {
		s += fmt.Sprintf("%d %s ", hours, maybePluralize("hour", hours))
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d %s ", minutes, maybePluralize("minute", minutes))
	}
	if seconds >= 0 {
		s += fmt.Sprintf("%d %s ", seconds, maybePluralize("second", seconds))
	}
	return s
}

var windowSize = time.Hour * 8

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

	stop chan struct{}
	mu   *sync.RWMutex
}

func NewEntry(log *Logger, clk clock.Clock, timeout, baseBackoff, monitorTick time.Duration) *Entry {
	return &Entry{
		log:         log,
		clk:         clk,
		timeout:     timeout,
		baseBackoff: baseBackoff,
		mu:          new(sync.RWMutex),
		monitorTick: monitorTick,
		stop:        make(chan struct{}, 1),
	}
}

func loadProxy(uri string) (func(*http.Request) (*url.URL, error), error) {
	proxyURL, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %s", err)
	}
	return http.ProxyURL(proxyURL), nil
}

func (e *Entry) generateResponseFilename(cacheFolder string) {
	e.responseFilename = path.Join(
		cacheFolder,
		fmt.Sprintf(
			"%s.resp",
			strings.TrimSuffix(
				filepath.Base(e.name),
				filepath.Ext(e.name),
			),
		),
	)
}

func (e *Entry) loadCertificate(filename string) error {
	e.name = filename
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

func (e *Entry) FromCertDef(def CertDefinition, globalUpstream []string, globalProxy string, cacheFolder string) error {
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
	e.generateResponseFilename(cacheFolder)
	if len(globalUpstream) > 0 && !def.OverrideGlobalUpstream {
		e.responders = globalUpstream
	} else if len(def.Responders) > 0 {
		e.responders = def.Responders
	}
	proxyURI := ""
	if globalProxy != "" && !def.OverrideGlobalProxy {
		proxyURI = globalProxy
	} else if def.Proxy != "" {
		proxyURI = def.Proxy
	}
	if proxyURI != "" {
		proxy, err := loadProxy(proxyURI)
		if err != nil {
			return err
		}
		e.client = new(http.Client)
		e.client.Transport = &http.Transport{
			Proxy: proxy,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
	return nil
}

func (e *Entry) Init() error {
	issuerNameHash, issuerKeyHash, err := HashNameAndPKI(
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
	for i := range e.responders {
		e.responders[i] = strings.TrimSuffix(e.responders[i], "/")
	}
	if e.client == nil {
		e.client = new(http.Client)
	}
	err = e.readFromDisk()
	if err != nil && !os.IsNotExist(err) {
		return err
	} else if err != nil && os.IsNotExist(err) {
		err = e.refreshResponse()
		if err != nil {
			return err
		}
	}
	go e.monitor()
	return nil
}

func (e *Entry) info(msg string, args ...interface{}) {
	e.log.Info(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

func (e *Entry) err(msg string, args ...interface{}) {
	e.log.Err(fmt.Sprintf("[entry:%s] %s", e.name, msg), args...)
}

func (e *Entry) verifyResponse(resp *ocsp.Response) error {
	now := e.clk.Now()
	if resp.ThisUpdate.After(now) {
		return fmt.Errorf("malformed OCSP response: ThisUpdate is in the future (%s after %s)", resp.ThisUpdate, now)
	}
	if resp.NextUpdate.Before(now) {
		return fmt.Errorf("stale OCSP response: NextUpdate is in the past (%s before %s)", resp.NextUpdate, now)
	}
	if resp.ThisUpdate.After(resp.NextUpdate) {
		return fmt.Errorf("malformed OCSP response: NextUpdate is before ThisUpate (%s before %s)", resp.NextUpdate, resp.ThisUpdate)
	}
	if e.serial.Cmp(resp.SerialNumber) != 0 {
		return fmt.Errorf("malformed OCSP response: Serial numbers don't match (wanted %s, got %s)", e.serial, resp.SerialNumber)
	}
	e.info("New response is valid, expires in %s", humanDuration(resp.NextUpdate.Sub(now)))
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
	e.updateResponse("", 0, resp, respBytes, false)
	return nil
}

func (e *Entry) updateResponse(eTag string, maxAge int, resp *ocsp.Response, respBytes []byte, write bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.eTag = eTag
	e.maxAge = time.Second * time.Duration(maxAge)
	e.lastSync = e.clk.Now()
	if resp != nil {
		e.response = respBytes
		e.nextUpdate = resp.NextUpdate
		e.thisUpdate = resp.ThisUpdate
		if e.responseFilename != "" && write {
			err := e.writeToDisk()
			if err != nil {
				return err
			}
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
	if resp == nil || bytes.Compare(respBytes, e.response) == 0 {
		e.mu.RUnlock()
		e.info("Response has not changed since last sync")
		e.updateResponse(eTag, maxAge, nil, nil, true)
		return nil
	}
	e.mu.RUnlock()
	err = e.verifyResponse(resp)
	if err != nil {
		return err
	}
	e.updateResponse(eTag, maxAge, resp, respBytes, true)
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

	updateWindowStarts := e.nextUpdate.Add(-windowSize)

	if updateWindowStarts.After(now) {
		return nil
	}
	updateTime := updateWindowStarts.Add(time.Second * time.Duration(mrand.Intn(int(windowSize.Seconds()))))
	if updateTime.Before(now) {
		e.info("Update time was in the past, updating immediately")
		return &instantly
	}
	updateIn := updateTime.Sub(now)
	e.info("Updating response in %s", humanDuration(updateIn))
	return &updateIn
}

func (e *Entry) monitor() {
	ticker := time.NewTicker(e.monitorTick)
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			if updateIn := e.timeToUpdate(); updateIn != nil {
				e.clk.Sleep(*updateIn)
				err := e.refreshResponse()
				if err != nil {
					e.err("Failed to update entry: %s", err)
				}
			}
		}
	}
}
