// Logic for fetching and verifiying OCSP responses, as
// well as deciding if a response should be updated.

package stapled

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
)

type Entry struct {
	name        string
	monitorTick time.Duration

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
	lastSync    time.Time
	maxAge      time.Duration
	eTag        string
	response    []byte
	nextPublish time.Time
	nextUpdate  time.Time
	thisUpdate  time.Time

	mu *sync.RWMutex
}

func NewEntry(response []byte, issuer *x509.Certificate, serial *big.Int, responders []string, timeout, backoff time.Duration) (*Entry, error) {
	client := new(http.Client)
	e := &Entry{
		client:      client,
		timeout:     timeout,
		baseBackoff: backoff,
		mu:          new(sync.RWMutex),
		lastSync:    time.Now(),
	}

	return e, nil
}

func (e *Entry) verifyResponse(resp *ocsp.Response) error {
	if resp.ThisUpdate.After(time.Now()) {
		return errors.New("Malformed OCSP response: ThisUpdate is in the future")
	}
	if resp.ThisUpdate.After(resp.NextUpdate) {
		return errors.New("Malformed OCSP response: NextUpdate is before ThisUpate")
	}
	if err := resp.CheckSignatureFrom(e.issuer); err != nil {
		return err
	}
	if e.serial.Cmp(resp.SerialNumber) != 0 {
		return errors.New("Malformed OCSP response: Serial numbers don't match")
	}
	// check signing cert is still valid? (this could
	// probably also be taken care of somewhere else...)
	return nil
}

func (e *Entry) randomResponder() string {
	return e.responders[mrand.Intn(len(e.responders))]
}

func (e *Entry) fetchResponse(ctx context.Context) (*ocsp.Response, []byte, string, int, error) {
	backoffSeconds := 0
	for {
		select {
		case <-ctx.Done():
			return nil, nil, "", 0, ctx.Err()
		case <-time.NewTimer(time.Duration(backoffSeconds) * time.Second).C:
		}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf(
				"%s/%s",
				e.randomResponder(),
				base64.StdEncoding.EncodeToString(e.request),
			),
			nil,
		)
		if err != nil {
			return nil, nil, "", 0, err
		}
		if e.eTag != "" {
			req.Header.Set("If-None-Match", e.eTag)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			// log
			backoffSeconds = 10
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			backoffSeconds = 10
			if resp.StatusCode == 503 {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, err := strconv.Atoi(retryAfter); err == nil {
						backoffSeconds = seconds
					}
				}
			}
			if resp.StatusCode == 304 {
				return nil, nil, "", 0, nil
			}
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// log
			backoffSeconds = 10
			continue
		}
		ocspResp, err := ocsp.ParseResponse(body, e.issuer)
		if err != nil {
			// log
			backoffSeconds = 10
			continue
		}
		if ocspResp.Status == int(ocsp.Success) {
			maxAge := 0
			eTag, cacheControl := resp.Header.Get("ETag"), resp.Header.Get("Cache-Control")
			if cacheControl != "" {
				cacheControl = strings.Replace(cacheControl, " ", "", -1)
				for _, p := range strings.Split(cacheControl, ",") {
					if strings.HasPrefix(p, "max-age=") {
						maxAge, err = strconv.Atoi(p[8:])
						if err != nil {
							// log
						}
					}
				}
			}
			return ocspResp, body, eTag, maxAge, nil
		}
		backoffSeconds = 10
	}
}

func (e *Entry) updateResponse() error {
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	resp, respBytes, eTag, maxAge, err := e.fetchResponse(ctx)
	if err != nil {
		return err
	}
	e.mu.RLock()
	if respBytes == nil || bytes.Compare(respBytes, e.response) == 0 {
		e.mu.RUnlock()
		e.mu.Lock()
		defer e.mu.Unlock()
		// return same response or got 304 header
		e.lastSync = now
		return nil
	}
	e.mu.RUnlock()
	err = e.verifyResponse(resp)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.response = respBytes
	e.eTag = eTag
	e.maxAge = time.Second * time.Duration(maxAge)
	e.nextUpdate = resp.NextUpdate
	e.thisUpdate = resp.ThisUpdate
	e.lastSync = now
	// write to file if we are going to do that
	return nil
}

var instantly = time.Duration(0)

func (e *Entry) timeToUpdate() *time.Duration {
	now := time.Now()
	// no response or nextUpdate is in the past
	e.mu.RLock()
	if e.response == nil || e.nextUpdate.Before(now) {
		e.mu.RUnlock()
		return &instantly
	}
	e.mu.RUnlock()
	// cache max age has expired
	if e.maxAge > 0 {
		if e.lastSync.Add(e.maxAge).Before(now) {
			return &instantly
		}
	}
	// check if we are in the first half of the window
	firstHalf := e.nextUpdate.Sub(e.thisUpdate) / 2
	if e.nextPublish.Add(firstHalf).After(now) {
		// wait until the object expires
		return nil
	}

	updateTime := e.thisUpdate.Add(time.Second * time.Duration(mrand.Intn(int(firstHalf))))
	if updateTime.Before(now) {
		return &instantly
	}
	updateIn := updateTime.Sub(now)
	return &updateIn
}

func (e *Entry) monitor() {
	ticker := time.NewTicker(e.monitorTick)
	for range ticker.C {
		if updateIn := e.timeToUpdate(); updateIn != nil {
			time.Sleep(*updateIn)
			err := e.updateResponse()
			if err != nil {
				// log
			}
		}
	}
}
