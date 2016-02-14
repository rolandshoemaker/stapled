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
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
)

type entry struct {
	serial *big.Int
	issuer *x509.Certificate

	responder        string
	client           *http.Client
	deadline         time.Duration
	request          []byte
	overrideUpstream bool

	lastSync    time.Time
	maxAge      time.Duration
	eTag        string
	response    []byte
	nextPublish time.Time
	nextUpdate  time.Time
	thisUpdate  time.Time

	mu *sync.RWMutex
}

func entryFromFile() (*entry, error) {
	return nil, nil
}

func entryFromDefinition() (*entry, error) {
	return nil, nil
}

func (e *entry) verifyResponse(resp *ocsp.Response) error {
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

func (e *entry) fetchResponse(ctx context.Context) (*ocsp.Response, []byte, error) {
	backoffSeconds := 0
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.NewTimer(time.Duration(backoffSeconds) * time.Second).C:
		}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf(
				"%s/%s",
				e.responder,
				base64.StdEncoding.EncodeToString(e.request),
			),
			nil,
		)
		if err != nil {
			return nil, nil, err
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
			return ocspResp, body, nil
		}
		backoffSeconds = 10
	}
}

func (e *entry) updateResponse() error {
	ctx := context.WithTimeout(context.Background(), e.deadline)
	resp, respBytes, err := e.fetchResponse(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	if bytes.Compare(respBytes, e.response) == 0 {
		e.lastSync = now
		return nil
	}
	err = e.verifyResponse(resp)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.response = respBytes
	e.nextUpdate = resp.NextUpdate
	e.thisUpdate = resp.ThisUpdate
	e.lastSync = now
	// write to file if we are going to do that
	return nil
}

var instantly = time.Duration(0)

func (e *entry) timeToUpdate() *time.Duration {
	now := time.Now()
	// no response or nextUpdate is in the past
	if e.response == nil || e.nextUpdate.Before(now) {
		return &instantly
	}
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
