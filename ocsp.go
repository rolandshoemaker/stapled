// Logic for fetching and verifiying OCSP responses, as
// well as deciding if a response should be updated.

package stapled

import (
	"crypto/x509"
	mrand "math/rand"
	"sync"
	"time"

	// "golang.org/x/crypto/ocsp"
)

type entry struct {
	issuer *x509.Certificate

	responder        string
	overrideUpstream bool

	lastSync    time.Time
	maxAge      time.Duration
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

func (e *entry) verifyResponse() error {
	return nil
}

func (e *entry) loadResponseFromFile(cacheFolder string) error {
	return nil
}

func (e *entry) fetchResponse() error {
	return nil
}

func (e *entry) updateResponse() error {
	// fetch response
	// verify response
	// update response (only lock during this part!)
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
	// haven't reached nextPublish yet
	if e.nextPublish.After(now) {
		return nil
	}
	// check if we are in the first half of the window
	firstHalf := e.nextUpdate.Sub(e.nextPublish) / 2
	if e.nextPublish.Add(firstHalf).After(now) {
		// wait until the object expires
		return nil
	}

	updateTime := e.nextPublish.Add(time.Second * time.Duration(mrand.Intn(int(firstHalf))))
	if updateTime.Before(now) {
		return &instantly
	}
	updateIn := updateTime.Sub(now)
	return &updateIn
}
