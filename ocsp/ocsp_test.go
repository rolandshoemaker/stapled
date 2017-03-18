package ocsp

import (
	"math/big"
	// "net/http"
	"testing"
	"time"

	// "github.com/rolandshoemaker/stapled/log"

	// "github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
)

func TestVerifyResponse(t *testing.T) {
	now := time.Now()
	serial := big.NewInt(10)
	thisUpdate := now.Add(-time.Hour)
	nextUpdate := now.Add(time.Hour)
	resp := &ocsp.Response{
		SerialNumber: serial,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}

	err := VerifyResponse(now, serial, resp)
	if err != nil {
		t.Fatalf("Valid response failed verification: %s", err)
	}

	resp.ThisUpdate = resp.ThisUpdate.Add(90 * time.Minute)
	err = VerifyResponse(now, serial, resp)
	if err == nil {
		t.Fatal("VerifyResponse allowed a response with ThisUpdate in the future")
	}
	resp.ThisUpdate = thisUpdate

	resp.NextUpdate = resp.NextUpdate.Add(-90 * time.Minute)
	err = VerifyResponse(now, serial, resp)
	if err == nil {
		t.Fatal("VerifyResponse allowed a response with NextUpdate in the past")
	}
	resp.NextUpdate = nextUpdate

	resp.SerialNumber = big.NewInt(1)
	err = VerifyResponse(now, serial, resp)
	if err == nil {
		t.Fatal("VerifyResponse allowed a response with the incorrect SerialNumber")
	}
}

func TestParseCacheControl(t *testing.T) {
	ma := parseCacheControl("derp")
	if ma != 0 {
		t.Fatalf("parseCacheControl parsed 'derp' as %d", ma)
	}
	ma = parseCacheControl("max-age=")
	if ma != 0 {
		t.Fatalf("parseCacheControl parsed 'max-age=' as %d", ma)
	}
	ma = parseCacheControl("max-age=100")
	if ma != 100 {
		t.Fatalf("parseCacheControl parsed 'max-age=100' as %d", ma)
	}

}

func TestRandomResponder(t *testing.T) {
	testResponders := []string{"a", "b"}
	random := randomResponder(testResponders)
	if !(random == "a" || random == "b") {
		t.Fatalf("randomResponder returned something that wasn't in the provided slice: %q", random)
	}
}

// func fetchHandler(w http.ResponseWriter, r *http.Request) {

// }

// func TestFetch(t *testing.T) {
// 	logger := log.NewLogger("", "", 0, clock.Default())
// 	c := http.Client{}

// 	http.HandleFunc("/", fetchHandler)
// 	go func() {
// 		err := http.ListenAndServe("localhost:8080", nil)
// 		if err != nil {
// 			t.Fatalf("HTTP test server failed: %s", err)
// 		}
// 	}()
// }
