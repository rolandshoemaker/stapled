package ocsp

import (
	"math/big"
	"testing"
	"time"

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
