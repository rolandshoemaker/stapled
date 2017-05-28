package ocsp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/rolandshoemaker/stapled/log"
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

type fetchSrv struct {
	response []byte
	status   int
	etag     string
}

func (fs *fetchSrv) fetchHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("wut", r.URL.Path[1:])
	b64, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
	req, err := ocsp.ParseRequest(b64)
	if err != nil {
		panic(err)
	}
	switch req.SerialNumber.Int64() {
	case 1:
		w.WriteHeader(http.StatusBadRequest)
	case 2:
		w.Header().Set("Retry-After", "IM A BANANA")
		w.WriteHeader(http.StatusBadRequest)
	case 3:
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ᶘ ᵒᴥᵒᶅ"))
	default:
		w.WriteHeader(fs.status)
		w.Write(fs.response)
	}
}

func TestFetch(t *testing.T) {
	logger := log.NewLogger("", "", 0, clock.Default())
	c := new(http.Client)

	fs := fetchSrv{}
	http.HandleFunc("/", fs.fetchHandler)
	go func() {
		err := http.ListenAndServe("localhost:8080", nil)
		if err != nil {
			t.Fatalf("HTTP test server failed: %s", err)
		}
	}()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %s", err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: "yo"},
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %s", err)
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %s", err)
	}

	ocspResponse := ocsp.Response{
		SerialNumber: big.NewInt(0),
		Status:       ocsp.Good,
	}
	response, err := ocsp.CreateResponse(
		issuer,
		issuer,
		ocspResponse,
		key,
	)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse failed: %s", err)
	}
	parsedResp, err := ocsp.ParseResponse(response, nil)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse failed: %s", err)
	}

	fs.response = response
	fs.status = 200

	ocspRequest := &ocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: []byte{0, 1},
		IssuerKeyHash:  []byte{0, 2},
		SerialNumber:   big.NewInt(0),
	}
	req, err := ocspRequest.Marshal()
	if err != nil {
		t.Fatalf("ocspRequest.Marshal failed: %s", err)
	}

	// good response
	returnedResp, _, _, _, err := Fetch(
		context.Background(),
		logger,
		[]string{"http://localhost:8080"},
		c,
		req,
		"etag!",
		issuer,
	)
	if err != nil {
		t.Fatalf("Fetch failed: %s", err)
	}
	if !reflect.DeepEqual(returnedResp, parsedResp) {
		t.Fatalf("Unexpected response: wanted %s, got %s", parsedResp, returnedResp)
	}

	// no responder, timeout context
	ctx, _ := context.WithTimeout(context.Background(), time.Second*15)
	_, _, _, _, err = Fetch(
		ctx,
		logger,
		[]string{"http://localhost:9999"},
		c,
		req,
		"",
		nil,
	)
	if err == nil {
		t.Fatal("Expected err with bad responder")
	}

	// bad responder, timeout context
	ocspRequest.SerialNumber = big.NewInt(1)
	req, err = ocspRequest.Marshal()
	if err != nil {
		t.Fatalf("ocspRequest.Marshal failed: %s", err)
	}
	ctx, _ = context.WithTimeout(context.Background(), time.Second*15)
	_, _, _, _, err = Fetch(
		ctx,
		logger,
		[]string{"http://localhost:8080"},
		c,
		req,
		"",
		nil,
	)
	if err == nil {
		t.Fatal("Expected err with bad responder")
	}

	// bad responder, stupid retry-after
	ocspRequest.SerialNumber = big.NewInt(2)
	req, err = ocspRequest.Marshal()
	if err != nil {
		t.Fatalf("ocspRequest.Marshal failed: %s", err)
	}
	ctx, _ = context.WithTimeout(context.Background(), time.Second*15)
	_, _, _, _, err = Fetch(
		ctx,
		logger,
		[]string{"http://localhost:8080"},
		c,
		req,
		"",
		nil,
	)
	if err == nil {
		t.Fatal("Expected err with bad responder")
	}

	// bad responder, gibberish response
	ocspRequest.SerialNumber = big.NewInt(3)
	req, err = ocspRequest.Marshal()
	if err != nil {
		t.Fatalf("ocspRequest.Marshal failed: %s", err)
	}
	ctx, _ = context.WithTimeout(context.Background(), time.Second*15)
	_, _, _, _, err = Fetch(
		ctx,
		logger,
		[]string{"http://localhost:8080"},
		c,
		req,
		"",
		nil,
	)
	if err == nil {
		t.Fatal("Expected err with bad responder")
	}

	// bad responder, unauthorized response
	ocspRequest.SerialNumber = big.NewInt(4)
	req, err = ocspRequest.Marshal()
	if err != nil {
		t.Fatalf("ocspRequest.Marshal failed: %s", err)
	}
	fs.response = ocsp.UnauthorizedErrorResponse
	ctx, _ = context.WithTimeout(context.Background(), time.Second*15)
	_, _, _, _, err = Fetch(
		ctx,
		logger,
		[]string{"http://localhost:8080"},
		c,
		req,
		"",
		nil,
	)
	if err == nil {
		t.Fatal("Expected err with bad responder")
	}
}
