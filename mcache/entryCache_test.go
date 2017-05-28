package mcache

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/rolandshoemaker/stapled/common"

	"github.com/rolandshoemaker/stapled/log"
)

var everyHash = []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}

func TestEntryCache(t *testing.T) {
	fc := clock.NewFake()
	c := NewEntryCache(fc, log.NewLogger("", "", 10, fc), time.Minute, nil, new(http.Client), time.Minute, nil, everyHash, true)

	issuer, err := common.ReadCertificate("../testdata/test-issuer.der")
	if err != nil {
		t.Fatalf("Failed to read test issuer: %s", err)
	}
	e := &Entry{
		mu:       new(sync.RWMutex),
		name:     "test.der",
		serial:   big.NewInt(1337),
		issuer:   issuer,
		response: []byte{5, 0, 1},
	}

	err = c.add(e)
	if err != nil {
		t.Fatalf("Failed to add entry to cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := common.HashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("Failed to hash subject and public key info: %s", err)
		}
		req := &ocsp.Request{h, nameHash, pkHash, e.serial}
		foundEntry, present := c.lookup(req)
		if !present {
			t.Fatal("Didn't find entry that should be in cache")
		}
		if foundEntry != e {
			t.Fatal("Cache returned wrong entry")
		}
		response, present := c.LookupResponse(req)
		if !present {
			t.Fatal("Didn't find response that should be in cache")
		}
		if bytes.Compare(response, e.response) != 0 {
			t.Fatal("Cache returned wrong response")
		}
	}

	err = c.Remove("test.der")
	if err != nil {
		t.Fatalf("Failed to remove entry from cache: %s", err)
	}

	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		nameHash, pkHash, err := common.HashNameAndPKI(h.New(), issuer.RawSubject, issuer.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatalf("Failed to hash subject and public key info: %s", err)
		}
		_, present := c.lookup(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found entry that should've been removed from cache")
		}
		_, present = c.LookupResponse(&ocsp.Request{h, nameHash, pkHash, e.serial})
		if present {
			t.Fatal("Found response that should've been removed from cache")
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %s", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hi"},
		SubjectKeyId: []byte{0, 1},
	}
	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %s", err)
	}
	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %s", err)
	}
	tf, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("ioutil.TempFile failed: %s", err)
	}
	defer tf.Close()
	_, err = tf.Write(cert)
	if err != nil {
		t.Fatalf("tf.Write failed: %s", err)
	}

	ocspResponse := ocsp.Response{
		SerialNumber: big.NewInt(1),
		Status:       ocsp.Good,
		NextUpdate:   fc.Now().Add(time.Hour),
	}
	response, err := ocsp.CreateResponse(
		parsedCert,
		parsedCert,
		ocspResponse,
		key,
	)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse failed: %s", err)
	}

	br := basicResponder{response}
	http.HandleFunc("/", br.basicFetchHandler)
	go func() {
		err := http.ListenAndServe("localhost:8080", nil)
		if err != nil {
			t.Fatalf("HTTP test server failed: %s", err)
		}
	}()

	err = c.AddFromCertificate(tf.Name(), parsedCert, []string{"http://localhost:8080"})
	if err != nil {
		t.Fatalf("c.AddFromCertificate failed: %s", err)
	}

	for _, e := range c.entries {
		err = e.refreshResponse(context.Background(), nil, new(http.Client))
		if err != nil {
			t.Fatalf("e.refreshResponse failed: %s", err)
		}
	}

	fc.Add(time.Hour * 5)
	for _, e := range c.entries {
		err = e.refreshResponse(context.Background(), nil, new(http.Client))
		if err == nil {
			t.Fatal("e.refreshResponse didn't fail with stale repsonse")
		}
	}

	ocspResponse.NextUpdate = fc.Now().Add(time.Hour * 24)
	response, err = ocsp.CreateResponse(
		parsedCert,
		parsedCert,
		ocspResponse,
		key,
	)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse failed: %s", err)
	}
	br.response = response
	for _, e := range c.entries {
		err = e.refreshResponse(context.Background(), nil, new(http.Client))
		if err != nil {
			t.Fatalf("e.refreshResponse failed: %s", err)
		}
	}

	certTemplate.SerialNumber = big.NewInt(2)
	certTemplate.AuthorityKeyId = []byte{0, 1}
	otherCert, err := x509.CreateCertificate(rand.Reader, certTemplate, parsedCert, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %s", err)
	}
	otf, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("ioutil.TempFile failed: %s", err)
	}
	defer otf.Close()
	_, err = otf.Write(otherCert)
	if err != nil {
		t.Fatalf("tf.Write failed: %s", err)
	}
	ocspResponse.SerialNumber = big.NewInt(2)
	response, err = ocsp.CreateResponse(
		parsedCert,
		parsedCert,
		ocspResponse,
		key,
	)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse failed: %s", err)
	}
	br.response = response

	err = c.AddFromCertificate(otf.Name(), nil, []string{"http://localhost:8080"})
	if err != nil {
		t.Fatalf("c.AddFromCertificate failed: %s", err)
	}

	certTemplate.SerialNumber = big.NewInt(3)
	certTemplate.AuthorityKeyId = []byte{1, 2}
	certTemplate.IssuingCertificateURL = []string{"http://localhost:8081"}
	otherOtherCert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %s", err)
	}
	otherOtherParsedCert, err := x509.ParseCertificate(otherOtherCert)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %s", err)
	}
	ootf, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatalf("ioutil.TempFile failed: %s", err)
	}
	defer ootf.Close()
	_, err = ootf.Write(otherOtherCert)
	if err != nil {
		t.Fatalf("tf.Write failed: %s", err)
	}
	ocspResponse.SerialNumber = big.NewInt(3)
	response, err = ocsp.CreateResponse(
		otherOtherParsedCert,
		otherOtherParsedCert,
		ocspResponse,
		key,
	)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse failed: %s", err)
	}
	br.response = response

	as := &aiaServer{otherOtherCert}
	asSrv := http.Server{Addr: "localhost:8081", Handler: as}
	go func() {
		err := asSrv.ListenAndServe()
		if err != nil {
			t.Fatalf("HTTP test server failed: %s", err)
		}
	}()

	err = c.AddFromCertificate(ootf.Name(), nil, []string{"http://localhost:8080"})
	if err != nil {
		t.Fatalf("c.AddFromCertificate failed: %s", err)
	}
}

type aiaServer struct {
	cert []byte
}

func (as *aiaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(as.cert)
}

type basicResponder struct {
	response []byte
}

func (br *basicResponder) basicFetchHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(br.response)
}
