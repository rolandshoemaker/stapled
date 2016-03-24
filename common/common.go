package common

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rolandshoemaker/stapled/log"
)

func HumanDuration(d time.Duration) string {
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

type Failer interface {
	Fail(*log.Logger, string)
}

type BasicFailer struct{}

func (bf *BasicFailer) Fail(logger *log.Logger, msg string) {
	logger.Err(msg)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func randomURL(urls []*url.URL) *url.URL {
	return urls[mrand.Intn(len(urls))]
}

func ProxyFunc(proxies []string) (func(*http.Request) (*url.URL, error), error) {
	proxyURLs := []*url.URL{}
	for _, p := range proxies {
		u, err := url.Parse(p)
		if err != nil {
			return nil, err
		}
		proxyURLs = append(proxyURLs, u)
	}
	return func(*http.Request) (*url.URL, error) {
		return randomURL(proxyURLs), nil
	}, nil
}

// ParseCertificate parses a certificate from either it's PEM
// or DER form
func ParseCertificate(contents []byte) (*x509.Certificate, error) {
	certBytes := []byte{}
	block, _ := pem.Decode(contents)
	if block == nil {
		certBytes = contents
	} else {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Invalid PEM type '%s'", block.Type)
		}
		certBytes = block.Bytes
	}
	return x509.ParseCertificate(certBytes)
}

func ReadCertificate(filename string) (*x509.Certificate, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(contents)
}

func HashNameAndPKI(h hash.Hash, name, pki []byte) ([]byte, []byte, error) {
	h.Write(name)
	nameHash := h.Sum(nil)
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pki, &publicKeyInfo); err != nil {
		return nil, nil, err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	pkiHash := h.Sum(nil)
	return nameHash[:], pkiHash[:], nil
}

func GetIssuer(uri string) (*x509.Certificate, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(body)
}
