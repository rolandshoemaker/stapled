package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/config"
	"github.com/rolandshoemaker/stapled/log"
	stapledOCSP "github.com/rolandshoemaker/stapled/ocsp"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
)

type lookupEntry struct {
	name     string
	filename string
	log      *log.Logger
	clk      clock.Clock

	serial     *big.Int
	issuer     *x509.Certificate
	responders []string

	timeout time.Duration
	request []byte
}

var defaultIssuer *x509.Certificate
var client *http.Client

func newEntry(filename string, timeout time.Duration, logger *log.Logger, clk clock.Clock) (*lookupEntry, error) {
	e := &lookupEntry{
		filename: filename,
		timeout:  timeout,
		log:      logger,
		clk:      clk,
	}

	e.name = strings.TrimSuffix(
		filepath.Base(filename),
		filepath.Ext(filename),
	)

	cert, err := common.ReadCertificate(e.filename)

	if err != nil {
		return nil, err
	}

	e.serial = cert.SerialNumber
	e.responders = cert.OCSPServer

	e.issuer = defaultIssuer
	if e.issuer == nil {
		// fetch from AIA
		for _, issuerURL := range cert.IssuingCertificateURL {
			e.log.Info("Fetching issuer from %s", issuerURL)
			e.issuer, err = common.GetIssuer(issuerURL)
			if err != nil {
				e.log.Err("Failed to retrieve issuer from '%s': %s", issuerURL, err)
				continue
			}
			break
		}
	}

	return e, nil
}

func (e *lookupEntry) fetchResponse() error {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	if e.issuer == nil {
		return errors.New("entry must have non-nil issuer")
	}
	if e.request == nil {
		issuerNameHash, issuerKeyHash, err := common.HashNameAndPKI(
			crypto.SHA1.New(),
			e.issuer.RawSubject,
			e.issuer.RawSubjectPublicKeyInfo,
		)
		if err != nil {
			return err
		}
		ocspRequest := &ocsp.Request{
			HashAlgorithm:  crypto.SHA1,
			IssuerNameHash: issuerNameHash,
			IssuerKeyHash:  issuerKeyHash,
			SerialNumber:   e.serial,
		}
		e.request, err = ocspRequest.Marshal()
		if err != nil {
			return err
		}
	}
	for i := range e.responders {
		e.responders[i] = strings.TrimSuffix(e.responders[i], "/")
	}

	resp, _, _, _, err := stapledOCSP.Fetch(
		ctx,
		e.log,
		e.responders,
		client,
		e.request,
		"",
		e.issuer,
	)

	if err != nil {
		return err
	}

	if resp == nil {
		return errors.New("response was nil")
	}

	err = stapledOCSP.VerifyResponse(e.clk.Now(), e.serial, resp)
	if err != nil {
		return err
	}

	fmt.Printf("Cert: %s\n", e.name)
	fmt.Printf("Good response:\n")
	fmt.Printf("  Status %d\n", resp.Status)
	fmt.Printf("  SerialNumber %036x\n", resp.SerialNumber)
	fmt.Printf("  ProducedAt %s\n", resp.ProducedAt)
	fmt.Printf("  ThisUpdate %s\n", resp.NextUpdate)
	fmt.Printf("  NextUpdate %s\n", resp.NextUpdate)
	fmt.Printf("  RevokedAt %s\n", resp.RevokedAt)
	fmt.Printf("  RevocationReason %d\n", resp.RevocationReason)
	fmt.Printf("  SignatureAlgorithm %s\n", resp.SignatureAlgorithm)
	fmt.Printf("  Extensions %#v\n", resp.Extensions)
	return nil
}

func main() {
	var conf config.Configuration
	var err error
	var issuerFilename string
	var timeoutSeconds time.Duration

	flag.StringVar(&issuerFilename, "issuer", "", "PEM/DER encoded issuer file")
	flag.DurationVar(&timeoutSeconds, "timeout", 5*time.Second, "Max # of seconds before a request times out")
	flag.Parse()

	clk := clock.Default()
	logger := log.NewLogger(conf.Syslog.Network, conf.Syslog.Addr, conf.Syslog.StdoutLevel, clk)

	if strings.TrimSpace(issuerFilename) != "" {
		defaultIssuer, err = common.ReadCertificate(issuerFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse issuer certificate file: %s\n", err)
			return
		}
	}

	client = new(http.Client)

	for _, f := range flag.Args() {
		e, err := newEntry(f, timeoutSeconds, logger, clk)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to setup OCSP request for %s: %s\n", f, err)
			return
		}

		err = e.fetchResponse()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to query OCSP for %s: %s\n", e.name, err)
			return
		}
	}
}
