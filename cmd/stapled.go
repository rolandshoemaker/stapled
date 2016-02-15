package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rolandshoemaker/stapled"

	"github.com/jmhodges/clock"
	"gopkg.in/yaml.v2"
)

func main() {
	configFilename := "example.yaml"

	configBytes, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read configuration file '%s': %s", configFilename, err)
		os.Exit(1)
	}
	var config stapled.Configuration
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse configuration file: %s", err)
		os.Exit(1)
	}

	clk := clock.Default()
	logger := stapled.NewLogger(config.Syslog.Network, config.Syslog.Addr, config.Syslog.StdoutLevel, clk)

	baseBackoff := time.Second * time.Duration(10)
	timeout := time.Second * time.Duration(10)
	if config.Fetcher.BaseBackoff != "" {
		backoffSeconds, err := time.ParseDuration(config.Fetcher.BaseBackoff)
		if err != nil {
			logger.Err("Failed to parse base-backoff: %s", err)
			os.Exit(1)
		}
		baseBackoff = time.Second * time.Duration(backoffSeconds)
	}
	if config.Fetcher.Timeout != "" {
		timeoutSeconds, err := time.ParseDuration(config.Fetcher.Timeout)
		if err != nil {
			logger.Err("Failed to parse timeout: %s", err)
			os.Exit(1)
		}
		timeout = time.Second * time.Duration(timeoutSeconds)
	}

	entries := []*stapled.Entry{}
	for _, def := range config.Definitions.Certificates {
		ed := stapled.EntryDefinition{
			Log:         logger,
			Clk:         clk,
			Timeout:     timeout,
			Backoff:     baseBackoff,
			Serial:      big.NewInt(0),
			CacheFolder: config.Disk.CacheFolder,
		}
		if def.Certificate == "" && def.Serial == "" {
			logger.Err("Either 'certificate' or 'serial' are required")
			os.Exit(1)
		}
		var cert *x509.Certificate

		if def.Serial != "" {
			serialBytes, err := hex.DecodeString(def.Serial)
			if err != nil {
				logger.Err("Failed to decode serial '%s': %s", def.Serial, err)
				os.Exit(1)
			}
			ed.Serial = ed.Serial.SetBytes(serialBytes)
		} else {
			certContents, err := ioutil.ReadFile(def.Certificate)
			if err != nil {
				logger.Err("Failed to read certificate '%s': %s", def.Certificate, err)
				os.Exit(1)
			}
			cert, err = stapled.ParseCertificate(certContents)
			if err != nil {
				logger.Err("Failed to parse certificate '%s': %s", def.Certificate, err)
				os.Exit(1)
			}
			ed.Serial = cert.SerialNumber
			ed.Responders = cert.OCSPServer
		}
		if def.Issuer != "" {
			issuerContents, err := ioutil.ReadFile(def.Issuer)
			if err != nil {
				logger.Err("Failed to read issuer '%s': %s", def.Issuer, err)
				os.Exit(1)
			}
			ed.Issuer, err = stapled.ParseCertificate(issuerContents)
			if err != nil {
				logger.Err("Failed to parse issuer '%s': %s", def.Issuer, err)
				os.Exit(1)
			}
		} else if cert != nil {
			if len(cert.IssuingCertificateURL) == 0 {
				logger.Err("issuer can only be ommited if the certificate contains AIA information about its issuer")
				os.Exit(1)
			}
			for _, issuerURL := range cert.IssuingCertificateURL {
				// this should be its own function
				resp, err := http.Get(issuerURL)
				if err != nil {
					logger.Err("Failed to retrieve issuer from '%s': %s", issuerURL, err)
					continue
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					logger.Err("Failed to read issuer body from '%s': %s", issuerURL, err)
					continue
				}
				ed.Issuer, err = stapled.ParseCertificate(body)
				if err != nil {
					logger.Err("Failed to parse issuer body from '%s': %s", issuerURL, err)
					continue
				}
			}
		} else {
			logger.Err("issuer can only be ommited if the certificate contains AIA information about its issuer")
			os.Exit(1)
		}
		if ed.Issuer == nil {
			logger.Err("Unable to retrieve issuer")
			os.Exit(1)
		}

		if len(def.Responders) > 0 {
			ed.Responders = def.Responders
		}
		if len(config.Fetcher.UpstreamStapleds) > 0 && !def.OverrideUpstream {
			ed.Responders = config.Fetcher.UpstreamStapleds
		}
		if len(ed.Responders) == 0 {
			logger.Err("No responders provided")
			os.Exit(1)
		}
		if config.Fetcher.Proxy != "" {
			proxyURL, err := url.Parse(config.Fetcher.Proxy)
			if err != nil {
				logger.Err("Failed to parse proxy URL: %s", err)
				os.Exit(1)
			}
			ed.Proxy = http.ProxyURL(proxyURL)
		}
		entry, err := stapled.NewEntry(ed)
		if err != nil {
			logger.Err("Failed to create entry: %s", err)
			os.Exit(1)
		}
		entries = append(entries, entry)
	}

	s, err := stapled.New(logger, clk, config.HTTP.Addr, config.DontDieOnStaleResponse, entries)
	if err != nil {
		logger.Err("Failed to initialize stapled: %s", err)
		os.Exit(1)
	}

	err = s.Run()
	if err != nil {
		logger.Err("stapled failed: %s", err)
		os.Exit(1)
	}
}
