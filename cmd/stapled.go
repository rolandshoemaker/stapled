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

	logger := stapled.NewLogger(config.Syslog.Network, config.Syslog.Addr, config.Syslog.Level)

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
		if def.Certificate == "" && def.Serial == "" {
			logger.Err("Either 'certificate' or 'serial' are required")
			os.Exit(1)
		}
		var cert *x509.Certificate

		var issuer *x509.Certificate
		responders := []string{}
		serial := big.NewInt(0)

		if def.Serial != "" {
			serialBytes, err := hex.DecodeString(def.Serial)
			if err != nil {
				logger.Err("Failed to decode serial '%s': %s", def.Serial, err)
				os.Exit(1)
			}
			serial = serial.SetBytes(serialBytes)
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
			serial = cert.SerialNumber
			responders = cert.OCSPServer
		}
		if def.Issuer != "" {
			issuerContents, err := ioutil.ReadFile(def.Issuer)
			if err != nil {
				logger.Err("Failed to read issuer '%s': %s", def.Issuer, err)
				os.Exit(1)
			}
			issuer, err = stapled.ParseCertificate(issuerContents)
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
				issuer, err = stapled.ParseCertificate(body)
				if err != nil {
					logger.Err("Failed to parse issuer body from '%s': %s", issuerURL, err)
					continue
				}
			}
		} else {
			logger.Err("issuer can only be ommited if the certificate contains AIA information about its issuer")
			os.Exit(1)
		}
		if issuer == nil {
			logger.Err("Unable to retrieve issuer")
			os.Exit(1)
		}

		if len(def.Responders) > 0 {
			responders = def.Responders
		}
		if len(config.Fetcher.UpstreamStapleds) > 0 && !def.OverrideUpstream {
			responders = config.Fetcher.UpstreamStapleds
		}
		if len(responders) == 0 {
			logger.Err("No responders provided")
			os.Exit(1)
		}
		var proxyFunc func(*http.Request) (*url.URL, error)
		if config.Fetcher.Proxy != "" {
			proxyURL, err := url.Parse(config.Fetcher.Proxy)
			if err != nil {
				logger.Err("Failed to parse proxy URL: %s", err)
				os.Exit(1)
			}
			proxyFunc = http.ProxyURL(proxyURL)
		}
		entry, err := stapled.NewEntry(logger, nil, issuer, serial, responders, timeout, baseBackoff, proxyFunc)
		if err != nil {
			logger.Err("Failed to create entry: %s", err)
			os.Exit(1)
		}
		entries = append(entries, entry)
	}

	s, err := stapled.New(logger, config.HTTP.Addr, config.DontDieOnStaleResponse, entries)
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
