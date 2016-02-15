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
		fmt.Println(err)
		os.Exit(1)
	}
	var config stapled.Configuration
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	baseBackoff := time.Second * time.Duration(10)
	timeout := time.Second * time.Duration(10)
	if config.Fetcher.BaseBackoff != "" {
		backoffSeconds, err := time.ParseDuration(config.Fetcher.BaseBackoff)
		if err != nil {
			fmt.Printf("Failed to parse base-backoff: %s\n", err)
			os.Exit(1)
		}
		baseBackoff = time.Second * time.Duration(backoffSeconds)
	}
	if config.Fetcher.Timeout != "" {
		timeoutSeconds, err := time.ParseDuration(config.Fetcher.Timeout)
		if err != nil {
			fmt.Printf("Failed to parse timeout: %s\n", err)
			os.Exit(1)
		}
		timeout = time.Second * time.Duration(timeoutSeconds)
	}

	entries := []*stapled.Entry{}
	for _, def := range config.Definitions.Certificates {
		if def.Certificate == "" && def.Serial == "" {
			fmt.Println("Either 'certificate' or 'serial' are required")
			os.Exit(1)
		}
		var cert *x509.Certificate

		var issuer *x509.Certificate
		responders := []string{}
		serial := big.NewInt(0)

		if def.Serial != "" {
			serialBytes, err := hex.DecodeString(def.Serial)
			if err != nil {
				fmt.Printf("Failed to decode serial '%s': %s\n", def.Serial, err)
				os.Exit(1)
			}
			serial = serial.SetBytes(serialBytes)
		} else {
			certContents, err := ioutil.ReadFile(def.Certificate)
			if err != nil {
				fmt.Printf("Failed to read certificate '%s': %s\n", def.Certificate, err)
				os.Exit(1)
			}
			cert, err = x509.ParseCertificate(certContents)
			if err != nil {
				fmt.Printf("Failed to parse certificate '%s': %s\n", def.Certificate, err)
				os.Exit(1)
			}
			serial = cert.SerialNumber
			responders = cert.OCSPServer
		}
		fmt.Println(def)
		if def.Issuer != "" {
			issuerContents, err := ioutil.ReadFile(def.Issuer)
			if err != nil {
				fmt.Printf("Failed to read issuer '%s': %s\n", def.Issuer, err)
				os.Exit(1)
			}
			issuer, err = x509.ParseCertificate(issuerContents)
			if err != nil {
				fmt.Printf("Failed to parse issuer '%s': %s\n", def.Issuer, err)
			}
		} else if cert != nil {
			if len(cert.IssuingCertificateURL) == 0 {
				fmt.Println("issuer can only be ommited if the certificate contains AIA information about its issuer")
			}
			for _, issuerURL := range cert.IssuingCertificateURL {
				// this should be its own function
				resp, err := http.Get(issuerURL)
				if err != nil {
					fmt.Println("Failed to retrieve issuer from '%s': %s\n", issuerURL, err)
					continue
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("Failed to read issuer body from '%s': %s\n", issuerURL, err)
					continue
				}
				issuer, err = x509.ParseCertificate(body)
				if err != nil {
					fmt.Printf("Failed to parse issuer body from '%s': %s\n", issuerURL, err)
					continue
				}
			}
		} else {
			fmt.Println("issuer can only be ommited if the certificate contains AIA information about its issuer")
			os.Exit(1)
		}
		if issuer == nil {
			fmt.Println("unable to retrieve issuer")
			os.Exit(1)
		}

		if len(def.Responders) > 0 {
			responders = def.Responders
		}
		if len(config.Fetcher.UpstreamStapleds) > 0 && !def.OverrideUpstream {
			responders = config.Fetcher.UpstreamStapleds
		}
		if len(responders) == 0 {
			fmt.Println("no responders provided")
			os.Exit(1)
		}
		var proxyFunc func(*http.Request) (*url.URL, error)
		if config.Fetcher.Proxy != "" {
			proxyURL, err := url.Parse(config.Fetcher.Proxy)
			if err != nil {
				fmt.Printf("Failed to parse proxy URL: %s\n", err)
				os.Exit(1)
			}
			proxyFunc = http.ProxyURL(proxyURL)
		}
		entry, err := stapled.NewEntry(nil, issuer, serial, responders, timeout, baseBackoff, proxyFunc)
		if err != nil {
			fmt.Printf("Failed to create entry: %s\n", err)
			os.Exit(1)
		}
		entries = append(entries, entry)
	}

	s, err := stapled.New(config.HTTP.Addr, config.DontDieOnStaleResponse, entries)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = s.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
