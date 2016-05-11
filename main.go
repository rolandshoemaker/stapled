package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/yaml.v2"

	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/config"
	"github.com/rolandshoemaker/stapled/log"
	"github.com/rolandshoemaker/stapled/mcache"
	"github.com/rolandshoemaker/stapled/scache"
)

func main() {
	var configFilename string

	flag.StringVar(&configFilename, "config", "example.yaml", "YAML configuration file")
	flag.Parse()

	configBytes, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read configuration file '%s': %s", configFilename, err)
		os.Exit(1)
	}
	var conf config.Configuration
	err = yaml.Unmarshal(configBytes, &conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse configuration file: %s", err)
		os.Exit(1)
	}

	clk := clock.Default()
	logger := log.NewLogger(conf.Syslog.Network, conf.Syslog.Addr, conf.Syslog.StdoutLevel, clk)

	timeout := time.Second * time.Duration(10)
	if conf.Fetcher.Timeout.Duration != 0 {
		timeout = conf.Fetcher.Timeout.Duration
	}

	client := new(http.Client)
	if len(conf.Fetcher.Proxies) != 0 {
		proxyFunc, err := common.ProxyFunc(conf.Fetcher.Proxies)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parsed proxy URI: %s", err)
		}
		client.Transport = &http.Transport{
			Proxy: proxyFunc,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}

	stableBackings := []scache.Cache{}
	if conf.Disk.CacheFolder != "" {
		stableBackings = append(stableBackings, scache.NewDisk(logger, clk, conf.Disk.CacheFolder))
	}

	issuers := []*x509.Certificate{}
	if conf.Definitions.IssuerFolder != "" {
		files, err := ioutil.ReadDir(conf.Definitions.IssuerFolder)
		if err != nil {
			logger.Err("Failed to read directory '%s': %s", conf.Definitions.IssuerFolder, err)
			os.Exit(1)
		}
		for _, fi := range files {
			if fi.IsDir() {
				continue
			}
			issuer, err := common.ReadCertificate(fi.Name())
			if err != nil {
				logger.Err("Failed to read issuer '%s': %s", fi.Name(), err)
				continue
			}
			issuers = append(issuers, issuer)
		}
	}

	c := mcache.NewEntryCache(clk, logger, 1*time.Minute, stableBackings, client, timeout, issuers)

	logger.Info("Loading certificates")
	for _, def := range conf.Definitions.Certificates {
		var issuer *x509.Certificate
		var responders []string
		if def.Issuer != "" {
			issuer, err = common.ReadCertificate(def.Issuer)
			if err != nil {
				logger.Err("Failed to load issuer '%s': %s", def.Issuer, err)
				os.Exit(1)
			}
		}
		err = c.AddFromCertificate(def.Certificate, issuer, responders)
		if err != nil {
			logger.Err("Failed to load entry: %s", err)
			os.Exit(1)
		}
	}

	logger.Info("Initializing stapled")
	s, err := New(
		c,
		logger,
		clk,
		conf.HTTP.Addr,
		conf.Fetcher.UpstreamResponders,
		conf.Definitions.CertWatchFolder,
	)
	if err != nil {
		logger.Err("Failed to initialize stapled: %s", err)
		os.Exit(1)
	}

	logger.Info("Running stapled")
	err = s.Run()
	if err != nil {
		logger.Err("stapled failed: %s", err)
		os.Exit(1)
	}
}
