package main

import (
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
	"github.com/rolandshoemaker/stapled/log"
	"github.com/rolandshoemaker/stapled/stableCache"
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
	var config Configuration
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse configuration file: %s", err)
		os.Exit(1)
	}

	clk := clock.Default()
	logger := log.NewLogger(config.Syslog.Network, config.Syslog.Addr, config.Syslog.StdoutLevel, clk)

	timeout := time.Second * time.Duration(10)
	if config.Fetcher.Timeout != "" {
		timeoutSeconds, err := time.ParseDuration(config.Fetcher.Timeout)
		if err != nil {
			logger.Err("Failed to parse timeout: %s", err)
			os.Exit(1)
		}
		timeout = time.Second * time.Duration(timeoutSeconds)
	}

	client := new(http.Client)
	if len(config.Fetcher.Proxies) != 0 {
		proxyFunc, err := common.ProxyFunc(config.Fetcher.Proxies)
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

	stableBackings := []stableCache.Cache{}
	if config.Disk.CacheFolder != "" {
		stableBackings = append(stableBackings, stableCache.NewDisk(logger, clk, config.Disk.CacheFolder))
	}

	logger.Info("Loading definitions")
	entries := []*Entry{}
	for _, def := range config.Definitions.Certificates {
		e := NewEntry(logger, clk, timeout)
		err = e.FromCertDef(def, config.Fetcher.UpstreamResponders)
		if err != nil {
			logger.Err("Failed to populate entry: %s", err)
			os.Exit(1)
		}
		err = e.Init(stableBackings, client)
		if err != nil {
			logger.Err("Failed to initialize entry: %s", err)
			os.Exit(1)
		}
		entries = append(entries, e)
	}

	logger.Info("Initializing stapled")
	s, err := New(
		logger,
		clk,
		config.HTTP.Addr,
		timeout,
		1*time.Minute,
		config.Fetcher.UpstreamResponders,
		config.DontDieOnStaleResponse,
		config.Definitions.CertWatchFolder,
		entries,
		stableBackings,
		client,
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
