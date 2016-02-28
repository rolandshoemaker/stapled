package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

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
	var config Configuration
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse configuration file: %s", err)
		os.Exit(1)
	}

	clk := clock.Default()
	logger := NewLogger(config.Syslog.Network, config.Syslog.Addr, config.Syslog.StdoutLevel, clk)

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

	logger.Info("Loading definitions")
	entries := []*Entry{}
	for _, def := range config.Definitions.Certificates {
		e := NewEntry(logger, clk, timeout, baseBackoff, 1*time.Minute)
		err = e.FromCertDef(def, config.Fetcher.UpstreamResponders, config.Fetcher.Proxy, config.Disk.CacheFolder)
		if err != nil {
			logger.Err("Failed to populate entry: %s", err)
			os.Exit(1)
		}
		err = e.Init()
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
		baseBackoff,
		1*time.Minute,
		config.Fetcher.UpstreamResponders,
		config.Disk.CacheFolder,
		config.DontDieOnStaleResponse,
		config.Definitions.CertWatchFolder,
		entries,
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
