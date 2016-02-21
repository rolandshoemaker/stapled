package main

import (
	"fmt"
	"io/ioutil"
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

	logger.Info("Loading definitions")
	entries := []*stapled.Entry{}
	for _, def := range config.Definitions.Certificates {
		ed, err := stapled.CertDefToEntryDef(logger,
			clk,
			timeout,
			baseBackoff,
			config.Disk.CacheFolder,
			config.Fetcher.UpstreamStapleds,
			config.Fetcher.Proxy,
			def,
		)
		if err != nil {
			logger.Err("Failed to parse definition: %s", err)
			os.Exit(1)
		}
		entry, err := stapled.NewEntry(ed)
		if err != nil {
			logger.Err("Failed to create entry: %s", err)
			os.Exit(1)
		}
		entries = append(entries, entry)
	}

	logger.Info("Initializing stapled")
	s, err := stapled.New(logger, clk, config.HTTP.Addr, config.DontDieOnStaleResponse, entries)
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
