package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jmhodges/clock"
)

type stapled struct {
	log                    *Logger
	clk                    clock.Clock
	c                      *cache
	responder              *http.Server
	clientTimeout          time.Duration
	clientBackoff          time.Duration
	entryMonitorTick       time.Duration
	upstreamResponders     []string
	cacheFolder            string
	dontDieOnStaleResponse bool
}

func New(log *Logger, clk clock.Clock, httpAddr string, timeout, backoff, entryMonitorTick time.Duration, responders []string, cacheFolder string, dontDieOnStale bool, entries []*Entry) (*stapled, error) {
	c := newCache(log)
	s := &stapled{
		log:                    log,
		clk:                    clk,
		c:                      c,
		clientTimeout:          timeout,
		clientBackoff:          backoff,
		entryMonitorTick:       entryMonitorTick,
		cacheFolder:            cacheFolder,
		dontDieOnStaleResponse: dontDieOnStale,
		upstreamResponders:     responders,
	}
	// add entries to cache
	for _, e := range entries {
		c.addMulti(e)
	}
	// initialize OCSP repsonder
	s.initResponder(httpAddr, log)
	return s, nil
}

func (s *stapled) Run() error {
	err := s.responder.ListenAndServe()
	if err != nil {
		return fmt.Errorf("HTTP server died: %s", err)
	}
	return nil
}
