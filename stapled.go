package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jmhodges/clock"

	"github.com/rolandshoemaker/stapled/log"
	"github.com/rolandshoemaker/stapled/memCache"
	"github.com/rolandshoemaker/stapled/stableCache"
)

type stapled struct {
	log                *log.Logger
	clk                clock.Clock
	c                  *memCache.EntryCache
	responder          *http.Server
	certFolderWatcher  *dirWatcher
	stableBackings     []stableCache.Cache
	client             *http.Client
	clientTimeout      time.Duration
	entryMonitorTick   time.Duration
	upstreamResponders []string
}

func New(log *log.Logger, clk clock.Clock, httpAddr string, timeout, monitorTick time.Duration, responders []string, dontDieOnStale bool, certFolder string, entries []*memCache.Entry, stableBackings []stableCache.Cache, client *http.Client) (*stapled, error) {
	c := memCache.NewEntryCache(log, monitorTick, stableBackings, client)
	s := &stapled{
		log:                log,
		clk:                clk,
		c:                  c,
		clientTimeout:      timeout,
		upstreamResponders: responders,
		certFolderWatcher:  newDirWatcher(certFolder),
		stableBackings:     stableBackings,
		client:             client,
	}
	// add entries to cache
	for _, e := range entries {
		c.addMulti(e)
	}
	// initialize OCSP repsonder
	s.initResponder(httpAddr, log)
	return s, nil
}

// this should probably live on cache
func (s *stapled) checkCertDirectory() {
	added, removed, err := s.certFolderWatcher.check()
	if err != nil {
		// log
		s.log.Err("Failed to poll certificate directory: %s", err)
		return
	}
	for _, a := range added {
		// create entry + add to cache
		e := memCache.NewEntry(s.log, s.clk, s.clientTimeout)
		err = e.loadCertificate(a)
		if err != nil {
			s.log.Err("Failed to load new certificate '%s': %s", a, err)
			continue
		}
		err = e.Init(s.c.StableBackings, s.client)
		if err != nil {
			s.log.Err("Failed to initialize entry for new certificate '%s': %s", a, err)
			continue
		}
		err = s.c.addMulti(e)
		if err != nil {
			s.log.Err("Failed to add entry to cache for new certificate '%s': %s", a, err)
		}
	}
	for _, r := range removed {
		s.c.remove(r)
	}
}

func (s *stapled) watchCertDirectory() {
	ticker := time.NewTicker(time.Second * 15)
	for _ = range ticker.C {
		s.checkCertDirectory()
	}
}

func (s *stapled) Run() error {
	if s.certFolderWatcher != nil {
		s.checkCertDirectory()
		go s.watchCertDirectory()
	}
	err := s.responder.ListenAndServe()
	if err != nil {
		return fmt.Errorf("HTTP server died: %s", err)
	}
	return nil
}
