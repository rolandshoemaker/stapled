package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jmhodges/clock"
)

type stapled struct {
	log               *Logger
	clk               clock.Clock
	c                 *cache
	responder         *http.Server
	certFolderWatcher *dirWatcher

	clientTimeout          time.Duration
	clientBackoff          time.Duration
	entryMonitorTick       time.Duration
	upstreamResponders     []string
	cacheFolder            string
	dontDieOnStaleResponse bool
}

func New(log *Logger, clk clock.Clock, httpAddr string, timeout, backoff, monitorTick time.Duration, responders []string, cacheFolder string, dontDieOnStale bool, certFolder string, entries []*Entry) (*stapled, error) {
	c := newCache(log, monitorTick)
	s := &stapled{
		log:                    log,
		clk:                    clk,
		c:                      c,
		clientTimeout:          timeout,
		clientBackoff:          backoff,
		cacheFolder:            cacheFolder,
		dontDieOnStaleResponse: dontDieOnStale,
		upstreamResponders:     responders,
		certFolderWatcher:      newDirWatcher(certFolder),
	}
	// add entries to cache
	for _, e := range entries {
		c.addMulti(e)
	}
	// initialize OCSP repsonder
	s.initResponder(httpAddr, log)
	return s, nil
}

func (s *stapled) checkCertDirectory() {
	added, removed, err := s.certFolderWatcher.check()
	if err != nil {
		// log
		s.log.Err("Failed to poll certificate directory: %s", err)
		return
	}
	for _, a := range added {
		// create entry + add to cache
		e := NewEntry(s.log, s.clk, s.clientTimeout, s.clientBackoff)
		err = e.loadCertificate(a)
		if err != nil {
			s.log.Err("Failed to load new certificate '%s': %s", a, err)
			continue
		}
		if s.cacheFolder != "" {
			e.generateResponseFilename(s.cacheFolder)
		}
		err = e.Init()
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
