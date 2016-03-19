package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jmhodges/clock"

	"github.com/rolandshoemaker/stapled/log"
	"github.com/rolandshoemaker/stapled/memCache"
)

type stapled struct {
	log                *log.Logger
	clk                clock.Clock
	c                  *memCache.EntryCache
	responder          *http.Server
	certFolderWatcher  *dirWatcher
	client             *http.Client
	entryMonitorTick   time.Duration
	upstreamResponders []string
}

func New(c *memCache.EntryCache, logger *log.Logger, clk clock.Clock, httpAddr string, responders []string, certFolder string) (*stapled, error) {
	s := &stapled{
		log:                logger,
		clk:                clk,
		c:                  c,
		upstreamResponders: responders,
		certFolderWatcher:  newDirWatcher(certFolder),
	}
	s.initResponder(httpAddr, logger)
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
		err = s.c.AddFromCertificate(a, nil, s.upstreamResponders)
		if err != nil {
			s.log.Err("Failed to add entry to cache for new certificate '%s': %s", a, err)
		}
	}
	for _, r := range removed {
		s.c.Remove(r)
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
