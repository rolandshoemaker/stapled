package stapled

import (
	"fmt"
	"net/http"

	"github.com/jmhodges/clock"
)

type stapled struct {
	log                    *Logger
	clk                    clock.Clock
	c                      *cache
	responder              *http.Server
	dontDieOnStaleResponse bool
}

func New(log *Logger, clk clock.Clock, httpAddr string, dontDieOnStale bool, entries []*Entry) (*stapled, error) {
	c := newCache(log)
	s := &stapled{log: log, clk: clk, c: c, dontDieOnStaleResponse: dontDieOnStale}
	// add entries to cache
	for _, e := range entries {
		c.add(e)
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
