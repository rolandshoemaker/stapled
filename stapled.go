package stapled

import (
	"fmt"
	"net/http"
	"sync"
)

type stapled struct {
	log                    *Logger
	c                      *cache
	responder              *http.Server
	dontDieOnStaleResponse bool
}

func New(log *Logger, httpAddr string, dontDieOnStale bool, entries []*Entry) (*stapled, error) {
	c := &cache{make(map[[32]byte]*Entry), make(map[[32]byte]*Entry), new(sync.RWMutex)}
	s := &stapled{log: log, c: c, dontDieOnStaleResponse: dontDieOnStale}
	// add entries to cache
	for _, e := range entries {
		c.add(e)
	}
	// initialize OCSP repsonder
	s.initResponder(httpAddr)
	return s, nil
}

func (s *stapled) Run() error {
	err := s.responder.ListenAndServe()
	if err != nil {
		return fmt.Errorf("HTTP server died: %s", err)
	}
	return nil
}
