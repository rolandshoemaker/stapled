package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	cflog "github.com/cloudflare/cfssl/log"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"golang.org/x/crypto/ocsp"
)

func (s *stapled) Response(r *ocsp.Request) ([]byte, bool) {
	if response, present := s.c.lookupResponse(r); present {
		return response, present
	}
	if len(s.upstreamResponders) == 0 {
		return nil, false
	}

	// this should live in cache.go, EntryFromResponse or something...
	// (although it's already so big :/)
	e := NewEntry(s.log, s.clk, s.clientTimeout, s.clientBackoff, s.entryMonitorTick)
	e.serial = r.SerialNumber
	var err error
	// e.request, err = r.Marshal()
	// if err != nil {
	// 	s.log.Err("Failed to marshal request: %s", err)
	// 	return nil, false
	// }
	e.responders = s.upstreamResponders
	serialHash := sha256.Sum256(e.serial.Bytes())
	key := sha256.Sum256(append(append(r.IssuerNameHash, r.IssuerKeyHash...), serialHash[:]...))
	e.name = fmt.Sprintf("%X", key)
	if s.cacheFolder != "" {
		e.generateResponseFilename(s.cacheFolder)
	}
	err = e.Init()
	if err != nil {
		s.log.Err("Failed to initialize new entry: %s", err)
		return nil, false
	}
	s.c.addSingle(e, key)
	return e.response, true
}

func (s *stapled) initResponder(httpAddr string, logger *Logger) {
	cflog.SetLogger(&responderLogger{logger})
	m := http.StripPrefix("/", cfocsp.NewResponder(s))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// hack to make monitors that just check / returns a 200 are satisfied
		if r.Method == "GET" && r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "max-age=43200") // Cache for 12 hours
			w.WriteHeader(200)
			return
		}
		m.ServeHTTP(w, r)
	})
	s.responder = &http.Server{
		Addr:    httpAddr,
		Handler: h,
	}
}
