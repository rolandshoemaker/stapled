package main

import (
	"net/http"

	cflog "github.com/cloudflare/cfssl/log"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"golang.org/x/crypto/ocsp"

	"github.com/rolandshoemaker/stapled/log"
)

func (s *stapled) Response(r *ocsp.Request) ([]byte, bool) {
	if response, present := s.c.LookupResponse(r); present {
		return response, present
	}
	if len(s.upstreamResponders) == 0 {
		return nil, false
	}

	response, err := s.c.AddFromRequest(r, s.upstreamResponders)
	if err != nil {
		s.log.Err("Failed to add entry to cache from request: %s", err)
		return nil, false
	}
	return response, true
}

func (s *stapled) initResponder(httpAddr string, logger *log.Logger) {
	cflog.SetLogger(&log.ResponderLogger{logger})
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
