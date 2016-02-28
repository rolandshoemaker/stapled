// Logic for serving OCSP responses via HTTP
// (should probably use a CFSSL responder with
// a custom Source).

package stapled

import (
	"net/http"

	cflog "github.com/cloudflare/cfssl/log"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"golang.org/x/crypto/ocsp"
)

func (s *stapled) Response(r *ocsp.Request) ([]byte, bool) {
	return s.c.lookupResponse(r)
}

func (s *stapled) initResponder(httpAddr string, logger *Logger) {
	cflog.SetLogger(&responderLogger{logger})
	m := http.StripPrefix("/", cfocsp.NewResponder(s))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
