// Logic for serving OCSP responses via HTTP
// (should probably use a CFSSL responder with
// a custom Source).

package stapled

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ocsp"
)

// Adapted from https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go
// to log + do stats etc the way we want.
func (s *stapled) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	s.log.Info("[responder] Received request: %s %s %s", req.RemoteAddr, req.Method, req.URL)
	// Read response from request
	var requestBody []byte
	var err error
	switch req.Method {
	case "GET":
		base64Request, err := url.QueryUnescape(req.URL.Path)
		if err != nil {
			s.log.Err("[responder] Error decoding URL: %s", req.URL.Path)
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
		// url.QueryUnescape not only unescapes %2B escaping, but it additionally
		// turns the resulting '+' into a space, which makes base64 decoding fail.
		// So we go back afterwards and turn ' ' back into '+'. This means we
		// accept some malformed input that includes ' ' or %20, but that's fine.
		base64RequestBytes := []byte(base64Request)
		for i := range base64RequestBytes {
			if base64RequestBytes[i] == ' ' {
				base64RequestBytes[i] = '+'
			}
		}
		requestBody, err = base64.StdEncoding.DecodeString(string(base64RequestBytes))
		if err != nil {
			s.log.Err("[responder] Error decoding base64 from URL: %s", base64Request)
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
	case "POST":
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			s.log.Err("[responder] Problem reading body of POST: %s", err)
			resp.WriteHeader(http.StatusBadRequest)
			return
		}
	default:
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	b64Body := base64.StdEncoding.EncodeToString(requestBody)

	// All responses after this point will be OCSP.
	// We could check for the content type of the request, but that
	// seems unnecessariliy restrictive.
	resp.Header().Add("Content-Type", "application/ocsp-response")

	// Parse response as an OCSP request
	// XXX: This fails if the request contains the nonce extension.
	//      We don't intend to support nonces anyway, but maybe we
	//      should return unauthorizedRequest instead of malformed.
	ocspRequest, err := ocsp.ParseRequest(requestBody)
	if err != nil {
		s.log.Err("[responder] Error decoding request body: %s", b64Body)
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write(ocsp.MalformedRequestErrorResponse)
		return
	}

	// Look up OCSP response from source
	response, found := s.c.lookupResponse(ocspRequest)
	if !found {
		s.log.Err("[responder] No response found for request: %s", b64Body)
		resp.Write(ocsp.UnauthorizedErrorResponse)
		return
	}

	resp.WriteHeader(http.StatusOK)
	resp.Write(response)
}

func (s *stapled) initResponder(httpAddr string) {
	m := http.StripPrefix("/", s)
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
