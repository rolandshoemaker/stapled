package ocsp

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
)

func humanDuration(d time.Duration) string {
	maybePluralize := func(input string, num int) string {
		if num == 1 {
			return input
		}
		return input + "s"
	}
	nanos := time.Duration(d.Nanoseconds())
	days := int(nanos / (time.Hour * 24))
	nanos %= time.Hour * 24
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds := int(nanos / time.Second)
	s := ""
	if days > 0 {
		s += fmt.Sprintf("%d %s ", days, maybePluralize("day", days))
	}
	if hours > 0 {
		s += fmt.Sprintf("%d %s ", hours, maybePluralize("hour", hours))
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d %s ", minutes, maybePluralize("minute", minutes))
	}
	if seconds >= 0 {
		s += fmt.Sprintf("%d %s ", seconds, maybePluralize("second", seconds))
	}
	return s
}

func VerifyResponse(now time.Time, serial *big.Int, resp *ocsp.Response) error {
	if resp.ThisUpdate.After(now) {
		return fmt.Errorf("malformed OCSP response: ThisUpdate is in the future (%s after %s)", resp.ThisUpdate, now)
	}
	if resp.NextUpdate.Before(now) {
		return fmt.Errorf("stale OCSP response: NextUpdate is in the past (%s before %s)", resp.NextUpdate, now)
	}
	if resp.ThisUpdate.After(resp.NextUpdate) {
		return fmt.Errorf("malformed OCSP response: NextUpdate is before ThisUpate (%s before %s)", resp.NextUpdate, resp.ThisUpdate)
	}
	if serial.Cmp(resp.SerialNumber) != 0 {
		return fmt.Errorf("malformed OCSP response: Serial numbers don't match (wanted %s, got %s)", serial, resp.SerialNumber)
	}
	return nil
}

var statusToString = map[int]string{
	0: "Success",
	1: "Malformed",
	2: "InternalError",
	3: "TryLater",
	5: "SignatureRequired",
	6: "Unauthorized",
}

func randomResponder(responders []string) string {
	return responders[mrand.Intn(len(responders))]
}

func parseCacheControl(h string) int {
	maxAge := 0
	h = strings.Replace(h, " ", "", -1)
	for _, p := range strings.Split(h, ",") {
		if strings.HasPrefix(p, "max-age=") {
			maxAge, _ = strconv.Atoi(p[8:])
		}
	}
	return maxAge
}

func Fetch(ctx context.Context, responders []string, client *http.Client, request []byte, etag string, issuer *x509.Certificate) (*ocsp.Response, []byte, string, int, error) {
	responder := randomResponder(responders)
	backoffSeconds := 0
	for {
		if backoffSeconds > 0 {
			// e.info("Request failed, backing off for %d seconds", backoffSeconds)
		}
		select {
		case <-ctx.Done():
			return nil, nil, "", 0, ctx.Err()
		case <-time.NewTimer(time.Duration(backoffSeconds) * time.Second).C:
		}
		if backoffSeconds > 0 {
			backoffSeconds = 0
		}
		req, err := http.NewRequest(
			"GET",
			fmt.Sprintf(
				"%s/%s",
				responder,
				url.QueryEscape(base64.StdEncoding.EncodeToString(request)),
			),
			nil,
		)
		if err != nil {
			return nil, nil, "", 0, err
		}
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		// e.info("Sending request to '%s'", req.URL)
		resp, err := client.Do(req)
		if err != nil {
			// e.err("Request for '%s' failed: %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 304 {
			// e.err("Request for '%s' got a non-200 response: %d", req.URL, resp.StatusCode)
			backoffSeconds = 10
			if resp.StatusCode == 503 {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, err := strconv.Atoi(retryAfter); err == nil {
						backoffSeconds = seconds
					}
				}
			}
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// e.err("Failed to read response body from '%s': %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			// e.err("Failed to parse response body from '%s': %s", req.URL, err)
			backoffSeconds = 10
			continue
		}
		if ocspResp.Status == int(ocsp.Success) {
			eTag, cacheControl := resp.Header.Get("ETag"), parseCacheControl(resp.Header.Get("Cache-Control"))
			return ocspResp, body, eTag, cacheControl, nil
		}
		// e.err("Request for '%s' got a invalid OCSP response status: %s", req.URL, statusToString[ocspResp.Status])
		backoffSeconds = 10
	}
}
