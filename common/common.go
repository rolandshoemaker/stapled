package common

import (
	"fmt"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rolandshoemaker/stapled/log"
)

func HumanDuration(d time.Duration) string {
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

func Fail(logger *log.Logger, msg string) {
	logger.Err(msg)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func randomURL(urls []*url.URL) *url.URL {
	return urls[mrand.Intn(len(urls))]
}

func ProxyFunc(proxies []string) (func(*http.Request) (*url.URL, error), error) {
	proxyURLs := []*url.URL{}
	for _, p := range proxies {
		u, err := url.Parse(p)
		if err != nil {
			return nil, err
		}
		proxyURLs = append(proxyURLs, u)
	}
	return func(*http.Request) (*url.URL, error) {
		return randomURL(proxyURLs), nil
	}, nil
}
