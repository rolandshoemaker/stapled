package scache

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/rolandshoemaker/stapled/common"
	"github.com/rolandshoemaker/stapled/log"
	stapledOCSP "github.com/rolandshoemaker/stapled/ocsp"
)

// Cache represents a stable cache
type Cache interface {
	Read(string, *big.Int, *x509.Certificate) (*ocsp.Response, []byte)
	Write(string, []byte)
}

// DiskCache is a on disk stable cache
type DiskCache struct {
	logger *log.Logger
	clk    clock.Clock
	path   string
	failer common.Failer
}

// NewDisk creates a DiskCache
func NewDisk(logger *log.Logger, clk clock.Clock, path string) *DiskCache {
	return &DiskCache{logger, clk, path, &common.BasicFailer{}}
}

// Read reads a OCSP response from disk
func (dc *DiskCache) Read(name string, serial *big.Int, issuer *x509.Certificate) (*ocsp.Response, []byte) {
	name = path.Join(dc.path, name) + ".resp"
	response, err := ioutil.ReadFile(name)
	if err != nil && !os.IsNotExist(err) {
		dc.failer.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to read response from '%s': %s", name, err))
		return nil, nil
	} else if err != nil {
		return nil, nil // no file exists yet
	}
	parsed, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		dc.failer.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to parse response from '%s': %s", name, err))
		return nil, nil
	}
	err = stapledOCSP.VerifyResponse(dc.clk.Now(), serial, parsed)
	if err != nil {
		dc.failer.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to verify response from '%s': %s", name, err))
		return nil, nil
	}
	dc.logger.Info("[disk-cache] Loaded valid response from '%s'", name)
	return parsed, response
}

// Write writes a OCSP response to disk
func (dc *DiskCache) Write(name string, content []byte) {
	name = path.Join(dc.path, name) + ".resp"
	tmpName := fmt.Sprintf("%s.tmp", name)
	err := ioutil.WriteFile(tmpName, content, os.ModePerm)
	if err != nil {
		dc.failer.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to write response to '%s': %s", tmpName, err))
		return
	}
	err = os.Rename(tmpName, name)
	if err != nil {
		os.Remove(tmpName) // silently attempt to remove temporary file
		dc.failer.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to rename '%s' to '%s': %s", tmpName, name, err))
		return
	}
	dc.logger.Info("[disk-cache] Written new response to '%s'", name)
	return
}
