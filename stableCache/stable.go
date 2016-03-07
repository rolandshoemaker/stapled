package stableCache

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

type Cache interface {
	Read(string, *big.Int, *x509.Certificate) (*ocsp.Response, []byte)
	Write(string, []byte)
}

type DiskCache struct {
	logger *log.Logger
	clk    clock.Clock
	path   string
}

func NewDisk(logger *log.Logger, clk clock.Clock, path string) *DiskCache {
	return &DiskCache{logger, clk, path}
}

func (dc *DiskCache) Read(name string, serial *big.Int, issuer *x509.Certificate) (*ocsp.Response, []byte) {
	name = path.Join(dc.path, name) + ".resp"
	response, err := ioutil.ReadFile(name)
	if err != nil && !os.IsNotExist(err) {
		common.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to read response from '%s': %s", name, err))
	} else if err != nil {
		return nil, nil // no file exists yet
	}
	parsed, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		common.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to parse response from '%s': %s", name, err))
	}
	err = stapledOCSP.VerifyResponse(dc.clk.Now(), serial, parsed)
	if err != nil {
		common.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to verify response from '%s': %s", name, err))
	}
	dc.logger.Info("[disk-cache] Loaded valid response from '%s'", name)
	return parsed, response
}

func (dc *DiskCache) Write(name string, content []byte) {
	name = path.Join(dc.path, name) + ".resp"
	tmpName := fmt.Sprintf("%s.tmp", name)
	err := ioutil.WriteFile(tmpName, content, os.ModePerm)
	if err != nil {
		common.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to write response to '%s': %s", tmpName, err))
	}
	err = os.Rename(tmpName, name)
	if err != nil {
		os.Remove(tmpName) // silently attempt to remove temporary file
		common.Fail(dc.logger, fmt.Sprintf("[disk-cache] Failed to rename '%s' to '%s': %s", tmpName, name, err))
	}
	dc.logger.Info("[disk-cache] Written new response to '%s'", name)
	return
}
