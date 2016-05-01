package scache

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"

	"github.com/rolandshoemaker/stapled/log"
)

type testFailer struct {
	failed bool
}

func (tf *testFailer) Fail(logger *log.Logger, msg string) {
	logger.Err(msg)
	tf.failed = true
}

func TestDiskCache(t *testing.T) {
	testRespBytes, err := ioutil.ReadFile("../testdata/ocsp.resp")
	if err != nil {
		t.Fatalf("Failed to read test ocsp response: %s", err)
	}
	testResp, err := ocsp.ParseResponse(testRespBytes, nil)
	if err != nil {
		t.Fatalf("Failed to parse test ocsp response: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(testResp.ThisUpdate.Add(time.Hour))
	logger := log.NewLogger("", "", 10, fc)
	tmpDir, err := ioutil.TempDir("", "boulder-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir)
	dc := NewDisk(logger, fc, tmpDir)
	tf := &testFailer{}
	dc.failer = tf

	// write a response
	dc.Write("test-write", testRespBytes)
	if tf.failed {
		t.Fatal("Failed to write response to disk")
	}

	readResp, bytes := dc.Read("test-write", testResp.SerialNumber, nil)
	if tf.failed {
		t.Fatal("Failed to read response from disk")
	}
	if readResp == nil || bytes == nil {
		t.Fatal("Either the parsed response or the DER bytes returned by Read are nil")
	}
}
