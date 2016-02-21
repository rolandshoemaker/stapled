package stapled

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
)

func TestCertDefToEntryDef(t *testing.T) {
	clk := clock.Default()
	logger := NewLogger("", "", 10, clk)

	cd := CertDefinition{
		Certificate: "testdata/test.der",
		Issuer:      "testdata/test-issuer.der",
	}

	_, err := CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err != nil {
		t.Fatalf("Failed to create entryDefinition from certDefinition: %s", err)
	}

	cd.Certificate = ""
	// _, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	// if err == nil {
	// 	t.Fatal("Created incomplete entryDefinition")
	// }
	cd.Name = "test.der"
	cd.Serial = "DEADBEEF"
	cd.Responders = []string{"ocsp.example.com"}
	_, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err != nil {
		t.Fatalf("Failed to create entryDefinition from certDefinition: %s", err)
	}
}
