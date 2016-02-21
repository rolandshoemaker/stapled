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

	ed, err := CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err != nil {
		t.Fatalf("Failed to create entryDefinition from certDefinition: %s", err)
	}

	if ed.Name != "test.der" {
		t.Fatal("entryDefinition has wrong name")
	}
	if ed.Issuer == nil {
		t.Fatal("entryDefinition is missing issuer")
	}
	if ed.Serial == nil {
		t.Fatal("entryDefinition is missing serial")
	}
	if ed.Proxy != nil {
		t.Fatal("entryDefinition contains proxy without being provided")
	}
	if len(ed.Responders) != 1 {
		t.Fatal("entryDefinition contains wrong number of responders")
	}
	if ed.Responders[0] != "http://ocsp.int-x1.letsencrypt.org/" {
		t.Fatal("entryDefinition contains incorrect responder")
	}

	cd.Issuer = ""
	ed, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err != nil {
		t.Fatal("Created incomplete entryDefinition")
	}

	if ed.Issuer == nil {
		t.Fatal("entryDefinition is missing issuer")
	}

	cd.Certificate = ""
	_, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err == nil {
		t.Fatal("Created incomplete entryDefinition")
	}

	cd.Issuer = "testdata/test-issuer.der"
	_, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err == nil {
		t.Fatal("Created incomplete entryDefinition")
	}
	cd.Name = "test.der"
	cd.Serial = "DEADBEEF"
	cd.Responders = []string{"http://ocsp.example.com"}
	ed, err = CertDefToEntryDef(logger, clk, time.Second, time.Second, "", nil, "", cd)
	if err != nil {
		t.Fatalf("Failed to create entryDefinition from certDefinition: %s", err)
	}

	if ed.Name != "test.der" {
		t.Fatal("entryDefinition has wrong name")
	}
	if ed.Issuer == nil {
		t.Fatal("entryDefinition is missing issuer")
	}
	if ed.Serial == nil {
		t.Fatal("entryDefinition is missing serial")
	}
	if ed.Proxy != nil {
		t.Fatal("entryDefinition contains proxy without being provided")
	}
	if len(ed.Responders) != 1 {
		t.Fatal("entryDefinition contains wrong number of responders")
	}
	if ed.Responders[0] != "http://ocsp.example.com" {
		t.Fatal("entryDefinition contains incorrect responder")
	}
}
