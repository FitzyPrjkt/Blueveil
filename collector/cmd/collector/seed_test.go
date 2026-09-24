// The embedded lab IOC set must stay byte-identical to the serve
// fixture so seed and serve --ioc-set observe the same indicators.
package main

import (
	"os"
	"testing"
)

func TestSeedIOCSetMatchesServeFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/lab-iocs.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if string(raw) != seedIOCSet && string(raw)+"\n" != seedIOCSet && string(raw) != seedIOCSet+"\n" {
		t.Fatalf("seedIOCSet const drifted from testdata/lab-iocs.json")
	}
}
