package main

import (
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestPresetMapBuildable ensures every generated preset can be turned into a
// ClientHelloSpec by the pinned uTLS (randomized presets are generated on the
// fly and have no static spec).
func TestPresetMapBuildable(t *testing.T) {
	for name, id := range presetByName {
		// Randomized presets are generated on the fly; HelloGolang is built via
		// crypto/tls defaults. Neither has a static UTLSIdToSpec entry.
		if strings.Contains(name, "Randomized") || name == "HelloGolang" {
			continue
		}
		if _, err := utls.UTLSIdToSpec(id); err != nil {
			t.Errorf("preset %s is not buildable: %v", name, err)
		}
	}
}

// TestPresetMapHasCurrentVersions guards against a stale generated map.
func TestPresetMapHasCurrentVersions(t *testing.T) {
	want := []string{
		"HelloChrome_155", "HelloFirefox_148", "HelloSafari_26_3",
		"HelloChrome_Auto", "HelloFirefox_Auto", "HelloSafari_Auto",
	}
	for _, n := range want {
		if _, ok := presetByName[n]; !ok {
			t.Errorf("preset map is missing %s (stale? run `make gen`)", n)
		}
	}
}
