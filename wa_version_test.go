package main

import "testing"

func TestParseWAVersion(t *testing.T) {
	version, err := parseWAVersion("2.3000.1053682356")
	if err != nil {
		t.Fatalf("parseWAVersion: %v", err)
	}
	if version.String() != "2.3000.1053682356" {
		t.Errorf("versão = %s", version.String())
	}
}

func TestParseWAVersionRejectsInvalid(t *testing.T) {
	for _, raw := range []string{"", "abc", "2.3000", "0.0.0", "2.3000.x"} {
		if _, err := parseWAVersion(raw); err == nil {
			t.Errorf("parseWAVersion(%q) deveria falhar", raw)
		}
	}
}
