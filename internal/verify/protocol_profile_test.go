package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestLoadProtocolProfileStrictBoundedInput(t *testing.T) {
	p := ProtocolProfile{Version: 1, Anchor: GenesisTrustRoot{ChainID: 99, Height: 100, HeaderHash: chain.Hash{1}},
		ValidThrough: 200, V2FromHeight: 150, Source: "synthetic profile"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	inputs := []struct {
		name, raw string
		valid     bool
	}{
		{"valid", string(raw), true},
		{"unknown-field", strings.TrimSuffix(string(raw), "}") + `,"v2_from_heigth":150}`, false},
		{"trailing-object", string(raw) + `{}`, false},
		{"oversized", string(raw) + strings.Repeat(" ", 16*1024), false},
		{"null", `null`, false},
		{"missing-activation", strings.Replace(string(raw), `,"v2_from_height":150`, ``, 1), false},
		{"null-activation", strings.Replace(string(raw), `"v2_from_height":150`, `"v2_from_height":null`, 1), false},
		{"unknown-schema", strings.Replace(string(raw), `"version":1`, `"version":2`, 1), false},
		{"empty-source", strings.Replace(string(raw), `"synthetic profile"`, `""`, 1), false},
		{"invalid-coverage", strings.Replace(string(raw), `"valid_through":200`, `"valid_through":100`, 1), false},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadProtocolProfile(path)
			if tc.valid {
				if err != nil || got == nil || *got != p {
					t.Fatalf("valid profile: %v", err)
				}
			} else if !errors.Is(err, ErrInvalidProtocolProfile) || got != nil {
				t.Fatalf("invalid profile: %v", err)
			}
		})
	}
}
