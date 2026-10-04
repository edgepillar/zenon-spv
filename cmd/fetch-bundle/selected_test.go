package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSelectedMomentumOptionsFailBeforeRPCOrPublication(t *testing.T) {
	peer, calls := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_RPC", "")
	t.Setenv("ZENON_SPV_PEERS", "")
	path := filepath.Join(t.TempDir(), "selected.json")
	before := []byte("protected existing output")
	if os.WriteFile(path, before, 0o600) != nil {
		t.Fatal("cannot preserve output")
	}
	base := []string{"--rpc", peer, "--height", "100", "--count", "16", "--proof-only", "--commitments", "z1qxemdeddedxpyllarxxxxxxxxxxxxxxxsy3fmg", "--out", path}
	for _, extra := range [][]string{
		{"--momentum-heights", ""}, {"--momentum-heights", "84"}, {"--momentum-heights", "101"},
		{"--momentum-heights", "90,90"}, {"--momentum-heights", "95,90"}, {"--momentum-heights", "090"},
		{"--momentum-heights", "90", "--momentum-heights", "95"},
		{"--momentum-heights", "90", "--proof-only=false"}, {"--momentum-heights", "90", "--height", "-1"},
		{"--momentum-heights", "90", "--checkpoint", filepath.Join(t.TempDir(), "anchor.json")},
	} {
		if err := run(append(slices.Clone(base), extra...)); err == nil || calls.Load() != 0 {
			t.Fatal("invalid height options collected or published")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, before) {
			t.Fatal("invalid selection changed prior output")
		}
	}
}
