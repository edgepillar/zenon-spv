package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchPeerSelectionPrecedesConfiguration(t *testing.T) {
	t.Setenv("ZENON_SPV_PEERS", "http://PRIVATE_ENV_PEER_A.invalid,http://PRIVATE_ENV_PEER_B.invalid")
	t.Setenv("ZENON_SPV_RPC", "http://PRIVATE_ENV_RPC.invalid")
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"explicit RPC", []string{"--rpc", "http://selected.invalid", "--quorum", "2"}, 64, "--quorum must be"},
		{"empty explicit RPC", []string{"--rpc", ""}, 64, "--peers or --rpc required"},
		{"explicit peers win", []string{"--rpc", "http://ignored.invalid", "--peers", "http://a.invalid,http://b.invalid", "--quorum", "2"}, 70, "genesis:"},
		{"explicit empty peers", []string{"--peers", "", "--quorum", "2"}, 64, "--quorum must be"},
		{"environment peers", []string{"--quorum", "2"}, 70, "genesis:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"--state", filepath.Join(dir, "state.json"), "--genesis-config", filepath.Join(dir, "absent-anchor.json")}, tc.args...)
			code, out, diagnostics := captureSetupRun(t, func() int { return runWatch(args) })
			if code != tc.code || out != "" || !strings.Contains(diagnostics, tc.want) || strings.Contains(diagnostics, "PRIVATE_ENV") {
				t.Fatalf("watch selected the wrong peer configuration: exit=%d", code)
			}
		})
	}
}
