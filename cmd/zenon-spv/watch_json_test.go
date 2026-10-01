package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchJSONSetupFailureDoesNotEchoPrivatePaths(t *testing.T) {
	dir := t.TempDir()
	code, out, diagnostics := captureSetupRun(t, func() int {
		return runWatch([]string{"--json", "--rpc", "http://127.0.0.1:1", "--peers", "",
			"--state", filepath.Join(dir, "PRIVATE_STATE"),
			"--genesis-config", filepath.Join(dir, "PRIVATE_ABSENT_ANCHOR")})
	})
	if code != 70 || out != "" || diagnostics != "genesis: operation failed\n" || strings.Contains(diagnostics, dir) {
		t.Fatalf("JSON watch did not report a private setup failure: exit=%d", code)
	}
}

func TestWatchOnceStillValidatesSetup(t *testing.T) {
	code, out, diagnostics := captureSetupRun(t, func() int {
		return runWatch([]string{"--once", "--json", "--rpc", "http://127.0.0.1:1", "--peers", "",
			"--state", filepath.Join(t.TempDir(), "PRIVATE_STATE"),
			"--genesis-config", filepath.Join(t.TempDir(), "PRIVATE_ABSENT_ANCHOR")})
	})
	if code != 70 || out != "" || diagnostics != "genesis: operation failed\n" {
		t.Fatalf("single-step watch skipped setup validation: exit=%d", code)
	}
}
