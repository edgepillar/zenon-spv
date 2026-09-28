package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchIntervalValidationPrecedesConfiguration(t *testing.T) {
	for _, interval := range []string{"-1ns", "-1s", "0s", "1ns", "10s"} {
		t.Run(interval, func(t *testing.T) {
			dir := t.TempDir()
			code, out, diagnostics := captureSetupRun(t, func() int {
				return runWatch([]string{"--interval", interval, "--rpc", "http://127.0.0.1:1", "--peers", "",
					"--state", filepath.Join(dir, "state.json"), "--genesis-config", filepath.Join(dir, "absent-anchor.json"), "--show-context"})
			})
			if strings.HasPrefix(interval, "-") {
				if code != 64 || !strings.Contains(diagnostics, "--interval must not be negative") {
					t.Fatalf("negative interval reached configuration: code=%d diagnostics=%s", code, diagnostics)
				}
			} else if code != 70 || !strings.HasPrefix(diagnostics, "genesis: ") {
				t.Fatalf("valid interval did not reach configuration: code=%d diagnostics=%s", code, diagnostics)
			}
			if out != "" || strings.Contains(diagnostics, "verification_context:") || strings.Contains(diagnostics, "watching:") {
				t.Fatal("failed setup reached evidence or startup reporting")
			}
		})
	}
}
