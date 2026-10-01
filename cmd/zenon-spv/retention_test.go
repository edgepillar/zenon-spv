package main

import (
	"bytes"
	"slices"
	"testing"
)

func TestRetentionCLIRejectsInvalidExplicitValuesBeforeSetup(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "6", "4097", "999999999999999999999999", "PRIVATE_VALUE"} {
		args := []string{"--json", "--retain-headers=" + value}
		for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
			r := readVerificationReport(t, command, append(slices.Clone(args), "PRIVATE_MISSING"), 64)
			if r.Error.Stage != "arguments" || r.Outcome != nil {
				t.Fatal("invalid capacity reached verification")
			}
		}
		configurationJSON(t, args, 64)
		inspectionJSON(t, append(slices.Clone(args), "--state", "PRIVATE_MISSING"), 64)
		code, out, diagnostics := captureSetupRun(t, func() int { return runWatch(args) })
		if code != 64 || out != "" || bytes.Contains([]byte(diagnostics), []byte("PRIVATE")) {
			t.Fatal("watch accepted or disclosed invalid capacity")
		}
	}
}
