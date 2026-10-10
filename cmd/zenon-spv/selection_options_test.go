package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestRepeatedReadOnlySelectionCannotEnableWriter(t *testing.T) {
	f := inspectionFixture(t, true)
	unchanged := unchangedQueryFile(t, f.statePath)
	for _, options := range [][]string{
		{"--retained-only", "--retained-only=false"},
		{"--retained-only=false", "-retained-only=true"},
		{"--retained-only", "-retained-only=true"},
	} {
		args := append(slices.Clone(f.args), options...)
		r := readVerificationReport(t, "verify-commitment", append(args, f.bundlePath), 64)
		if r.Error == nil || r.Error.Stage != "arguments" || r.Error.Category != "usage" ||
			r.Outcome != nil || r.Context != nil || r.VerificationTip != nil || len(r.Results) != 0 {
			t.Fatal("repeated read-only selection reached verification setup")
		}
		unchanged(t)
		if _, err := os.Lstat(f.statePath + ".lock"); !os.IsNotExist(err) {
			t.Fatal("repeated read-only selection entered the writer-lock path")
		}
	}
}

func TestSelectionGuardsPreserveFirstValuesAndFlagGrammar(t *testing.T) {
	for _, args := range [][]string{
		{"--state=PRIVATE_FIRST", "-state=PRIVATE_LAST"},
		{"-state", "PRIVATE_FIRST", "--state", "PRIVATE_LAST"},
		{"--state=PRIVATE_FIRST", "--state=PRIVATE_FIRST"},
	} {
		fs := flag.NewFlagSet("selection", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		state := fs.String("state", "", "selected state")
		validate := registerSelectionGuards(fs)
		if fs.Parse(args) != nil || *state != "PRIVATE_FIRST" {
			t.Fatal("a repeated selector replaced the first value")
		}
		if err := validate(); err == nil || err.Error() != "--state must occur at most once" {
			t.Fatal("repeated selector was not privately refused")
		}
	}
	for _, args := range [][]string{nil, {"--state", "--state"}, {"--", "--state", "--state"}} {
		fs := flag.NewFlagSet("selection", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		state := fs.String("state", "", "selected state")
		readOnly := fs.Bool("retained-only", false, "read-only query")
		capacity := fs.Int("retain-headers", 256, "capacity")
		validate := registerSelectionGuards(fs)
		if fs.Parse(args) != nil || validate() != nil || *readOnly || *capacity != 256 {
			t.Fatal("single selections, defaults or the flag terminator changed")
		}
		if len(args) == 2 && *state != "--state" {
			t.Fatal("a selector-looking path was treated as another option")
		}
	}
}

func TestRepeatedVerifierSelectionsArePrivate(t *testing.T) {
	for _, name := range []string{"genesis-config", "protocol-profile", "schedule", "state", "window", "retain-headers"} {
		t.Run(name, func(t *testing.T) {
			args := []string{"--" + name + "=PRIVATE_FIRST", "-" + name + "=PRIVATE_LAST"}
			for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
				var out, diagnostics bytes.Buffer
				code := runVerification(command, append(slices.Clone(args), "PRIVATE_BUNDLE"), &out, &diagnostics)
				if code != 64 || out.Len() != 0 || diagnostics.String() != "--"+name+" must occur at most once\n" {
					t.Fatal("text verification did not privately reject a repeated selector")
				}
			}
			var out, diagnostics bytes.Buffer
			inspect := runInspectConfig
			if name == "state" {
				inspect = runInspectState
			}
			if inspect(args, &out, &diagnostics) != 64 || strings.Contains(out.String()+diagnostics.String(), "PRIVATE") {
				t.Fatal("inspection disclosed a repeated selector")
			}
		})
	}
}

func TestSelectionGuardsPreserveHelpFormatting(t *testing.T) {
	help := func(guarded bool) string {
		var out bytes.Buffer
		fs := flag.NewFlagSet("selection", flag.ContinueOnError)
		fs.SetOutput(&out)
		fs.String("window", "low", "selected window")
		fs.String("state", "", "selected state")
		fs.Bool("retained-only", false, "read-only query")
		fs.Int("quorum", 0, "selected quorum")
		if guarded {
			registerSelectionGuards(fs)
		}
		if fs.Parse([]string{"--help"}) != flag.ErrHelp {
			t.Fatal("help status changed")
		}
		return out.String()
	}
	if help(false) != help(true) {
		t.Fatal("selection guards changed ordinary help/default formatting")
	}
}

func TestInvalidWatchSelectionValuesArePrivate(t *testing.T) {
	for _, name := range []string{"quorum", "once", "interval", "safety-margin", "batch-size"} {
		code, out, diagnostics := captureSetupRun(t, func() int {
			return runWatch([]string{"--json", "--" + name + "=PRIVATE_INVALID"})
		})
		if code != 64 || out != "" || diagnostics != "--"+name+" has an invalid value\n" {
			t.Fatal("invalid watch selection reached setup or disclosed its value")
		}
	}
}
