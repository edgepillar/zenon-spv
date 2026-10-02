package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestManifestSelectionIsExactAndUncached(t *testing.T) {
	args := testArguments(scenarios, true)
	for _, option := range []string{"-json", "-count=1", "-race", "-timeout=5m"} {
		if !slices.Contains(args, option) {
			t.Fatalf("missing execution option %s", option)
		}
	}
	selection := regexp.MustCompile(args[slices.Index(args, "-run")+1])
	seen := make(map[string]bool)
	for _, s := range scenarios {
		if seen[s.ID] || seen[s.Package+"/"+s.Test] || !selection.MatchString(s.Test) || selection.MatchString(s.Test+"Unrelated") {
			t.Fatal("ambiguous scenario identity or test selection")
		}
		seen[s.ID], seen[s.Package+"/"+s.Test] = true, true
		if !slices.Contains(args, "./"+s.Package) {
			t.Fatal("selected test package was not scheduled")
		}
	}
}

func TestPilotEnvironmentDisablesAmbientSelectionAndDownloads(t *testing.T) {
	t.Setenv("ZENON_SPV_PEERS", "PRIVATE_ENDPOINT")
	t.Setenv(candidateExportEnvironment, "PRIVATE_EXPORT_DIRECTORY")
	t.Setenv("GOFLAGS", "-run=Nothing")
	t.Setenv("GOPROXY", "PRIVATE_PROXY")
	t.Setenv("GONOPROXY", "*")
	t.Setenv("GOPRIVATE", "*")
	env := pilotEnvironment(filepath.Join(t.TempDir(), "go"))
	for _, value := range env {
		if strings.Contains(value, "PRIVATE_") || strings.HasPrefix(value, "ZENON_SPV_") || value == "GOFLAGS=-run=Nothing" || value == "GONOPROXY=*" || value == "GOPRIVATE=*" {
			t.Fatal("ambient configuration reached the offline test process")
		}
	}
	for _, expected := range []string{"GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=", "GONOPROXY=none", "GOPRIVATE="} {
		if !slices.Contains(env, expected) {
			t.Fatalf("missing offline setting %s", expected)
		}
	}
}

func TestPilotUsageDoesNotExposeArguments(t *testing.T) {
	for _, args := range [][]string{{"--PRIVATE_FLAG"}, {"--timeout", "PRIVATE_DURATION"}, {"--timeout", "0"}, {"--timeout", "2h"}, {"PRIVATE_PATH"},
		{"--export-binaries", "relative_PRIVATE_PATH"}, {"--export-binaries", ""},
		{"--export-binaries", filepath.Join(t.TempDir(), "first"), "--export-binaries", filepath.Join(t.TempDir(), "second")}} {
		var out, diagnostics bytes.Buffer
		if code := run(args, &out, &diagnostics); code != 64 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid arguments did not fail privately before setup")
		}
	}
}

type failingWriter struct{ short bool }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("PRIVATE_OUTPUT_PATH")
}

func TestPilotOutputFailureHasNoReplay(t *testing.T) {
	for _, short := range []bool{false, true} {
		var diagnostics bytes.Buffer
		if code := writeReport(failingWriter{short}, &diagnostics, []byte("{}\n"), 0); code != 70 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("failed output reported success or disclosed an underlying error")
		}
	}
}

func TestSourceFingerprintBindsNamesBytesAndFixtures(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, dir := range []string{"cmd", "internal", "tools"} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+modulePath+"\n")
	write("go.sum", "")
	write(filepath.Join("internal", "example_test.go"), "test input")
	write(filepath.Join("internal", "fixture.json"), "fixture input")
	before, err := captureSource()
	if err != nil || !hexDigest(before.InputsSHA256, 64) || before.Revision != nil || before.Modified != nil {
		t.Fatal("source archive did not retain explicit unknown revision metadata")
	}
	for _, path := range []string{"internal/example_test.go", "internal/fixture.json", "go.sum"} {
		t.Run(path, func(t *testing.T) {
			write(path, "changed")
			after, err := captureSource()
			if err != nil || after.InputsSHA256 == before.InputsSHA256 {
				t.Fatal("source change did not alter the input fingerprint")
			}
			before = after
		})
	}
	if err := os.Rename("internal/example_test.go", "internal/renamed_test.go"); err != nil {
		t.Fatal(err)
	}
	after, err := captureSource()
	if err != nil || after.InputsSHA256 == before.InputsSHA256 {
		t.Fatal("source rename did not alter the input fingerprint")
	}
}

func TestSourceModuleAcceptsWindowsLineEndings(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, dir := range []string{"cmd", "internal", "tools"} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("go.mod", []byte("module "+modulePath+"\r\n\r\ngo 1.25.0\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("go.sum", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if record, err := captureSource(); err != nil || !hexDigest(record.InputsSHA256, 64) {
		t.Fatalf("valid CRLF module was refused: %v", err)
	}
}
