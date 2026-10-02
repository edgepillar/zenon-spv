package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/buildinfo"
)

func sampleCandidate(t *testing.T) (string, pilotReport) {
	t.Helper()
	dir := t.TempDir()
	revision, modified := strings.Repeat("b", 40), false
	report := pilotReport{SchemaVersion: 1, Mode: "offline_synthetic", Status: "passed", InputsUnchanged: true,
		Runner: buildinfo.Capture("offline-pilot"), Source: sourceRecord{Revision: &revision, Modified: &modified, InputsSHA256: strings.Repeat("c", 64)}}
	for _, path := range corpusPaths {
		report.Corpus = append(report.Corpus, corpusRecord{Path: path, SHA256: digestBytes([]byte(path))})
	}
	for _, s := range scenarios {
		result := caseResult{scenario: s, Status: "passed", Binaries: []binaryRecord{}}
		for _, command := range s.Commands {
			result.Binaries = append(result.Binaries, binaryRecord{Command: command, SHA256: digestBytes([]byte(command))})
		}
		report.Cases = append(report.Cases, result)
	}
	for _, command := range candidateCommands() {
		filename := command
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, filename), []byte(command), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, report
}

func candidateReportBytes(t *testing.T, report pilotReport) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestCandidateManifest(t *testing.T) {
	t.Run("exact report and executable bytes are bound", func(t *testing.T) {
		dir, report := sampleCandidate(t)
		raw := candidateReportBytes(t, report)
		if err := finalizeCandidate(dir, report, raw); err != nil {
			t.Fatal(err)
		}
		manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		var manifest candidateManifest
		if err != nil || json.Unmarshal(manifestRaw, &manifest) != nil || bytes.Contains(manifestRaw, []byte(dir)) ||
			manifest.SchemaVersion != 1 || manifest.Mode != "offline_synthetic_candidate" || manifest.TestStatus != "passed" ||
			manifest.Report.SHA256 != digestBytes(raw) || manifest.Report.Bytes != int64(len(raw)) || len(manifest.Binaries) != 7 {
			t.Fatal("manifest lost exact report, platform or executable bindings")
		}
		got, err := os.ReadFile(filepath.Join(dir, manifest.Report.Filename))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatal("exported report differs from stdout bytes")
		}
		for _, binary := range manifest.Binaries {
			got, err := os.ReadFile(filepath.Join(dir, binary.Filename))
			if err != nil || digestBytes(got) != binary.SHA256 || int64(len(got)) != binary.Bytes || string(got) != binary.Command {
				t.Fatal("exported executable was rebuilt or replaced")
			}
		}
		if err := finalizeCandidate(dir, report, raw); err == nil {
			t.Fatal("completed candidate directory was overwritten")
		}
	})
	t.Run("skips stay explicit", func(t *testing.T) {
		dir, report := sampleCandidate(t)
		report.Status = "passed_with_skips"
		report.Cases[0].Status, report.Cases[0].Skipped = "passed_with_skips", 1
		if err := finalizeCandidate(dir, report, candidateReportBytes(t, report)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil || !bytes.Contains(raw, []byte(`"test_status": "passed_with_skips"`)) {
			t.Fatal("manifest hid skipped execution")
		}
	})
	for _, mode := range []string{"failed", "changed source", "missing scenario", "wrong scenario", "missing binary record", "conflicting digest", "unknown command", "wrong digest", "inconsistent skips", "missing corpus", "wrong platform", "missing file", "changed file", "empty file", "directory file", "extra file", "existing manifest", "different report bytes"} {
		t.Run(mode, func(t *testing.T) {
			dir, report := sampleCandidate(t)
			filename := "zenon-spv"
			if runtime.GOOS == "windows" {
				filename += ".exe"
			}
			path := filepath.Join(dir, filename)
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "failed":
				report.Status = "failed"
			case "changed source":
				report.InputsUnchanged = false
			case "missing scenario":
				report.Cases = report.Cases[:len(report.Cases)-1]
			case "wrong scenario":
				report.Cases[0].ID = "PRIVATE_SCENARIO"
			case "missing binary record":
				report.Cases[0].Binaries = nil
			case "conflicting digest":
				report.Cases[1].Binaries[0].SHA256 = strings.Repeat("a", 64)
			case "unknown command":
				report.Cases[0].Binaries[0].Command = "../PRIVATE_PATH"
			case "wrong digest":
				report.Cases[0].Binaries[0].SHA256 = "PRIVATE_DIGEST"
			case "inconsistent skips":
				report.Cases[0].Skipped = 1
			case "missing corpus":
				report.Corpus = nil
			case "wrong platform":
				report.Runner.OS = "PRIVATE_PLATFORM"
			case "missing file", "directory file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "directory file" {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			case "changed file":
				write(path, []byte("different bytes"))
			case "empty file":
				write(path, nil)
			case "extra file":
				write(filepath.Join(dir, "PRIVATE_FILE"), []byte("private bytes"))
			case "existing manifest":
				write(filepath.Join(dir, "manifest.json"), []byte("prior manifest"))
			}
			raw := candidateReportBytes(t, report)
			if mode == "different report bytes" {
				raw = []byte("PRIVATE_REPORT")
			}
			if err := finalizeCandidate(dir, report, raw); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid candidate completed or disclosed private input")
			}
			got, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if mode == "existing manifest" {
				if err != nil || string(got) != "prior manifest" {
					t.Fatal("existing manifest was replaced")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("invalid candidate left a completion manifest")
			}
		})
	}
}

func TestCandidateDirectorySetup(t *testing.T) {
	root := t.TempDir()
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(checkout, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(checkout)
	dir := filepath.Join(root, "new-candidate")
	resolved, err := prepareCandidateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(resolved, "PRIVATE_FILE")
	if err := os.WriteFile(marker, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, "relative", checkout, filepath.Join(checkout, "inside")} {
		if _, err := prepareCandidateDirectory(path); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("existing, relative or source directory accepted")
		}
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "preserved" {
		t.Fatal("candidate setup changed existing files")
	}
}
