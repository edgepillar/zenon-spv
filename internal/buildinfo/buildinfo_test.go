package buildinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"testing"
)

func gitMetadata() *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: strings.Repeat("a", 40)},
		{Key: "vcs.modified", Value: "false"},
	}}
}

func TestSourceMetadataPrivacyAndUnknowns(t *testing.T) {
	info := gitMetadata()
	info.Path, info.Main.Path = "/PRIVATE/package", "/PRIVATE/module"
	info.Main.Replace = &debug.Module{Path: "/PRIVATE/replacement"}
	info.Deps = []*debug.Module{{Path: "/PRIVATE/dependency"}}
	info.Settings = append(info.Settings,
		debug.BuildSetting{Key: "-ldflags", Value: "/PRIVATE/flags SECRET"},
		debug.BuildSetting{Key: "vcs.time", Value: "PRIVATE_TIME"},
		debug.BuildSetting{Key: "CGO_CFLAGS", Value: "/PRIVATE/include"})
	raw, err := json.Marshal(sourceInfo(info))
	if err != nil || string(raw) != `{"vcs":"git","revision":"`+strings.Repeat("a", 40)+`","modified":false}` {
		t.Fatalf("unexpected filtered source metadata: %s, %v", raw, err)
	}
	info.Settings[2].Value = "true"
	info.Settings[1].Value = strings.Repeat("b", 64)
	if source := sourceInfo(info); source == nil || !source.Modified || len(source.Revision) != 64 {
		t.Fatal("modified SHA-256 checkout metadata was lost")
	}
	for _, test := range []struct{ key, value string }{
		{"vcs", "PRIVATE_VCS"}, {"vcs.revision", "/PRIVATE/revision"},
		{"vcs.revision", strings.Repeat("z", 40)}, {"vcs.revision", "abc123"},
		{"vcs.modified", "unknown"}, {"vcs.modified", ""},
	} {
		candidate := gitMetadata()
		for i := range candidate.Settings {
			if candidate.Settings[i].Key == test.key {
				candidate.Settings[i].Value = test.value
			}
		}
		if sourceInfo(candidate) != nil {
			t.Fatalf("invalid %s was presented as known source metadata", test.key)
		}
	}
	for removed := range 3 {
		candidate := gitMetadata()
		candidate.Settings = append(candidate.Settings[:removed], candidate.Settings[removed+1:]...)
		if sourceInfo(candidate) != nil {
			t.Fatal("incomplete metadata was presented as a known checkout")
		}
		candidate = gitMetadata()
		candidate.Settings = append(candidate.Settings, candidate.Settings[removed])
		if sourceInfo(candidate) != nil {
			t.Fatal("duplicate metadata was presented as a known checkout")
		}
	}
	if sourceInfo(nil) != nil || sourceInfo(&debug.BuildInfo{}) != nil {
		t.Fatal("missing metadata was presented as a known checkout")
	}
}

func TestCustomToolchainDetailsAreOmitted(t *testing.T) {
	for _, version := range []string{"go1.25", "go1.25.14", "go1.26rc2", "go1.27beta1"} {
		if safeGoVersion(version) != version {
			t.Fatal("release toolchain version was lost")
		}
	}
	for _, version := range []string{"", "go1.25.14-PRIVATE", "devel PRIVATE_BUILD", "go1.25\nPRIVATE", "/PRIVATE/toolchain", "go1.25." + strings.Repeat("1", 100)} {
		if safeGoVersion(version) != "unknown" {
			t.Fatal("custom toolchain metadata was exposed")
		}
	}
}

func TestVersionCommandArgumentsAndOutput(t *testing.T) {
	for _, args := range [][]string{nil, {"--json=false"}, {"--json"}, {"--help"}} {
		var out, diagnostics bytes.Buffer
		if Run("zenon-spv", args, &out, &diagnostics) != 0 || out.Len() == 0 || diagnostics.Len() != 0 {
			t.Fatal("valid version command failed")
		}
		if len(args) > 0 && args[0] == "--json" {
			var report Report
			decoder := json.NewDecoder(&out)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&report); err != nil || report.Command != "zenon-spv" || report.SchemaVersion != 1 {
				t.Fatal("invalid JSON build report")
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Fatal("version output contained multiple documents")
			}
		}
	}
	for _, args := range [][]string{{"PRIVATE_ARGUMENT"}, {"--json=PRIVATE_VALUE"}, {"--PRIVATE_FLAG"}, {"--json", "extra"}} {
		var out, diagnostics bytes.Buffer
		if Run("zenon-spv", args, &out, &diagnostics) != 64 || out.Len() != 0 || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid version invocation succeeded or exposed arguments")
		}
	}
	for _, writer := range []io.Writer{
		failingWriter{err: errors.New("PRIVATE_WRITE_ERROR")}, failingWriter{},
	} {
		var diagnostics bytes.Buffer
		if Run("fetch-bundle", []string{"--json"}, writer, &diagnostics) != 70 || strings.Contains(diagnostics.String(), "PRIVATE") {
			t.Fatal("failed or short version write was not handled privately")
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }
