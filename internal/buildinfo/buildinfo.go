// Package buildinfo exposes a small, privacy-filtered build diagnostic.
// Embedded metadata is descriptive, not authenticated release provenance.
package buildinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"runtime/debug"
)

// Report deliberately excludes module paths, replacements, dependencies,
// build flags, environment settings, timestamps, and arbitrary metadata.
type Report struct {
	SchemaVersion uint32  `json:"schema_version"`
	Command       string  `json:"command"`
	GoVersion     string  `json:"go_version"`
	OS            string  `json:"os"`
	Architecture  string  `json:"architecture"`
	Source        *Source `json:"source"`
}

// Source is present only for complete, unambiguous Git build metadata.
// Modified describes the source tree at build time, not the current checkout.
type Source struct {
	VCS      string `json:"vcs"`
	Revision string `json:"revision"`
	Modified bool   `json:"modified"`
}

var releaseGoVersion = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+|(?:beta|rc)[0-9]+)?$`)

// Capture reads in-memory runtime metadata only. Incomplete or unsupported
// source metadata stays unknown; it never defaults to an unmodified checkout.
func Capture(command string) Report {
	info, _ := debug.ReadBuildInfo()
	return Report{
		SchemaVersion: 1, Command: command, GoVersion: safeGoVersion(runtime.Version()),
		OS: runtime.GOOS, Architecture: runtime.GOARCH, Source: sourceInfo(info),
	}
}

func safeGoVersion(version string) string {
	if len(version) <= 32 && releaseGoVersion.MatchString(version) {
		return version
	}
	return "unknown"
}

func sourceInfo(info *debug.BuildInfo) *Source {
	if info == nil {
		return nil
	}
	values := make(map[string]string, 3)
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs", "vcs.revision", "vcs.modified":
			if _, duplicate := values[setting.Key]; duplicate {
				return nil
			}
			values[setting.Key] = setting.Value
		}
	}
	if values["vcs"] != "git" || !validRevision(values["vcs.revision"]) {
		return nil
	}
	modified := values["vcs.modified"]
	if modified != "true" && modified != "false" {
		return nil
	}
	return &Source{VCS: "git", Revision: values["vcs.revision"], Modified: modified == "true"}
}

func validRevision(revision string) bool {
	if len(revision) != 40 && len(revision) != 64 {
		return false
	}
	for _, c := range revision {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Run handles version-only arguments before either CLI loads configuration,
// state, or RPC clients. Diagnostics never echo arbitrary argument values.
func Run(command string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "emit a versioned JSON build report")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return writeOutput(stdout, stderr, []byte("Usage: "+command+" version [--json]\n"))
		}
		_, _ = fmt.Fprintln(stderr, "version: invalid arguments; use version --help")
		return 64
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "version: unexpected arguments; use version --help")
		return 64
	}
	report := Capture(command)
	var raw []byte
	if *jsonOutput {
		var err error
		raw, err = json.Marshal(report)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "version: cannot encode build report")
			return 70
		}
		raw = append(raw, '\n')
	} else {
		var text bytes.Buffer
		fmt.Fprintln(&text, report.Command)
		if report.Source == nil {
			fmt.Fprintln(&text, "source: unavailable")
		} else {
			status := "unmodified"
			if report.Source.Modified {
				status = "modified"
			}
			fmt.Fprintf(&text, "source: git %s (%s)\n", report.Source.Revision, status)
		}
		fmt.Fprintf(&text, "go: %s\ntarget: %s/%s\n", report.GoVersion, report.OS, report.Architecture)
		raw = text.Bytes()
	}
	return writeOutput(stdout, stderr, raw)
}

func writeOutput(stdout, stderr io.Writer, raw []byte) int {
	n, err := stdout.Write(raw)
	if err != nil || n != len(raw) {
		_, _ = fmt.Fprintln(stderr, "version: cannot write build report")
		return 70
	}
	return 0
}
