package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/0x3639/zenon-spv/internal/buildinfo"
)

const candidateExportEnvironment = "ZENON_SPV_PILOT_EXPORT_DIR"
const candidateBinaryLimit = 128 << 20

type candidateFile struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}

type candidateBinary struct {
	Command string `json:"command"`
	candidateFile
}

type candidateManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Mode          string            `json:"mode"`
	TestStatus    string            `json:"test_status"`
	OS            string            `json:"os"`
	Architecture  string            `json:"architecture"`
	GoVersion     string            `json:"go_version"`
	Source        sourceRecord      `json:"source"`
	Corpus        []corpusRecord    `json:"corpus"`
	Report        candidateFile     `json:"report"`
	Binaries      []candidateBinary `json:"binaries"`
}

// Only a fresh directory outside the checkout can receive exports. Its parent
// and the running tests remain trusted; this is not an ownership/ACL sandbox.
func prepareCandidateDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("invalid candidate directory")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", errors.New("candidate parent unavailable")
	}
	path = filepath.Join(parent, filepath.Base(path))
	cwd, err := os.Getwd()
	if err != nil {
		return "", errors.New("source directory unavailable")
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", errors.New("source directory unavailable")
	}
	rel, err := filepath.Rel(cwd, path)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("candidate directory is inside the checkout")
	}
	if err != nil && strings.EqualFold(filepath.VolumeName(cwd), filepath.VolumeName(path)) {
		return "", errors.New("candidate directory cannot be resolved")
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return "", errors.New("candidate directory cannot be created")
	}
	return path, nil
}

func candidateCommands() []string {
	var commands []string
	for _, s := range scenarios {
		for _, command := range s.Commands {
			if !slices.Contains(commands, command) {
				commands = append(commands, command)
			}
		}
	}
	slices.Sort(commands)
	return commands
}

// Finalization never rebuilds a command. It binds exported bytes to every
// scenario's recorded execution hash and writes the manifest last.
func finalizeCandidate(dir string, report pilotReport, raw []byte) error {
	if report.SchemaVersion != 1 || report.Mode != "offline_synthetic" || report.Error != nil ||
		!report.InputsUnchanged || (report.Status != "passed" && report.Status != "passed_with_skips") ||
		!hexDigest(report.Source.InputsSHA256, 64) || len(report.Cases) != len(scenarios) || len(raw) > 4<<20 ||
		report.Runner.OS != runtime.GOOS || report.Runner.Architecture != runtime.GOARCH || len(report.Corpus) != len(corpusPaths) {
		return errors.New("candidate requires complete successful execution")
	}
	canonical, err := json.MarshalIndent(report, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return errors.New("candidate report bytes are inconsistent")
	}
	for i, corpus := range report.Corpus {
		if corpus.Path != corpusPaths[i] || !hexDigest(corpus.SHA256, 64) {
			return errors.New("candidate corpus records are incomplete")
		}
	}
	commands := candidateCommands()
	digests := make(map[string]string)
	skipped := false
	for i, result := range report.Cases {
		expected := scenarios[i]
		if result.ID != expected.ID || result.Package != expected.Package || result.Test != expected.Test ||
			result.Failed != 0 || result.Passed < 0 || result.Skipped < 0 ||
			(result.Status != "passed" && result.Status != "passed_with_skips") ||
			(result.Status == "passed_with_skips") != (result.Skipped > 0) || len(result.Binaries) != len(expected.Commands) {
			return errors.New("candidate execution is inconsistent")
		}
		skipped = skipped || result.Skipped > 0
		seen := make(map[string]bool)
		for _, binary := range result.Binaries {
			if !slices.Contains(expected.Commands, binary.Command) || seen[binary.Command] || !hexDigest(binary.SHA256, 64) ||
				(digests[binary.Command] != "" && digests[binary.Command] != binary.SHA256) {
				return errors.New("candidate executable records disagree")
			}
			seen[binary.Command], digests[binary.Command] = true, binary.SHA256
		}
	}
	if len(digests) != len(commands) || (report.Status == "passed_with_skips") != skipped {
		return errors.New("candidate execution is incomplete")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(commands) {
		return errors.New("candidate directory is incomplete or contains extra files")
	}
	manifest := candidateManifest{
		SchemaVersion: 1, Mode: "offline_synthetic_candidate", TestStatus: report.Status,
		OS: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: buildinfo.Capture("offline-pilot").GoVersion,
		Source: report.Source, Corpus: report.Corpus,
		Report: candidateFile{Filename: "offline-pilot.json", SHA256: digestBytes(raw), Bytes: int64(len(raw))},
	}
	for i, command := range commands {
		filename := command
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		if entries[i].Name() != filename {
			return errors.New("candidate directory contains unexpected files")
		}
		digest, size, err := candidateFileDigest(filepath.Join(dir, filename))
		if err != nil || digest != digests[command] {
			return errors.New("candidate executable differs from tested bytes")
		}
		manifest.Binaries = append(manifest.Binaries, candidateBinary{Command: command,
			candidateFile: candidateFile{Filename: filename, SHA256: digest, Bytes: size}})
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("candidate manifest encoding failed")
	}
	if err := writeCandidateFile(filepath.Join(dir, manifest.Report.Filename), raw); err != nil {
		return err
	}
	return writeCandidateFile(filepath.Join(dir, "manifest.json"), append(encoded, '\n'))
}

func candidateFileDigest(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > candidateBinaryLimit {
		return "", 0, errors.New("candidate executable is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("candidate executable cannot be read")
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(file, candidateBinaryLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || n != info.Size() || n > candidateBinaryLimit {
		return "", 0, errors.New("candidate executable read failed")
	}
	return hex.EncodeToString(digest.Sum(nil)), n, nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func writeCandidateFile(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("candidate metadata cannot be created")
	}
	n, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || n != len(raw) {
		_ = os.Remove(path) // Only this newly created, incomplete file is removed.
		return errors.New("candidate metadata write failed")
	}
	return nil
}
