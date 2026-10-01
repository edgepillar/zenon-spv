package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type sourceRecord struct {
	Revision     *string `json:"revision"`
	Modified     *bool   `json:"modified"`
	InputsSHA256 string  `json:"inputs_sha256"`
}

type corpusRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Include test sources and fixtures, not only production code. Relative names
// and bytes are separately length-prefixed before hashing in lexical order.
// This is a local input fingerprint, not an authenticated source attestation.
func captureSource() (sourceRecord, error) {
	var record sourceRecord
	mod, err := os.ReadFile("go.mod")
	if err != nil || !strings.HasPrefix(string(mod), "module "+modulePath+"\n") {
		return record, errors.New("run the pilot from the repository root")
	}
	paths := []string{"go.mod", "go.sum"}
	for _, dir := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("symlinked source is unsupported")
			}
			if !entry.IsDir() && (strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".json") || entry.Name() == "go.mod" || entry.Name() == "go.sum") {
				paths = append(paths, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			return record, errors.New("cannot enumerate source inputs")
		}
	}
	slices.Sort(paths)
	h := sha256.New()
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return record, errors.New("source input is not a regular file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return record, errors.New("cannot read source input")
		}
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(path))))
		_, _ = io.WriteString(h, path)
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
		_, _ = h.Write(raw)
	}
	record.InputsSHA256 = hex.EncodeToString(h.Sum(nil))
	// Git may be unavailable in an exported source archive. Do not invent a
	// clean revision; the input fingerprint is still available in that case.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	git := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "git", args...)
		for _, env := range os.Environ() {
			if !strings.HasPrefix(strings.ToUpper(env), "GIT_") {
				cmd.Env = append(cmd.Env, env)
			}
		}
		return cmd.Output()
	}
	// An exported source directory inside an unrelated repository must not
	// inherit the enclosing repository's revision.
	top, topErr := git("rev-parse", "--show-toplevel")
	cwd, cwdErr := os.Getwd()
	root, rootErr := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	cwd, resolvedErr := filepath.EvalSymlinks(cwd)
	if topErr != nil || cwdErr != nil || rootErr != nil || resolvedErr != nil || root != cwd {
		return record, nil
	}
	revision, revErr := git("rev-parse", "--verify", "HEAD")
	status, statusErr := git("status", "--porcelain", "--untracked-files=normal")
	ref := strings.TrimSpace(string(revision))
	if revErr == nil && statusErr == nil && (hexDigest(ref, 40) || hexDigest(ref, 64)) {
		modified := len(status) != 0
		record.Revision, record.Modified = &ref, &modified
	}
	return record, nil
}

func captureCorpus() ([]corpusRecord, error) {
	corpus := make([]corpusRecord, 0, len(corpusPaths))
	for _, path := range corpusPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.New("cannot read pinned corpus")
		}
		sum := sha256.Sum256(raw)
		corpus = append(corpus, corpusRecord{Path: path, SHA256: hex.EncodeToString(sum[:])})
	}
	return corpus, nil
}
