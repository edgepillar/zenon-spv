package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	if !sourceModuleMatches() {
		return record, errors.New("run the pilot from the repository root")
	}
	paths, err := sourceInputPaths(openSourceDirectory)
	if err != nil {
		return record, errors.New("cannot enumerate bounded source inputs")
	}
	fingerprint, err := hashSourceInputs(paths, openSourceInput)
	if err != nil {
		return record, errors.New("cannot read bounded source inputs")
	}
	record.InputsSHA256 = fingerprint
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
	return hashCorpusInputs(corpusPaths, openSourceInput)
}
