package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/0x3639/zenon-spv/internal/verify"
)

// The caller owns and protects the private run directory. Stage through one
// exclusively created handle; close it before verification or private cleanup.
func collectBundle(ctx context.Context, c configuration, path string) (result processResult) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return processResult{category: "input_unavailable", code: 70}
	}
	defer func() {
		if file.Close() != nil && result.category == "" {
			result.category, result.code = "input_unavailable", 70
		}
	}()
	result = runProcessOutput(ctx, c.collection.binary, collectionArguments(c), int(verify.DefaultMaxBundleBytes), c.timeout, file)
	if result.category != "" {
		return result
	}
	valid, err := stagedJSON(file, result.StdoutBytes)
	if err != nil {
		result.category, result.code = "input_unavailable", 70
	} else if !valid {
		result.category, result.code = "invalid_bundle", 2
	}
	return result
}

// Allocate exactly the completed byte count, only after the collector and both
// stream copies exit. Whole-document json.Valid retains the existing syntax and
// depth boundary without decoding evidence or accepting a partial document.
func stagedJSON(file *os.File, expected int64) (bool, error) {
	if expected < 0 || expected > verify.DefaultMaxBundleBytes {
		return false, errors.New("invalid staged size")
	}
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() != expected {
		return false, errors.New("staged size mismatch")
	}
	raw := make([]byte, int(expected))
	if n, err := file.ReadAt(raw, 0); err != nil || n != len(raw) {
		return false, errors.New("incomplete staged read")
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], expected); n != 0 || err != io.EOF {
		return false, errors.New("staged bytes changed")
	}
	return json.Valid(raw), nil
}
