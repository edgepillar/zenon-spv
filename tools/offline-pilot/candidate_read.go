package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// Recheck the descriptor before reading. Linux/macOS share the nonblocking,
// no-follow open used for source inputs; export parents remain caller-owned.
func checkedCandidateInput(path string, openFile func(string) (*os.File, error)) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > candidateBinaryLimit {
		return nil, 0, os.ErrInvalid
	}
	before, err = candidateIdentityInfo(path, before)
	if err != nil {
		return nil, 0, err
	}
	f, err := openFile(path)
	if err != nil {
		return nil, 0, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() != before.Size() || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, 0, os.ErrInvalid
	}
	return f, after.Size(), nil
}

func candidateFileDigest(path string) (string, int64, error) {
	f, size, err := checkedCandidateInput(path, openSourceInput)
	if err != nil {
		return "", 0, errors.New("candidate executable is not a bounded regular file")
	}
	digest, err := candidateDigest(f, size)
	if err != nil {
		return "", 0, errors.New("candidate executable read failed")
	}
	return digest, size, nil
}

// Hash the exact opened length and observe real EOF before closing. A failed
// read or close returns no digest. This does not freeze same-size file contents.
func candidateDigest(input io.ReadCloser, size int64) (string, error) {
	h := sha256.New()
	readErr := os.ErrInvalid
	if size > 0 && size <= candidateBinaryLimit {
		var n int64
		n, readErr = io.CopyBuffer(h, io.LimitReader(input, size), make([]byte, 32<<10))
		if readErr == nil && n != size {
			readErr = io.ErrUnexpectedEOF
		}
		if readErr == nil {
			var next [1]byte
			nextN, err := io.ReadFull(input, next[:])
			if nextN != 0 || err != io.EOF {
				readErr = os.ErrInvalid
				if err != nil && err != io.EOF {
					readErr = err
				}
			}
		}
	}
	closeErr := input.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
