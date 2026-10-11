package conformance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// Check the opened descriptor before reading or creating an export. This is
// not an ownership sandbox or a snapshot of concurrently modified contents.
func checkedCandidateBinaryInput(path string, openFile func(string) (*os.File, error)) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > candidateBinaryLimit {
		return nil, 0, os.ErrInvalid
	}
	before, err = candidateBinaryIdentity(path, before)
	if err != nil {
		return nil, 0, err
	}
	file, err := openFile(path)
	if err != nil {
		return nil, 0, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() != before.Size() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, 0, os.ErrInvalid
	}
	return file, after.Size(), nil
}

func openCandidateBinary(path string) (io.ReadCloser, int64, error) {
	file, size, err := checkedCandidateBinaryInput(path, openCandidateBinaryInput)
	if err != nil {
		return nil, 0, errors.New("candidate binary is not a bounded regular file")
	}
	return file, size, nil
}

func candidateBinaryDigest(path string) (string, int64, error) {
	input, size, err := openCandidateBinary(path)
	if err != nil {
		return "", 0, err
	}
	digest, err := readCandidateBinary(input, size, io.Discard)
	if err != nil {
		return "", 0, errors.New("candidate binary read failed")
	}
	return digest, size, nil
}

// Read the exact opened length, require real EOF, and close the input on every
// path. No digest is returned for a read, write, size, EOF or close failure.
func readCandidateBinary(input io.ReadCloser, size int64, output io.Writer) (string, error) {
	digest := sha256.New()
	readErr := os.ErrInvalid
	if size > 0 && size <= candidateBinaryLimit {
		var n int64
		n, readErr = io.CopyBuffer(io.MultiWriter(output, digest), io.LimitReader(input, size), make([]byte, 32<<10))
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
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func copyCandidateBinary(input io.ReadCloser, size int64, output io.WriteCloser, expectedSHA string) error {
	digest, readErr := readCandidateBinary(input, size, output)
	closeErr := output.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if digest != expectedSHA {
		return os.ErrInvalid
	}
	return nil
}
