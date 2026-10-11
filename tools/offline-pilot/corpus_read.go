package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// On a stable tree these files already fit the source fingerprint ceiling.
// Recheck the aggregate at corpus capture rather than trusting earlier sizes.
const maxCorpusBytes = maxSourceBytes

func hashCorpusInputs(paths []string, openFile func(string) (*os.File, error)) ([]corpusRecord, error) {
	corpus := make([]corpusRecord, 0, len(paths))
	buffer := make([]byte, 32<<10)
	remaining := int64(maxCorpusBytes)
	for _, path := range paths {
		f, size, err := checkedSourceInput(path, remaining, openFile)
		if err != nil {
			return nil, err
		}
		digest, err := corpusDigest(f, size, buffer)
		if err != nil {
			return nil, err
		}
		corpus = append(corpus, corpusRecord{Path: path, SHA256: digest})
		remaining -= size
	}
	return corpus, nil
}

// Hash raw content only, with no path or length prefix. Always close the input;
// an incomplete read or failed close must not yield a usable corpus digest.
func corpusDigest(input io.ReadCloser, size int64, buffer []byte) (string, error) {
	h := sha256.New()
	readErr := copySourceBytes(h, input, size, buffer)
	closeErr := input.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
