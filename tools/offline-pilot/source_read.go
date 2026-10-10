package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// Match the independent exported-candidate checker's aggregate source ceiling.
// The buffer is shared across members; source bytes are never held wholesale.
const maxSourceBytes = 64 << 20

func checkedSourceInput(path string, remaining int64, openFile func(string) (*os.File, error)) (*os.File, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > remaining {
		return nil, 0, os.ErrInvalid
	}
	f, err := openFile(path)
	if err != nil {
		return nil, 0, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > remaining {
		_ = f.Close()
		return nil, 0, os.ErrInvalid
	}
	return f, info.Size(), nil
}

func sourceModuleMatches() bool {
	f, _, err := checkedSourceInput("go.mod", maxSourceBytes, openSourceInput)
	if err != nil {
		return false
	}
	// Only the fixed module line is needed here. ReadSlice refuses a larger
	// first line without allocating a file-sized module buffer.
	line, readErr := bufio.NewReaderSize(f, 128).ReadSlice('\n')
	closeErr := f.Close()
	return (readErr == nil || readErr == io.EOF) && closeErr == nil &&
		strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r") == "module "+modulePath
}

func hashSourceInputs(paths []string, openFile func(string) (*os.File, error)) (string, error) {
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	remaining := int64(maxSourceBytes)
	for _, path := range paths {
		f, size, err := checkedSourceInput(path, remaining, openFile)
		if err != nil {
			return "", err
		}
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(path))))
		_, _ = io.WriteString(h, path)
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(size)))
		readErr := copySourceBytes(h, f, size, buffer)
		closeErr := f.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		remaining -= size
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Descriptor size binds the length prefix, then exactly that many bytes and
// EOF must be observed. Growth, shrinkage or any read error discards the entire
// fingerprint. Stable same-size paths/contents remain the caller's obligation.
func copySourceBytes(output io.Writer, input io.Reader, size int64, buffer []byte) error {
	if size < 0 || size > maxSourceBytes || len(buffer) == 0 {
		return os.ErrInvalid
	}
	n, err := io.CopyBuffer(output, io.LimitReader(input, size), buffer)
	if err != nil {
		return err
	}
	if n != size {
		return io.ErrUnexpectedEOF
	}
	var overflow [1]byte
	next, err := io.ReadFull(input, overflow[:])
	if next != 0 || err != io.EOF {
		if err != nil && err != io.EOF {
			return err
		}
		return os.ErrInvalid
	}
	return nil
}
