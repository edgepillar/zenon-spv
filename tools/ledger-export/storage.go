// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb/storage"
)

// The upstream filesystem constructor can create a missing LOCK even when
// ReadOnly is requested. This adapter has no filesystem write operation.
// CURRENT must already select one canonical manifest; no repair is attempted.
const maxInputFiles = 100_000 // provisional directory accounting cap, not a protocol limit
var readOnlyError = errors.New("read-only input storage")

type inputLock struct {
	file     *os.File
	once     sync.Once
	released atomic.Bool
	err      error
}

func (l *inputLock) Unlock() { l.once.Do(func() { l.err = l.file.Close(); l.released.Store(true) }) }

type readOnlyStorage struct {
	path   string
	mu     sync.Mutex
	closed bool
	lock   *inputLock
}

var _ storage.Storage = (*readOnlyStorage)(nil)

func (s *readOnlyStorage) available() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storage.ErrClosed
	}
	return nil
}
func (s *readOnlyStorage) Lock() (storage.Locker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, storage.ErrClosed
	}
	if s.lock != nil && !s.lock.released.Load() {
		return nil, storage.ErrLocked
	}
	file, err := lockExistingInput(filepath.Join(s.path, "LOCK"))
	if err != nil {
		return nil, err
	}
	s.lock = &inputLock{file: file}
	return s.lock, nil
}
func (s *readOnlyStorage) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	lock := s.lock
	s.mu.Unlock()
	if lock != nil {
		lock.Unlock()
		return lock.err
	}
	return nil
}
func (*readOnlyStorage) Log(string)                                      {}
func (*readOnlyStorage) SetMeta(storage.FileDesc) error                  { return readOnlyError }
func (*readOnlyStorage) Create(storage.FileDesc) (storage.Writer, error) { return nil, readOnlyError }
func (*readOnlyStorage) Remove(storage.FileDesc) error                   { return readOnlyError }
func (*readOnlyStorage) Rename(storage.FileDesc, storage.FileDesc) error { return readOnlyError }

func inputFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, storage.ErrInvalidFile
	}
	file, err := openExistingInput(path)
	if err != nil {
		return nil, err
	}
	inside, err := file.Stat()
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil || !inside.Mode().IsRegular() || !os.SameFile(before, inside) || !os.SameFile(after, inside) {
		file.Close()
		return nil, storage.ErrInvalidFile
	}
	return file, nil
}

func parseDescriptor(name string) (storage.FileDesc, bool) {
	var fd storage.FileDesc
	number := ""
	if strings.HasPrefix(name, "MANIFEST-") {
		fd.Type = storage.TypeManifest
		number = strings.TrimPrefix(name, "MANIFEST-")
	} else {
		for _, kind := range []struct {
			suffix string
			typeID storage.FileType
		}{{".log", storage.TypeJournal}, {".ldb", storage.TypeTable}, {".sst", storage.TypeTable}, {".tmp", storage.TypeTemp}} {
			if strings.HasSuffix(name, kind.suffix) {
				fd.Type = kind.typeID
				number = strings.TrimSuffix(name, kind.suffix)
				break
			}
		}
	}
	if len(number) < 6 || len(number) > 19 {
		return fd, false
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return fd, false
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n < 0 {
		return fd, false
	}
	fd.Num = n
	canonical := fd.String()
	if strings.HasSuffix(name, ".sst") {
		canonical = strings.TrimSuffix(canonical, ".ldb") + ".sst"
	}
	return fd, name == canonical && storage.FileDescOk(fd)
}

func (s *readOnlyStorage) GetMeta() (storage.FileDesc, error) {
	if err := s.available(); err != nil {
		return storage.FileDesc{}, err
	}
	file, err := inputFile(filepath.Join(s.path, "CURRENT"))
	if err != nil {
		return storage.FileDesc{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(raw) == 0 || len(raw) > 64 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		return storage.FileDesc{}, storage.ErrInvalidFile
	}
	fd, ok := parseDescriptor(string(raw[:len(raw)-1]))
	if !ok || fd.Type != storage.TypeManifest {
		return storage.FileDesc{}, storage.ErrInvalidFile
	}
	return fd, nil
}

func (s *readOnlyStorage) List(kind storage.FileType) ([]storage.FileDesc, error) {
	if err := s.available(); err != nil {
		return nil, err
	}
	directory, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	seen := map[storage.FileDesc]bool{}
	var result []storage.FileDesc
	count := 0
	for {
		page, readErr := directory.ReadDir(256)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		for _, entry := range page {
			count++
			if count > maxInputFiles {
				return nil, storage.ErrInvalidFile
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil, storage.ErrInvalidFile
			}
			if fd, ok := parseDescriptor(entry.Name()); ok {
				if seen[fd] {
					return nil, storage.ErrInvalidFile
				}
				seen[fd] = true
				if fd.Type&kind != 0 {
					result = append(result, fd)
				}
			}
		}
		if readErr == io.EOF {
			return result, nil
		}
	}
}

func (s *readOnlyStorage) Open(fd storage.FileDesc) (storage.Reader, error) {
	if err := s.available(); err != nil {
		return nil, err
	}
	if !storage.FileDescOk(fd) {
		return nil, storage.ErrInvalidFile
	}
	file, err := inputFile(filepath.Join(s.path, fd.String()))
	if os.IsNotExist(err) && fd.Type == storage.TypeTable {
		return inputFile(filepath.Join(s.path, strings.TrimSuffix(fd.String(), ".ldb")+".sst"))
	}
	return file, err
}
