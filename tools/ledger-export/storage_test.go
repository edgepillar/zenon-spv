// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb/storage"
)

func TestMissingLockIsNeverCreated(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	if err := os.Remove(filepath.Join(path, "LOCK")); err != nil {
		t.Fatal(err)
	}
	before := image(t, path)
	var out, meta bytes.Buffer
	if run(context.Background(), arguments(path), &out, &meta, openReadOnly) != 1 || out.Len() != 0 || receipt(t, meta.Bytes())["status"] != "UNKNOWN" {
		t.Fatal("missing lock accepted")
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(image(t, path))
	if !bytes.Equal(a, b) {
		t.Fatal("read-only input created a lock or changed files")
	}
}

func TestStorageWriteMethodsNeverTouchInput(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	before := image(t, path)
	s := &readOnlyStorage{path: path}
	fd, err := s.GetMeta()
	if err != nil {
		t.Fatal(err)
	}
	if s.SetMeta(fd) == nil || s.Remove(fd) == nil || s.Rename(fd, storage.FileDesc{Type: storage.TypeManifest, Num: 999999}) == nil {
		t.Fatal("mutator accepted")
	}
	if writer, err := s.Create(fd); err == nil || writer != nil {
		t.Fatal("writer opened")
	}
	s.Log("private storage log must not be written")
	lock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lock(); !errors.Is(err, storage.ErrLocked) {
		t.Fatal("duplicate lease accepted")
	}
	lock.Unlock()
	lock, err = s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	lock.Unlock()
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("storage close")
	}
	if _, err = s.Open(fd); !errors.Is(err, storage.ErrClosed) {
		t.Fatal("closed reader")
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(image(t, path))
	if !bytes.Equal(a, b) {
		t.Fatal("mutator touched input")
	}
}

func TestDescriptorSelectionRejectsAmbiguousNames(t *testing.T) {
	for _, name := range []string{"MANIFEST-000001", "000001.log", "000001.ldb", "000001.sst", "000001.tmp"} {
		if _, ok := parseDescriptor(name); !ok {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"../000001.ldb", "MANIFEST-+00001", "MANIFEST-0000001", "000001.ldb/extra", "000001.log\n", "-00001.ldb", "9223372036854775808.ldb", "CURRENT", "LOCK"} {
		if _, ok := parseDescriptor(name); ok {
			t.Fatal("noncanonical descriptor accepted")
		}
	}
	path := t.TempDir()
	for _, name := range []string{"000001.ldb", "000001.sst"} {
		if os.WriteFile(filepath.Join(path, name), []byte("owned alias control"), 0600) != nil {
			t.Fatal("fixture")
		}
	}
	if _, err := (&readOnlyStorage{path: path}).List(storage.TypeAll); err == nil {
		t.Fatal("ambiguous table aliases accepted")
	}
}

func TestCurrentMustSelectOneCanonicalManifest(t *testing.T) {
	for _, text := range []string{"MANIFEST-000001", "MANIFEST-000001\nextra\n", "../MANIFEST-000001\n", "000001.ldb\n", "MANIFEST-0000001\n", "\n"} {
		path := t.TempDir()
		if err := os.WriteFile(filepath.Join(path, "CURRENT"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := (&readOnlyStorage{path: path}).GetMeta(); err == nil {
			t.Fatal("invalid current accepted")
		}
	}
}
