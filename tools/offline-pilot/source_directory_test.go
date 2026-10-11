package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type sourceTestEntry struct {
	name string
	mode fs.FileMode
}

func (e sourceTestEntry) Name() string               { return e.name }
func (e sourceTestEntry) IsDir() bool                { return e.mode.IsDir() }
func (e sourceTestEntry) Type() fs.FileMode          { return e.mode }
func (e sourceTestEntry) Info() (fs.FileInfo, error) { return nil, os.ErrInvalid }

type sourceTestDirectory struct {
	remaining int
	next      func(int) os.DirEntry
	readErr   error
	closeErr  error
	empty     bool
	oversized bool
	index     int
	maxPage   int
	closed    bool
}

func (d *sourceTestDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	if n <= 0 || d.closed {
		return nil, os.ErrInvalid
	}
	d.maxPage = max(d.maxPage, n)
	if d.empty {
		return nil, nil
	}
	count := min(n, d.remaining)
	if d.oversized {
		count = n + 1
	}
	page := make([]os.DirEntry, count)
	for i := range page {
		page[i] = d.next(d.index)
		d.index++
	}
	d.remaining -= count
	if d.readErr != nil {
		return page, d.readErr
	}
	if d.remaining == 0 {
		return page, io.EOF // Exercise a final partial page together with EOF.
	}
	return page, nil
}

func (d *sourceTestDirectory) Close() error { d.closed = true; return d.closeErr }

func TestSourceEnumerationBoundaries(t *testing.T) {
	ignored := func(i int) os.DirEntry { return sourceTestEntry{fmt.Sprintf("entry-%05d.txt", i), 0} }
	controls, refusals := 0, 0
	for _, selected := range []struct {
		name          string
		cmd, internal int
		mode          string
		depth         int
		refused       bool
	}{
		{name: "empty_roots"},
		{name: "exact_entry_ceiling_across_roots", cmd: maxSourceEntries - 1, internal: 1},
		{name: "ignored_entry_overflow_across_roots", cmd: maxSourceEntries, internal: 1, refused: true},
		{name: "last_permitted_depth", depth: maxSourceDepth},
		{name: "depth_overflow", depth: maxSourceDepth + 1, refused: true},
		{name: "open_error", mode: "open", refused: true},
		{name: "partial_page_read_error", cmd: 1, mode: "read", refused: true},
		{name: "close_error", mode: "close", refused: true},
		{name: "no_read_progress", mode: "empty", refused: true},
		{name: "oversized_page", mode: "oversized", refused: true},
		{name: "unselected_symlink", cmd: 1, mode: "symlink", refused: true},
	} {
		t.Run(selected.name, func(t *testing.T) {
			var opened []*sourceTestDirectory
			paths, err := sourceInputPaths(func(path string) (sourceDirectory, error) {
				if path == "cmd" && selected.mode == "open" {
					return nil, os.ErrPermission
				}
				d := &sourceTestDirectory{next: ignored}
				if path == "cmd" {
					d.remaining = selected.cmd
					switch selected.mode {
					case "read":
						d.readErr = os.ErrPermission
					case "close":
						d.closeErr = os.ErrPermission
					case "empty":
						d.empty = true
					case "oversized":
						d.oversized = true
					case "symlink":
						d.next = func(int) os.DirEntry { return sourceTestEntry{"PRIVATE_LINK.txt", os.ModeSymlink} }
					}
				}
				if path == "internal" {
					d.remaining = selected.internal
				}
				if selected.depth > 0 && strings.Split(filepath.ToSlash(path), "/")[0] == "cmd" {
					depth := len(strings.Split(filepath.ToSlash(path), "/"))
					if depth > maxSourceDepth {
						t.Fatal("over-depth directory was opened")
					}
					d.remaining = 1
					if depth < selected.depth {
						d.next = func(int) os.DirEntry { return sourceTestEntry{"d", os.ModeDir} }
					} else {
						d.next = func(int) os.DirEntry { return sourceTestEntry{"leaf.go", 0} }
					}
				}
				opened = append(opened, d)
				return d, nil
			})
			if (err != nil) != selected.refused || (selected.refused && paths != nil) {
				t.Fatal("directory boundary produced an unexpected selection")
			}
			for _, d := range opened {
				if !d.closed || d.maxPage > sourceDirectoryPage {
					t.Fatal("directory descriptor or page bound was violated")
				}
			}
			if !selected.refused && (len(paths) != 2+boolInt(selected.depth > 0) || !slices.IsSorted(paths)) {
				t.Fatal("valid enumeration lost module inputs or selected an ignored member")
			}
			controls++
			if selected.refused {
				refusals++
			}
		})
	}
	if controls != 11 || refusals != 8 {
		t.Fatal("incomplete source enumeration controls")
	}
	t.Log("offline-pilot-source-enumeration-controls {\"schema_version\":1,\"controls\":11,\"refusals\":8,\"entry_ceiling\":32768,\"depth_ceiling\":32,\"maximum_requested_page\":64,\"descriptors_closed\":true}")
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestSourceEnumerationPreservesFingerprint(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, root := range []string{"cmd", "internal", "tools"} {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal("cannot prepare source tree")
		}
	}
	for name, raw := range map[string][]byte{
		"go.mod": []byte("module " + modulePath + "\n"), "go.sum": nil,
		"internal/z.go": []byte("last"), "internal/A.json": []byte("fixture"),
		"cmd/é.go": []byte("unicode name"), "tools/go.mod": []byte("nested module"),
	} {
		if os.WriteFile(name, raw, 0600) != nil {
			t.Fatal("cannot prepare selected source")
		}
	}
	for i := range 3*sourceDirectoryPage + 1 {
		if os.WriteFile(filepath.Join("internal", fmt.Sprintf("ignored-%03d.txt", i)), nil, 0600) != nil {
			t.Fatal("cannot prepare multi-page directory")
		}
	}
	var historical []string
	for _, root := range []string{"cmd", "internal", "tools"} {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && (strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".json") || entry.Name() == "go.mod" || entry.Name() == "go.sum") {
				historical = append(historical, filepath.ToSlash(path))
			}
			return nil
		}); err != nil {
			t.Fatal("cannot reproduce historical selection")
		}
	}
	historical = append(historical, "go.mod", "go.sum")
	slices.Sort(historical)
	paths, err := sourceInputPaths(openSourceDirectory)
	if err != nil || !slices.Equal(paths, historical) {
		t.Fatal("paged source selection differs from historical lexical selection")
	}
	h := sha256.New()
	for _, name := range historical {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("cannot read historical input")
		}
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(name))))
		h.Write([]byte(name))
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
		h.Write(raw)
	}
	observed, err := hashSourceInputs(paths, openSourceInput)
	if err != nil || observed != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("bounded enumeration changed historical fingerprint bytes")
	}
	t.Log("offline-pilot-source-enumeration-encoding {\"schema_version\":1,\"historical_selection_and_bytes_matched\":true,\"selected_inputs\":6,\"ignored_entries\":193}")
}

func TestSourceDirectoryPreflight(t *testing.T) {
	root := t.TempDir()
	dir, regular := filepath.Join(root, "directory"), filepath.Join(root, "regular")
	if os.Mkdir(dir, 0700) != nil || os.WriteFile(regular, nil, 0600) != nil {
		t.Fatal("cannot prepare descriptor controls")
	}
	for _, path := range []string{filepath.Join(root, "missing"), regular} {
		opened := false
		d, err := checkedSourceDirectory(path, func(string) (*os.File, error) { opened = true; return nil, os.ErrInvalid })
		if err == nil || d != nil || opened {
			t.Fatal("non-directory path reached an open operation")
		}
	}
	for _, closed := range []bool{false, true} {
		f, err := os.Open(regular)
		if err != nil {
			t.Fatal("cannot prepare replacement descriptor")
		}
		if closed {
			if err := f.Close(); err != nil {
				t.Fatal("cannot prepare closed replacement descriptor")
			}
		}
		d, err := checkedSourceDirectory(dir, func(string) (*os.File, error) { return f, nil })
		if err == nil || d != nil {
			t.Fatal("non-directory or failed descriptor was accepted")
		}
		if _, err := f.Stat(); err == nil {
			t.Fatal("rejected directory descriptor was not closed")
		}
	}
	t.Log("offline-pilot-source-directory-preflight {\"schema_version\":1,\"refusals\":4,\"descriptors_closed\":true}")
}
