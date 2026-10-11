package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Match the independent exported-candidate checker. Count every child entry,
// including directories and unselected extensions; the three roots have depth 1.
const maxSourceEntries = 32768
const maxSourceDepth = 32
const sourceDirectoryPage = 64

type sourceDirectory interface {
	ReadDir(int) ([]os.DirEntry, error)
	Close() error
}

func openSourceDirectory(path string) (sourceDirectory, error) {
	return checkedSourceDirectory(path, openSourceInput)
}

func checkedSourceDirectory(path string, openFile func(string) (*os.File, error)) (sourceDirectory, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return nil, os.ErrInvalid
	}
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.IsDir() {
		_ = f.Close()
		return nil, os.ErrInvalid
	}
	return f, nil
}

// Read directory pages before sorting only selected paths. WalkDir would read
// an entire directory before an entry-count callback could refuse a wide tree.
// At most maxSourceDepth descriptors and one page per active level are retained.
func sourceInputPaths(openDirectory func(string) (sourceDirectory, error)) ([]string, error) {
	paths := []string{"go.mod", "go.sum"}
	entries := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if depth > maxSourceDepth {
			return os.ErrInvalid
		}
		dir, err := openDirectory(path)
		if err != nil {
			return err
		}
		readErr := func() error {
			for {
				// A single overflow entry proves refusal without reading a full
				// page beyond the remaining aggregate budget.
				n := min(sourceDirectoryPage, maxSourceEntries-entries+1)
				page, readErr := dir.ReadDir(n)
				if len(page) > n || (readErr != nil && readErr != io.EOF) {
					return os.ErrInvalid
				}
				for _, child := range page {
					entries++
					if entries > maxSourceEntries || child.Type()&os.ModeSymlink != 0 {
						return os.ErrInvalid
					}
					member := filepath.Join(path, child.Name())
					if child.IsDir() {
						if err := walk(member, depth+1); err != nil {
							return err
						}
					} else if strings.HasSuffix(child.Name(), ".go") || strings.HasSuffix(child.Name(), ".json") || child.Name() == "go.mod" || child.Name() == "go.sum" {
						paths = append(paths, filepath.ToSlash(member))
					}
				}
				if readErr == io.EOF {
					return nil
				}
				if len(page) == 0 {
					return io.ErrNoProgress
				}
			}
		}()
		closeErr := dir.Close()
		if readErr != nil {
			return readErr
		}
		return closeErr
	}
	for _, root := range []string{"cmd", "internal", "tools"} {
		if err := walk(root, 1); err != nil {
			return nil, err
		}
	}
	slices.Sort(paths)
	return paths, nil
}
