package verify

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStateInputTypeAndSizePrecedeOpen(t *testing.T) {
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized.json")
	f, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxStateFileBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		want       error
	}{
		{"directory", dir, ErrStateFileNotRegular},
		{"oversized", oversized, ErrStateFileTooLarge},
		{"missing", filepath.Join(dir, "missing"), os.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			file, info, err := openStateInput(tc.path, func(string) (*os.File, error) {
				called = true
				return nil, os.ErrPermission
			})
			if called || file != nil || info != nil || !errors.Is(err, tc.want) {
				t.Fatal("invalid path reached open or exposed an input")
			}
		})
	}
}

func TestStateInputOpenedDescriptorCheckedAndClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("ordinary input"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"directory", "oversized", "stat failure", "open failure"} {
		t.Run(mode, func(t *testing.T) {
			var opened *os.File
			file, info, err := openStateInput(path, func(name string) (*os.File, error) {
				if mode == "open failure" {
					return nil, os.ErrPermission
				}
				var err error
				if mode == "directory" {
					opened, err = os.Open(dir)
				} else {
					opened, err = os.OpenFile(name, os.O_RDWR, 0)
				}
				if err != nil {
					t.Fatal("cannot prepare descriptor control")
				}
				if mode == "oversized" {
					if err := opened.Truncate(MaxStateFileBytes + 1); err != nil {
						_ = opened.Close()
						t.Fatal(err)
					}
				} else if mode == "stat failure" {
					if err := opened.Close(); err != nil {
						t.Fatal(err)
					}
				}
				return opened, nil
			})
			want := map[string]error{"directory": ErrStateFileNotRegular, "oversized": ErrStateFileTooLarge,
				"stat failure": os.ErrClosed, "open failure": os.ErrPermission}[mode]
			if file != nil || info != nil || !errors.Is(err, want) {
				t.Fatal("opened descriptor bypassed type, size, or error handling")
			}
			if opened != nil {
				if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("rejected descriptor was not closed")
				}
			}
			// Each control begins with a regular small path; the oversized
			// descriptor must be reached after, not before, the initial stat.
			if err := os.WriteFile(path, []byte("ordinary input"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStateInputRegularFileAndSymlinkReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	raw := []byte("ordinary input")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ordinary", "regular symlink"} {
		t.Run(mode, func(t *testing.T) {
			selected := path
			if mode == "regular symlink" {
				selected = filepath.Join(dir, "alias.json")
				if err := os.Symlink(path, selected); err != nil {
					t.Skip("symlink creation is unavailable")
				}
			}
			file, info, err := openStateInput(selected, openReadOnlyStateFile)
			if err != nil {
				t.Fatal("ordinary file target refused")
			}
			defer func() { _ = file.Close() }()
			got, err := io.ReadAll(file)
			if err != nil || string(got) != string(raw) || !info.Mode().IsRegular() || info.Size() != int64(len(raw)) {
				t.Fatal("ordinary file read or size hint changed")
			}
		})
	}
}
