package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConsumerInputDescriptors(t *testing.T) {
	t.Run("before open", func(t *testing.T) {
		dir := t.TempDir()
		for _, limit := range []int64{maxExpectationsBytes, maxReportBytes} {
			oversized := filepath.Join(t.TempDir(), "input.json")
			file, err := os.Create(oversized)
			if err != nil {
				t.Fatal("cannot create size control")
			}
			if err := file.Truncate(limit + 1); err != nil {
				_ = file.Close()
				t.Fatal("cannot prepare size control")
			}
			if err := file.Close(); err != nil {
				t.Fatal("cannot close size control")
			}
			for _, path := range []string{dir, oversized, filepath.Join(dir, "missing.json")} {
				called := false
				raw, err := readInputWithOpen(path, limit, func(string) (*os.File, error) {
					called = true
					return nil, os.ErrPermission
				})
				if called || raw != nil || !errors.Is(err, os.ErrInvalid) {
					t.Fatal("invalid type, size or missing path reached open")
				}
			}
		}
	})
	for _, mode := range []string{"directory", "oversized", "closed", "open failure", "ordinary"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			content := []byte("ordinary private input")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal("cannot prepare ordinary input")
			}
			var opened *os.File
			raw, err := readInputWithOpen(path, maxExpectationsBytes, func(name string) (*os.File, error) {
				if mode == "open failure" {
					return nil, os.ErrPermission
				}
				var err error
				if mode == "directory" {
					opened, err = os.Open(t.TempDir())
				} else {
					opened, err = os.OpenFile(name, os.O_RDWR, 0)
				}
				if err != nil {
					t.Fatal("cannot prepare descriptor control")
				}
				if mode == "oversized" {
					if err := opened.Truncate(maxExpectationsBytes + 1); err != nil {
						_ = opened.Close()
						t.Fatal("cannot grow descriptor control")
					}
				}
				if mode == "closed" {
					if err := opened.Close(); err != nil {
						t.Fatal("cannot close descriptor control")
					}
				}
				return opened, nil
			})
			if mode == "ordinary" {
				if err != nil || !bytes.Equal(raw, content) {
					t.Fatal("ordinary input bytes changed")
				}
			} else {
				want := os.ErrInvalid
				if mode == "open failure" {
					want = os.ErrPermission
				}
				if raw != nil || !errors.Is(err, want) {
					t.Fatal("opened descriptor bypassed validation")
				}
			}
			if opened != nil {
				if err := opened.Close(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("consumed or rejected descriptor was not closed")
				}
			}
		})
	}
}
