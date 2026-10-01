package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestScheduleOutputPreservesAliases(t *testing.T) {
	headers, preimages := makeChain(t, 6)
	a, b := startPeer(t, headers, preimages, nil), startPeer(t, headers, preimages, nil)
	defer a.Close()
	defer b.Close()
	for _, mode := range []string{"symlink", "hard link"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			original, output := filepath.Join(dir, "PRIVATE_ORIGINAL.json"), filepath.Join(dir, "PRIVATE_OUTPUT.json")
			before := []byte("previous schedule")
			if err := os.WriteFile(original, before, 0o600); err != nil {
				t.Fatal(err)
			}
			link := os.Link
			if mode == "symlink" {
				link = os.Symlink
			}
			if err := link(original, output); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			err := run([]string{"--peers", a.URL + "," + b.URL, "--chain-id", "99",
				"--from", "1001", "--through", "1006", "--out", output})
			if (mode == "symlink" && err == nil) || (mode == "hard link" && err != nil) {
				t.Fatalf("unexpected publication outcome: %v", err)
			}
			after, readErr := os.ReadFile(original)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("schedule publication changed another directory entry's file")
			}
		})
	}
}

type failedScheduleFile struct {
	scheduleOutputFile
	point string
	cause error
}

func (f failedScheduleFile) Write(p []byte) (int, error) {
	if f.point == "write" || f.point == "short write" {
		n, err := f.scheduleOutputFile.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		if f.point == "short write" {
			return n, nil
		}
		return n, f.cause
	}
	return f.scheduleOutputFile.Write(p)
}

func (f failedScheduleFile) Sync() error {
	if f.point == "sync" {
		return f.cause
	}
	return f.scheduleOutputFile.Sync()
}

func (f failedScheduleFile) Close() error {
	err := f.scheduleOutputFile.Close()
	if f.point == "close" {
		return f.cause
	}
	return err
}

func TestSchedulePublicationFailureBoundaries(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, point := range []string{"create", "write", "short write", "sync", "close", "rename", "directory sync", "success"} {
			t.Run(point+map[bool]string{false: "/new", true: "/replace"}[existing], func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "PRIVATE_SCHEDULE.json")
				var before os.FileInfo
				if existing {
					if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
						t.Fatal(err)
					}
					var err error
					before, err = os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				fault := errors.New("PRIVATE_FILESYSTEM_ERROR")
				fs := defaultScheduleOutputIO()
				create, rename := fs.createTemp, fs.rename
				fs.createTemp = func(dir string) (scheduleOutputFile, error) {
					if point == "create" {
						return nil, fault
					}
					f, err := create(dir)
					if err != nil {
						return nil, err
					}
					return failedScheduleFile{f, point, fault}, nil
				}
				replaced, syncedDirectory := false, false
				fs.rename = func(src, dest string) error {
					if point == "rename" {
						return fault
					}
					err := rename(src, dest)
					replaced = err == nil
					return err
				}
				fs.syncDir = func(string) error {
					if !replaced {
						t.Fatal("directory sync preceded replacement")
					}
					syncedDirectory = true
					if point == "directory sync" {
						return fault
					}
					return nil
				}
				data := []byte("new schedule bytes")
				err := publishScheduleOutput(path, data, fs)
				if point == "success" {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					want := fault
					if point == "short write" {
						want = io.ErrShortWrite
					}
					if !errors.Is(err, want) || strings.Contains(err.Error(), "PRIVATE") {
						t.Fatal("publication failure lost its cause or disclosed private details")
					}
				}
				visible := point == "success" || point == "directory sync"
				if replaced != visible || syncedDirectory != visible {
					t.Fatal("failure crossed the publication boundary")
				}
				if point == "directory sync" && !strings.Contains(err.Error(), "new output is visible") {
					t.Fatal("post-replacement failure concealed uncertain durability")
				}
				after, readErr := os.ReadFile(path)
				switch {
				case visible:
					if readErr != nil || !bytes.Equal(after, data) {
						t.Fatal("publication did not expose the complete new bytes")
					}
					info, err := os.Stat(path)
					if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
						t.Fatal("published schedule lost private permissions")
					}
				case existing:
					info, err := os.Stat(path)
					if readErr != nil || string(after) != "old" || err != nil || !os.SameFile(before, info) ||
						before.Mode() != info.Mode() || !before.ModTime().Equal(info.ModTime()) {
						t.Fatal("pre-replacement failure changed the existing output")
					}
				default:
					if !os.IsNotExist(readErr) {
						t.Fatal("pre-replacement failure created an output")
					}
				}
				files, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					if strings.HasPrefix(file.Name(), ".spv-schedule-") {
						t.Fatal("publication left staged bytes behind")
					}
				}
			})
		}
	}
}

func TestScheduleOutputRechecksDestination(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, "schedule.json"), filepath.Join(dir, "other.json")
	if err := os.WriteFile(target, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Check support before the injected staging callback runs.
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fs := defaultScheduleOutputIO()
	create := fs.createTemp
	fs.createTemp = func(dir string) (scheduleOutputFile, error) {
		if err := os.Symlink(target, path); err != nil {
			return nil, err
		}
		return create(dir)
	}
	fs.rename = func(string, string) error {
		t.Fatal("late symlink reached replacement")
		return nil
	}
	if err := publishScheduleOutput(path, []byte("new"), fs); err == nil {
		t.Fatal("late symlink accepted")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "other" {
		t.Fatal("late symlink changed another file")
	}
}

func TestScheduleInvalidOutputPrecedesRPC(t *testing.T) {
	var requests atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer peer.Close()
	dir := t.TempDir()
	for _, output := range []string{dir, filepath.Join(dir, "PRIVATE_MISSING", "schedule.json"), dir + string(os.PathSeparator)} {
		err := run([]string{"--peers", peer.URL + "/a," + peer.URL + "/b", "--from", "2", "--through", "3", "--out", output})
		if err == nil || requests.Load() != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid output reached RPC or disclosed its path")
		}
	}
}
