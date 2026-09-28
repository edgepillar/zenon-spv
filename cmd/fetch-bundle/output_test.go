package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOutputCollisionPreservesFileBeforeRPC(t *testing.T) {
	peer, requests := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_PEERS", "")
	path := filepath.Join(t.TempDir(), "output.json")
	before := []byte("existing output")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--rpc", peer, "--height", "1006", "--count", "5", "--out", path, "--checkpoint", path})
	after, readErr := os.ReadFile(path)
	if err == nil || requests.Load() != 0 || readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("colliding outputs were not refused before RPC or overwrite: err=%v requests=%d unchanged=%t", err, requests.Load(), bytes.Equal(before, after))
	}
}

func TestOutputDestinationAliasesAndInvalidTypes(t *testing.T) {
	peer, requests := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_PEERS", "")
	for _, mode := range []string{"missing alias", "case alias", "cleaned alias", "relative alias", "parent symlink", "hard link", "file symlink", "dangling symlink", "directory", "missing directory", "stdout twice", "empty bundle", "trailing separator"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			bundle, checkpoint := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "checkpoint.json")
			before := []byte("original target")
			if err := os.WriteFile(bundle, before, 0o600); err != nil {
				t.Fatal(err)
			}
			original := bundle
			switch mode {
			case "missing alias":
				bundle = filepath.Join(dir, "new.json")
				checkpoint = bundle
			case "case alias":
				bundle = filepath.Join(dir, "new.json")
				checkpoint = filepath.Join(dir, "NEW.json")
			case "cleaned alias":
				checkpoint = dir + string(os.PathSeparator) + "." + string(os.PathSeparator) + "bundle.json"
			case "relative alias":
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				checkpoint, err = filepath.Rel(cwd, bundle)
				if err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				checkpoint = filepath.Join(alias, "bundle.json")
			case "hard link":
				if err := os.Link(bundle, checkpoint); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			case "file symlink", "dangling symlink":
				target := bundle
				if mode == "dangling symlink" {
					target = filepath.Join(dir, "missing.json")
				}
				if err := os.Symlink(target, checkpoint); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "directory":
				checkpoint = dir
			case "missing directory":
				checkpoint = filepath.Join(dir, "missing", "checkpoint.json")
			case "stdout twice":
				bundle, checkpoint = "-", "-"
			case "empty bundle":
				bundle = ""
			case "trailing separator":
				bundle += string(os.PathSeparator)
			}
			err := run([]string{"--rpc", peer, "--height", "1006", "--count", "5", "--out", bundle, "--checkpoint", checkpoint})
			if err == nil || requests.Load() != 0 {
				t.Fatalf("invalid destinations reached RPC: err=%v requests=%d", err, requests.Load())
			}
			after, err := os.ReadFile(original)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid destinations modified an existing file")
			}
			assertNoOutputTemps(t, dir)
		})
	}
}

func TestOutputPathPreservesSymlinkParentTraversal(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "real", "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	lexical := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(lexical, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := dir + "/link/../bundle.json"
	outputs, err := resolveOutputDestinations(path, "")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("intended output")
	if err := publishOutputs(outputs, [][]byte{data}, io.Discard, defaultOutputIO()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "real", "bundle.json"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("symlink parent traversal selected the wrong destination")
	}
	got, err = os.ReadFile(lexical)
	if err != nil || string(got) != "unrelated" {
		t.Fatal("lexical normalization overwrote an unrelated file")
	}
}

type outputWriterFunc func([]byte) (int, error)

func (f outputWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestOutputStdoutFollowsFilePublication(t *testing.T) {
	for _, stdoutIndex := range []int{0, 1} {
		for _, fail := range []bool{false, true} {
			outputs, data, dir := outputPair(t, true)
			outputs[stdoutIndex].path = "-"
			fileIndex := 1 - stdoutIndex
			writes := 0
			stdout := outputWriterFunc(func(p []byte) (int, error) {
				writes++
				got, err := os.ReadFile(outputs[fileIndex].path)
				if err != nil || !bytes.Equal(got, data[fileIndex]) || !bytes.Equal(p, data[stdoutIndex]) {
					t.Fatal("stdout preceded file publication or contained the wrong document")
				}
				if fail {
					return len(p) / 2, nil
				}
				return len(p), nil
			})
			err := publishOutputs(outputs, data, stdout, defaultOutputIO())
			if writes != 1 || (fail && (!errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "visible"))) || (!fail && err != nil) {
				t.Fatalf("stdout result: writes=%d err=%v", writes, err)
			}
			assertNoOutputTemps(t, dir)
		}
	}
}

func TestOutputStagingFailureDoesNotEmitStdout(t *testing.T) {
	outputs, data, dir := outputPair(t, true)
	outputs[0].path = "-"
	fault := errors.New("staging unavailable")
	fs := defaultOutputIO()
	fs.createTemp = func(string) (outputFile, error) { return nil, fault }
	var stdout bytes.Buffer
	if err := publishOutputs(outputs, data, &stdout, fs); !errors.Is(err, fault) || stdout.Len() != 0 {
		t.Fatalf("staging failure leaked stdout: %v", err)
	}
	assertNoOutputTemps(t, dir)
}

func TestOutputDestinationRecheckedAfterStaging(t *testing.T) {
	outputs, data, dir := outputPair(t, true)
	fs := defaultOutputIO()
	create := fs.createTemp
	calls := 0
	fs.createTemp = func(dir string) (outputFile, error) {
		calls++
		if calls == 2 {
			if err := os.Remove(outputs[1].path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(outputs[0].path, outputs[1].path); err != nil {
				t.Fatal(err)
			}
		}
		return create(dir)
	}
	fs.rename = func(string, string) error {
		t.Error("late alias was published")
		return errors.New("unexpected rename")
	}
	var stdout bytes.Buffer
	if err := publishOutputs(outputs, data, &stdout, fs); err == nil || !strings.Contains(err.Error(), "distinct destinations") || stdout.Len() != 0 {
		t.Fatalf("late output alias accepted: %v", err)
	}
	for _, o := range outputs {
		got, err := os.ReadFile(o.path)
		if err != nil || string(got) != "old" {
			t.Fatal("late alias changed destination bytes")
		}
	}
	assertNoOutputTemps(t, dir)
}

func outputPair(t *testing.T, existing bool) ([]outputDestination, [][]byte, string) {
	t.Helper()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "checkpoint.json")
	if existing {
		for _, path := range []string{a, b} {
			if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	outputs, err := resolveOutputDestinations(a, b)
	if err != nil {
		t.Fatal(err)
	}
	return outputs, [][]byte{[]byte("new bundle\n"), []byte("new checkpoint\n")}, dir
}

func assertNoOutputTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".spv-output-") {
			t.Fatal("staged output was not cleaned up")
		}
	}
}

type failedOutputFile struct {
	outputFile
	point string
	fault error
}

func (f failedOutputFile) Write(p []byte) (int, error) {
	if f.point == "write" || f.point == "short write" {
		n, err := f.outputFile.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		if f.point == "short write" {
			return n, nil
		}
		return n, f.fault
	}
	return f.outputFile.Write(p)
}

func (f failedOutputFile) Sync() error {
	if f.point == "sync" {
		return f.fault
	}
	return f.outputFile.Sync()
}

func (f failedOutputFile) Close() error {
	err := f.outputFile.Close()
	if f.point == "close" {
		return f.fault
	}
	return err
}

func TestOutputStagingFailuresPreserveBothDestinations(t *testing.T) {
	fault := errors.New("injected storage failure")
	for _, point := range []string{"create", "write", "short write", "sync", "close"} {
		t.Run(point, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				outputs, data, dir := outputPair(t, existing)
				fs := defaultOutputIO()
				create := fs.createTemp
				calls := 0
				fs.createTemp = func(dir string) (outputFile, error) {
					calls++
					if calls == 2 && point == "create" {
						return nil, fault
					}
					f, err := create(dir)
					if err != nil || calls != 2 {
						return f, err
					}
					return failedOutputFile{outputFile: f, point: point, fault: fault}, nil
				}
				fs.rename = func(string, string) error {
					t.Error("publication began before staging finished")
					return fault
				}
				var stdout bytes.Buffer
				err := publishOutputs(outputs, data, &stdout, fs)
				want := fault
				if point == "short write" {
					want = io.ErrShortWrite
				}
				if !errors.Is(err, want) || stdout.Len() != 0 {
					t.Fatalf("staging failure was hidden or emitted stdout: %v", err)
				}
				for _, o := range outputs {
					after, err := os.ReadFile(o.path)
					if existing && (err != nil || string(after) != "old") {
						t.Fatal("staging failure changed an existing output")
					}
					if !existing && !os.IsNotExist(err) {
						t.Fatal("staging failure published a new output")
					}
				}
				assertNoOutputTemps(t, dir)
			}
		})
	}
}

func TestOutputPublicationReplacesFilesAfterStaging(t *testing.T) {
	for _, existing := range []bool{false, true} {
		outputs, data, dir := outputPair(t, existing)
		fs := defaultOutputIO()
		rename := fs.rename
		renamed, synced := 0, 0
		fs.rename = func(from, to string) error {
			if renamed == 0 {
				staged, err := filepath.Glob(filepath.Join(dir, ".spv-output-*"))
				if err != nil || len(staged) != 2 {
					t.Fatal("both files were not staged before publication")
				}
			}
			renamed++
			return rename(from, to)
		}
		syncDir := fs.syncDir
		fs.syncDir = func(dir string) error { synced++; return syncDir(dir) }
		var stdout bytes.Buffer
		if err := publishOutputs(outputs, data, &stdout, fs); err != nil {
			t.Fatal(err)
		}
		if renamed != 2 || synced != 2 || stdout.Len() != 0 {
			t.Fatal("incorrect output publication sequence")
		}
		for i, o := range outputs {
			got, err := os.ReadFile(o.path)
			if err != nil || !bytes.Equal(got, data[i]) {
				t.Fatal("published output differs from staged bytes")
			}
			info, err := os.Stat(o.path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
				t.Fatalf("output permissions=%o", info.Mode().Perm())
			}
		}
		assertNoOutputTemps(t, dir)
	}
}

func TestOutputPublicationFailureReportsVisiblePrefix(t *testing.T) {
	fault := errors.New("injected publish failure")
	for _, point := range []string{"first rename", "second rename", "first directory sync", "second directory sync"} {
		t.Run(point, func(t *testing.T) {
			outputs, data, dir := outputPair(t, true)
			fs := defaultOutputIO()
			rename, syncDir := fs.rename, fs.syncDir
			renamed, synced := 0, 0
			fs.rename = func(from, to string) error {
				if (point == "first rename" && renamed == 0) || (point == "second rename" && renamed == 1) {
					return fault
				}
				renamed++
				return rename(from, to)
			}
			fs.syncDir = func(dir string) error {
				synced++
				if (point == "first directory sync" && synced == 1) || (point == "second directory sync" && synced == 2) {
					return fault
				}
				return syncDir(dir)
			}
			var stdout bytes.Buffer
			err := publishOutputs(outputs, data, &stdout, fs)
			if !errors.Is(err, fault) || !strings.Contains(err.Error(), "visible") || stdout.Len() != 0 {
				t.Fatalf("publication failure was not explicit: %v", err)
			}
			for i, o := range outputs {
				want := []byte("old")
				if i < renamed {
					want = data[i]
				}
				got, err := os.ReadFile(o.path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("unexpected publication prefix")
				}
			}
			assertNoOutputTemps(t, dir)
		})
	}
}

func TestInvalidCheckpointDestinationPreservesBundleBeforeRPC(t *testing.T) {
	peer, requests := bundleFixturePeer(t)
	t.Setenv("ZENON_SPV_PEERS", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	before := []byte("existing bundle")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--rpc", peer, "--height", "1006", "--count", "5", "--out", path, "--checkpoint", dir})
	after, readErr := os.ReadFile(path)
	if err == nil || requests.Load() != 0 || readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("invalid checkpoint changed bundle or reached RPC: err=%v requests=%d unchanged=%t", err, requests.Load(), bytes.Equal(before, after))
	}
}
