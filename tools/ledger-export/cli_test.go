// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func arguments(path string) []string {
	return []string{"--layout", layout, "--immutable-copy", path, "--expect-height", "3000", "--expect-hash", selected().Hash, "--provenance-sha256", selected().Provenance}
}
func receipt(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("one receipt required: %s", raw)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		t.Fatal("extra receipt data")
	}
	scope, ok := result["scope"].(map[string]any)
	if !ok {
		t.Fatal("missing scope")
	}
	for _, v := range scope {
		if flag, ok := v.(bool); ok && flag {
			t.Fatal("unexpected authority claim")
		}
	}
	return result
}
func createDisk(t *testing.T, rows []pair) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "ledger")
	db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: true})
	if err != nil {
		t.Fatal(err)
	}
	var batch leveldb.Batch
	for _, row := range rows {
		batch.Put(row.key, row.value)
	}
	if err = db.Write(&batch, nil); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func image(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("unexpected fixture file type")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[name] = hex.EncodeToString(digest[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReadOnlyFileViewPreservesAllFixtureBytes(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	before := image(t, path)
	var out, meta bytes.Buffer
	exit := run(context.Background(), arguments(path), &out, &meta, openReadOnly)
	report := receipt(t, meta.Bytes())
	if exit != 0 || report["status"] != "SELECTED_FRONTIER_EXPORTED" || report["put_stream_complete"] != true || !bytes.Equal(out.Bytes(), literalStream(t)) {
		t.Fatalf("read-only export: %d %s", exit, meta.Bytes())
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(image(t, path))
	if !bytes.Equal(a, b) {
		t.Fatal("read-only export changed fixture file membership or bytes")
	}
}

func TestRealSnapshotKeepsOneViewDuringWriterAdvance(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snapshot, err := db.GetSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Release()
	if err = db.Put([]byte{0x55, 'a'}, []byte{0, 'x'}, nil); err != nil {
		t.Fatal(err)
	}
	if err = db.Put([]byte{0x55, 0}, []byte{0, 'x'}, nil); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, err = exportSnapshot(context.Background(), diskSnapshot{snapshot}, &out, selected(), defaults)
	if err != nil || !bytes.Equal(out.Bytes(), literalStream(t)) {
		t.Fatal("snapshot observed the later fixture writes")
	}
}

func TestLiveWriteLockRefusesWithoutChangingFiles(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out, meta bytes.Buffer
	exit := run(context.Background(), arguments(path), &out, &meta, openReadOnly)
	if exit != 1 || out.Len() != 0 || receipt(t, meta.Bytes())["status"] != "UNKNOWN" {
		t.Fatal("locked writable fixture was opened")
	}
}

func TestMissingDirectoryIsNotCreated(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "not-created")
	var out, meta bytes.Buffer
	exit := run(context.Background(), arguments(path), &out, &meta, openReadOnly)
	if exit != 1 || out.Len() != 0 || receipt(t, meta.Bytes())["reason"] != "input_directory" {
		t.Fatal("missing directory accepted")
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("missing input was created")
	}
}

func TestSymlinkInputRefuses(t *testing.T) {
	path := createDisk(t, fixture(t).view.iterator.rows)
	alias := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(path, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("Windows fixture cannot create a symlink; ordinary physical-path cases still execute")
		}
		t.Fatal(err)
	}
	var out, meta bytes.Buffer
	exit := run(context.Background(), arguments(alias), &out, &meta, openReadOnly)
	if exit != 1 || out.Len() != 0 || receipt(t, meta.Bytes())["reason"] != "input_directory" {
		t.Fatal("symlink input accepted")
	}
}

func TestOptionsAndHelpNeverEchoPrivateTextOrOpenInput(t *testing.T) {
	secret := "PRIVATE_TEST_INPUT_DO_NOT_ECHO"
	bad := [][]string{nil, {"--unknown", secret}, {"--layout", secret}, {"--expect-height", "-1"}, {"--help", secret}}
	for _, name := range []string{"expect-height", "max-bytes", "max-records", "max-scan-bytes", "max-scan-records", "max-key-bytes", "max-value-bytes"} {
		for _, value := range []string{"01", "+1", "-1", "18446744073709551616", secret} {
			a := arguments("/" + secret)
			a = append(a, "--"+name, value)
			bad = append(bad, a)
		}
	}
	bad = append(bad, append(arguments("/"+secret), "--expect-height", "2"))
	for _, args := range bad {
		var out, meta bytes.Buffer
		called := false
		exit := run(context.Background(), args, &out, &meta, func(string) (rawStore, error) { called = true; return nil, errors.New(secret) })
		r := receipt(t, meta.Bytes())
		if exit != 1 || called || out.Len() != 0 || r["status"] != "UNKNOWN" || strings.Contains(meta.String(), secret) {
			t.Fatal("invalid options leaked or opened input")
		}
	}
	for _, arg := range []string{"--help", "-h"} {
		var out, meta bytes.Buffer
		exit := run(context.Background(), []string{arg}, &out, &meta, func(string) (rawStore, error) { t.Fatal("help opened input"); return nil, nil })
		r := receipt(t, meta.Bytes())
		if exit != 0 || out.String() != usage || r["status"] != "UNKNOWN" || r["put_stream_complete"] != false {
			t.Fatal("help became an export")
		}
	}
}

func TestCanonicalOptionsAndAllDefaultCaps(t *testing.T) {
	c, err := options(arguments("/physical-fixture"))
	if err != nil || c.selected != selected() || c.caps != defaults {
		t.Fatal("default selection or limits drift")
	}
	for _, value := range []string{"0", "127", "128", "18446744073709551615"} {
		a := arguments("/physical-fixture")
		a[5] = value
		c, err := options(a)
		if err != nil || strconv.FormatUint(c.selected.Height, 10) != value {
			t.Fatal("height range")
		}
	}
	for _, hash := range []string{strings.Repeat("AA", 32), strings.Repeat("00", 31), strings.Repeat("g0", 32)} {
		a := arguments("/physical-fixture")
		a[7] = hash
		if _, err := options(a); err == nil {
			t.Fatal("noncanonical hash accepted")
		}
	}
}

func TestCLIErrorDoesNotPublishPartialStatistics(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"open", "write", "backend", "close"} {
		t.Run(mode, func(t *testing.T) {
			db := fixture(t)
			var out, meta bytes.Buffer
			writer := io.Writer(&out)
			if mode == "write" {
				writer = badWriter{"error"}
			}
			if mode == "backend" {
				db.view.getFailure = true
			}
			if mode == "close" {
				db.closeFailure = true
			}
			exit := run(context.Background(), arguments(root), writer, &meta, func(string) (rawStore, error) {
				if mode == "open" {
					return nil, errors.New("PRIVATE_TEST_BACKEND")
				}
				return db, nil
			})
			r := receipt(t, meta.Bytes())
			if exit != 1 || r["status"] != "UNKNOWN" || r["put_stream_complete"] != false || r["statistics"] != nil || strings.Contains(meta.String(), "PRIVATE_TEST") {
				t.Fatal("partial operation reported success")
			}
		})
	}
}

func ordinaryBinary(t *testing.T) string {
	t.Helper()
	if selected := os.Getenv("SPV_LEDGER_EXPORT_TEST_BINARY"); selected != "" {
		info, err := os.Lstat(selected)
		if err != nil || !filepath.IsAbs(selected) || !info.Mode().IsRegular() {
			t.Fatal("selected ordinary binary")
		}
		return selected
	}
	path := filepath.Join(t.TempDir(), "ledger-export.exe")
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBin += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", path, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ordinary build: %v %s", err, output)
	}
	return path
}

func compiledInventory(t *testing.T, binary string) {
	// Input state and expected ordered records are independently selected here.
	// The completion helper's observations must match these literal expectations
	// before its pins are used by the independent inventory process.
	balanceA := append(unhex(t, "03"+strings.Repeat("33", 20)+"03"), bytes.Repeat([]byte{0x44}, 10)...)
	balanceB := append(unhex(t, "03"+strings.Repeat("33", 20)+"03"), bytes.Repeat([]byte{0x55}, 10)...)
	storage := unhex(t, "03"+strings.Repeat("33", 20)+"046b")
	rows := []pair{{[]byte{0x55, 0}, metadata(t)}, {append([]byte{0x55}, balanceA...), make([]byte, 33)}, {append([]byte{0x55}, balanceB...), []byte{0}}, {append([]byte{0x55}, storage...), []byte{0, 'v'}}, {[]byte{0x55, 'z'}, nil}, {[]byte{0x66, 'x'}, []byte{0, 'x'}}}
	path := createDisk(t, rows)
	before := image(t, path)
	expected := unhex(t, "01010027"+hex.EncodeToString(metadata(t)[1:])+"0120"+hex.EncodeToString(balanceA)+"20"+strings.Repeat("00", 32)+"0120"+hex.EncodeToString(balanceB)+"000117"+hex.EncodeToString(storage)+"0176")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out, meta bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, arguments(path)...)
	cmd.Stdout = &out
	cmd.Stderr = &meta
	if err := cmd.Run(); err != nil {
		t.Fatalf("ordinary CLI: %v %s", err, meta.Bytes())
	}
	r := receipt(t, meta.Bytes())
	if r["status"] != "SELECTED_FRONTIER_EXPORTED" || !bytes.Equal(out.Bytes(), expected) {
		t.Fatal("ordinary byte stream mismatch")
	}
	expectedSHA := sha256.Sum256(expected)
	rawBinary, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binarySHA := sha256.Sum256(rawBinary)
	python := os.Getenv("SPV_LEDGER_INVENTORY_PYTHON")
	if python == "" {
		python = "python3"
	}
	script := os.Getenv("SPV_LEDGER_INVENTORY_SCRIPT")
	if script == "" {
		script = filepath.Join("..", "ledger-inventory", "inventory.py")
	}
	completionScript := os.Getenv("SPV_LEDGER_EXPORT_COMPLETION_SCRIPT")
	if completionScript == "" {
		completionScript = "consume_completion.py"
	}
	helperSource, err := os.ReadFile(completionScript)
	if err != nil {
		t.Fatal(err)
	}
	capturedSHA := sha256.Sum256(out.Bytes())
	var completed map[string]any
	var completionSHA [32]byte
	controls := []struct{ exit, capture, digest, reason string }{
		{strconv.Itoa(cmd.ProcessState.ExitCode()), "complete", hex.EncodeToString(capturedSHA[:]), ""},
		{"130", "complete", hex.EncodeToString(capturedSHA[:]), "process_failure"},
		{"0", "incomplete", hex.EncodeToString(capturedSHA[:]), "capture_incomplete"},
		{"0", "complete", strings.Repeat("00", 32), "capture_mismatch"},
	}
	for _, control := range controls {
		// ProcessState and completed stdout/stderr copies are the outer channel.
		// A success-looking producer receipt must not replace that channel.
		helper := exec.CommandContext(ctx, python, "-I", "-B", completionScript,
			"--layout", layout, "--expect-height", "3000", "--expect-hash", selected().Hash,
			"--provenance-sha256", selected().Provenance, "--producer-exit", control.exit,
			"--capture-status", control.capture, "--capture-bytes", strconv.Itoa(out.Len()),
			"--capture-sha256", control.digest)
		helper.Stdin = bytes.NewReader(meta.Bytes())
		raw, helperErr := helper.CombinedOutput()
		matched := receipt(t, raw)
		if control.reason != "" {
			if helper.ProcessState == nil || helper.ProcessState.ExitCode() != 2 || helperErr == nil || matched["status"] != "UNKNOWN" || matched["reason"] != control.reason || matched["inventory_selection"] != nil || matched["capture_matched"] != false {
				t.Fatal("completion refusal")
			}
			continue
		}
		if helperErr != nil || matched["status"] != "SELECTED_EXPORT_COMPLETION_MATCHED" || matched["capture_matched"] != true {
			t.Fatal("completed capture did not reconcile")
		}
		completed, completionSHA = matched, sha256.Sum256(raw)
	}
	pins := completed["inventory_selection"].(map[string]any)
	if len(pins) != 5 || pins["record_space"] != "effective-raw-ledger" || pins["records"] != float64(4) || pins["bytes"] != float64(len(expected)) || pins["sha256"] != hex.EncodeToString(expectedSHA[:]) || pins["provenance_sha256"] != selected().Provenance {
		t.Fatal("completion changed independently selected fixture pins")
	}
	caps := completed["inventory_limits"].(map[string]any)
	if len(caps) != 4 || caps["bytes"] != float64(defaults.OutputBytes) || caps["records"] != float64(defaults.Records) || caps["key_bytes"] != float64(defaults.KeyBytes) || caps["value_bytes"] != float64(defaults.ValueBytes) {
		t.Fatal("completion changed selected inventory caps")
	}
	consumer := exec.CommandContext(ctx, python, "-I", "-B", script,
		"--expect-bytes", strconv.Itoa(int(pins["bytes"].(float64))),
		"--expect-records", strconv.Itoa(int(pins["records"].(float64))),
		"--expect-sha256", pins["sha256"].(string), "--provenance-sha256", pins["provenance_sha256"].(string),
		"--max-bytes", strconv.Itoa(int(caps["bytes"].(float64))),
		"--max-records", strconv.Itoa(int(caps["records"].(float64))),
		"--max-key-bytes", strconv.Itoa(int(caps["key_bytes"].(float64))),
		"--max-value-bytes", strconv.Itoa(int(caps["value_bytes"].(float64))))
	consumer.Stdin = bytes.NewReader(out.Bytes())
	raw, err := consumer.CombinedOutput()
	if err != nil {
		t.Fatalf("independent inventory: %v %s", err, raw)
	}
	var inventory map[string]any
	if json.Unmarshal(raw, &inventory) != nil || inventory["status"] != "SELECTED_STREAM_INVENTORIED" || inventory["records"] != float64(4) {
		t.Fatal("inventory result")
	}
	families := inventory["families"].(map[string]any)
	typed := families["typed_balance"].(map[string]any)
	if typed["present_empty_values"] != float64(1) || typed["raw_zero32_values"] != float64(1) || inventory["distinct_typed_balance_addresses"] != float64(1) {
		t.Fatal("typed empty/zero inventory changed")
	}
	for _, v := range inventory["scope"].(map[string]any) {
		if flag, ok := v.(bool); ok && flag {
			t.Fatal("inventory gained proof authority")
		}
	}
	bad := arguments(path)
	bad[5] = "3001"
	out.Reset()
	meta.Reset()
	rejected := exec.CommandContext(ctx, binary, bad...)
	rejected.Stdout = &out
	rejected.Stderr = &meta
	if rejected.Run() == nil || out.Len() != 0 || receipt(t, meta.Bytes())["status"] != "UNKNOWN" {
		t.Fatal("ordinary wrong-identity refusal")
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(image(t, path))
	if !bytes.Equal(a, b) {
		t.Fatal("ordinary CLI modified input bytes")
	}
	t.Logf("ordinary_binary_sha256=%x selected_put_stream_sha256=%x records=4 raw_fixture_keys=%d inventory_processes=1 acceptance_enabled=false", binarySHA, expectedSHA, len(rows))
	t.Logf("completion_helper_sha256=%x completion_receipt_sha256=%x helper_processes=4 outer_refusals=3 retained_stream_reused=true acceptance_enabled=false", sha256.Sum256(helperSource), completionSHA)
}

func TestCompiledCLI(t *testing.T) {
	binary := ordinaryBinary(t)
	t.Run("independent-inventory", func(t *testing.T) { compiledInventory(t, binary) })
	t.Run("interrupt-blocked-output", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows os.Process.Signal cannot inject os.Interrupt; file and ordinary CLI controls still execute")
		}
		rows := []pair{{[]byte{0x55, 0}, metadata(t)}, {[]byte{0x55, 'z'}, make([]byte, (256<<10)+1)}}
		path := createDisk(t, rows)
		before := image(t, path)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, arguments(path)...)
		var meta bytes.Buffer
		cmd.Stderr = &meta
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer pipe.Close()
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		first := make([]byte, 1)
		if _, err = io.ReadFull(pipe, first); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("export did not begin")
		}
		if err = cmd.Process.Signal(os.Interrupt); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			pipe.Close()
			<-done
			t.Fatal("interrupted output did not join")
		}
		var exited *exec.ExitError
		if !errors.As(err, &exited) || ctx.Err() != nil {
			t.Fatal("interrupt did not terminate the owned process")
		}
		if meta.Len() == 0 {
			if exited.ExitCode() != 130 {
				t.Fatal("missing completion did not use the declared bounded abort")
			}
		} else if exited.ExitCode() != 1 || receipt(t, meta.Bytes())["status"] != "UNKNOWN" {
			t.Fatal("interrupt became a complete export")
		}
		a, _ := json.Marshal(before)
		b, _ := json.Marshal(image(t, path))
		if !bytes.Equal(a, b) {
			t.Fatal("interrupt changed input bytes")
		}
	})
}

func TestFixtureOrderingIsExplicit(t *testing.T) {
	rows := fixture(t).view.iterator.rows
	if !sort.SliceIsSorted(rows, func(i, j int) bool { return bytes.Compare(rows[i].key, rows[j].key) < 0 }) {
		t.Fatal("fixture ordering")
	}
}
