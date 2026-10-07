package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Force GC only in this reachability diagnostic. HeapAlloc here is neither a
// peak-RSS measurement nor the behavior of the ordinary observer pipeline.
func TestCollectorObservationReleasesCapturedOutput(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select process fixture")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("cannot pin process fixture")
	}
	hash := sha256.Sum256(raw)
	dir := t.TempDir()
	t.Setenv("ZENON_OBSERVER_COLLECTION_TEST", "1")
	t.Setenv("ZENON_OBSERVER_COLLECTION_LARGE", "1")
	t.Setenv("ZENON_OBSERVER_COLLECTION_CANARY", filepath.Join(dir, "PRIVATE_CANARY"))
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	args := selectedCollectionArguments()
	for _, name := range []string{"collector", "verifier", "consumer"} {
		args[slices.Index(args, "--"+name)+1] = binary
		args[slices.Index(args, "--"+name+"-sha256")+1] = hex.EncodeToString(hash[:])
	}
	for _, name := range []string{"genesis-config", "protocol-profile", "schedule", "state", "expectations"} {
		path := filepath.Join(dir, "PRIVATE_"+name)
		if os.WriteFile(path, []byte("PRIVATE_INPUT"), 0o600) != nil {
			t.Fatal("cannot stage local fixture")
		}
		args[slices.Index(args, "--"+name)+1] = path
	}
	args[slices.Index(args, "--private-dir")+1] = dir
	c, ok := parseConfiguration(append(args, "--timeout", "15s"))
	if !ok {
		t.Fatal("cannot select collection fixture")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, code := observe(context.Background(), c)
	if code != 2 || result.Category == nil || *result.Category != "process_failure" ||
		result.Collector == nil || result.Collector.ExitCode == nil || *result.Collector.ExitCode != 0 ||
		result.Collector.StdoutBytes != (32<<20)+11 || result.Collector.StderrBytes == 0 ||
		result.Verifier.ExitCode == nil || *result.Verifier.ExitCode != 70 || result.Consumer.ExitCode != nil {
		t.Fatal("large collection lost actual completion or stage boundaries")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("cannot inspect private cleanup")
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "block-observation-") {
			t.Fatal("completed collection retained a private run directory")
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Keep the full returned observation live across GC. A pointer into the
	// processResult also keeps its large stdout allocation live and exceeds
	// this deliberately loose bound; small runtime bookkeeping does not.
	runtime.KeepAlive(result)
	t.Logf("summary-live heap bytes: before=%d after=%d", before.HeapAlloc, after.HeapAlloc)
	if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc > 8<<20 {
		t.Fatal("collector metadata retained the completed stdout buffer")
	}
}
