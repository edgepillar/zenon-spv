package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/statelock"
)

func TestCLIStateWriterLockAndReadOnlyQueries(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	check := unchangedQueryFile(t, f.statePath)
	lock, err := statelock.Acquire(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	for _, command := range []string{"verify-headers", "verify-commitment", "verify-segment", "verify-state-value"} {
		r := readVerificationReport(t, command, append(slices.Clone(f.args), f.bundlePath), 70)
		if r.Outcome != nil || r.Error == nil || r.Error.Stage != "state_lock" || len(r.Results) != 0 || r.Persistence != "not_attempted" {
			t.Fatal("busy state writer reached verification or claimed persistence")
		}
		check(t)
	}
	for _, command := range []string{"verify-commitment", "verify-segment"} {
		r := readVerificationReport(t, command, append(slices.Clone(f.args), "--retained-only", f.bundlePath), 0)
		if r.Persistence != "read_only" || r.Error != nil {
			t.Fatal("writer lock blocked a read-only query")
		}
		check(t)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	// The input still has no headers, so releasing the lock reveals the
	// ordinary REFUSED result instead of turning a query into an extension.
	r := readVerificationReport(t, "verify-segment", append(slices.Clone(f.args), f.bundlePath), 2)
	if r.Error != nil || r.Results[0].Reason != "ReasonMissingEvidence" {
		t.Fatal("released writer lock changed verification semantics")
	}
	check(t)
}

func TestCLIStateLockReleasedAfterLoadFailure(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	path := filepath.Join(t.TempDir(), "invalid-state.json")
	before := []byte("invalid trusted-state JSON")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(slices.Clone(f.args[:2]), "--state", path, f.bundlePath)
	r := readVerificationReport(t, "verify-segment", args, 70)
	if r.Error == nil || r.Error.Stage != "state" || r.Outcome != nil {
		t.Fatal("load failure changed its operational stage")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("state was loaded before taking its writer lock")
	}
	lock, err := statelock.Acquire(path)
	if err != nil {
		t.Fatal("failed command retained a writer lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed command changed state bytes")
	}
}

func TestRetainedOnlyDoesNotCreateLockFile(t *testing.T) {
	f := nodeRetainedQueryFixture(t, false)
	raw, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "read-only-state.json")
	if err := os.WriteFile(path, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	args := append(slices.Clone(f.args[:2]), "--state", path, "--retained-only", f.bundlePath)
	readVerificationReport(t, "verify-segment", args, 0)
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("read-only query created a lock file: %v", err)
	}
}
