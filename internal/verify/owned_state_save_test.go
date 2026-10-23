package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

type ownedSaveCase struct {
	name    string
	mode    int
	k       int
	empty   bool
	resume  bool
	loadedK int
	version uint32
}

func ownedSaveFixture(t *testing.T, tc ownedSaveCase) VerifiedState {
	t.Helper()
	f := newSequenceFixtureSize(tc.mode, 64)
	opts := f.options(t, sequenceModel{w: 6, k: tc.k})
	state, err := NewVerifiedState(f.anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !tc.empty {
		result, next := state.Extend(f.headers[:16])
		if result.Outcome != OutcomeAccept {
			t.Fatal(result)
		}
		state = next
	}
	if tc.resume {
		path := filepath.Join(t.TempDir(), "resume.json")
		if err := state.Save(path); err != nil {
			t.Fatal(err)
		}
		opts.Policy.RetainHeaders = tc.loadedK
		state, err = LoadTrustedState(path, f.anchor, opts)
		if err != nil {
			t.Fatal(err)
		}
	}
	return state
}

func readOwnedSaveBytes(t testing.TB, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifiedStateSaveRetainsEncodingAndOwnership(t *testing.T) {
	for _, tc := range []ownedSaveCase{
		{name: "empty_legacy", empty: true, version: 1},
		{name: "v1_legacy", version: 1},
		{name: "v2_legacy", mode: 1, version: 2},
		{name: "v1_explicit", k: 16, version: 3},
		{name: "v2_explicit", mode: 1, k: 16, version: 3},
		{name: "scheduled_explicit", mode: 2, k: 16, version: 3},
		{name: "trusted_resume", mode: 1, k: 16, resume: true, loadedK: 16, version: 3},
		{name: "resized_resume", mode: 1, k: 16, resume: true, loadedK: 8, version: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := ownedSaveFixture(t, tc)
			before := state.Snapshot()
			view := state.Snapshot()
			if len(view.RetainedWindow) != 0 {
				view.RetainedWindow[0].PublicKey[0] ^= 1
				view.RetainedWindow[0].Signature[0] ^= 1
				view.RetainedWindow[0].HeaderHash[0] ^= 1
			}
			if view.ProtocolProfile != nil {
				view.ProtocolProfile.Source = "detached diagnostic change"
				view.ProtocolProfile.ValidThrough++
			}
			dir := t.TempDir()
			control, path := filepath.Join(dir, "mutable.json"), filepath.Join(dir, "owned.json")
			if err := SaveHeaderState(control, before); err != nil {
				t.Fatal(err)
			}
			if err := state.Save(path); err != nil {
				t.Fatal(err)
			}
			raw := readOwnedSaveBytes(t, path)
			if !bytes.Equal(raw, readOwnedSaveBytes(t, control)) || !reflect.DeepEqual(before, state.Snapshot()) {
				t.Fatal("owned persistence changed encoding or captured state")
			}
			loaded, err := LoadHeaderState(path)
			if err != nil || loaded.Genesis != before.Genesis || loaded.Capacity != before.Capacity ||
				loaded.RetainHeaders != before.RetainHeaders || !reflect.DeepEqual(loaded.ProtocolProfile, before.ProtocolProfile) ||
				len(loaded.RetainedWindow) != len(before.RetainedWindow) {
				t.Fatal("owned save did not preserve the complete readable state", err)
			}
			for i, header := range before.RetainedWindow {
				if !sequenceHeadersEqual(header, loaded.RetainedWindow[i]) {
					t.Fatal("owned save changed a retained envelope")
				}
			}
			var envelope struct {
				Version uint32 `json:"version"`
			}
			if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Version != tc.version {
				t.Fatal("owned save changed the selected persistence version")
			}
			// Qualification retains these exact pins before and after the writer change.
			fmt.Printf("OWNED_SAVE_BYTES %s %d %x\n", tc.name, len(raw), sha256.Sum256(raw))
		})
	}
}

func TestVerifiedStateSaveKeepsMutableStateValidation(t *testing.T) {
	state := ownedSaveFixture(t, ownedSaveCase{mode: 1, k: 16})
	for _, mutation := range []string{"signature", "hash", "version", "linkage", "capacity", "profile"} {
		t.Run(mutation, func(t *testing.T) {
			view := state.Snapshot()
			switch mutation {
			case "signature":
				view.RetainedWindow[0].Signature[0] ^= 1
			case "hash":
				view.RetainedWindow[0].HeaderHash[0] ^= 1
			case "version":
				view.RetainedWindow[0].Version = 3
			case "linkage":
				view.RetainedWindow[1].PreviousHash[0] ^= 1
			case "capacity":
				view.Capacity = 0
			case "profile":
				view.ProtocolProfile.ValidThrough = view.Genesis.Height
			}
			path := filepath.Join(t.TempDir(), "state.json")
			sentinel := []byte("prior state remains selected")
			if err := os.WriteFile(path, sentinel, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := SaveHeaderState(path, view); err == nil || !bytes.Equal(readOwnedSaveBytes(t, path), sentinel) {
				t.Fatal("caller-owned malformed state replaced the prior file")
			}
			if err := state.Save(path); err != nil {
				t.Fatal("detached view mutation changed the owned saver", err)
			}
			if _, err := LoadHeaderState(path); err != nil {
				t.Fatal("owned saver published an unreadable state", err)
			}
		})
	}
}

func TestVerifiedStateSaveZeroHandle(t *testing.T) {
	var zero VerifiedState
	path := filepath.Join(t.TempDir(), "state.json")
	if err := zero.Save(path); !errors.Is(err, ErrUninitializedState) {
		t.Fatal("zero handle reached persistence", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("zero handle created a state file", err)
	}
}

func TestVerifiedStateSaveWriterFailures(t *testing.T) {
	state := ownedSaveFixture(t, ownedSaveCase{k: 16})
	t.Run("empty_path", func(t *testing.T) {
		owned := state.Save("")
		control := SaveHeaderState("", state.Snapshot())
		if owned == nil || control == nil || owned.Error() != control.Error() {
			t.Fatal("owned save changed the empty-path error")
		}
	})
	t.Run("directory_target", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "target")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(path, "marker")
		if err := os.WriteFile(marker, []byte("preserved"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := state.Save(path); err == nil || string(readOwnedSaveBytes(t, marker)) != "preserved" {
			t.Fatal("failed owned save replaced the selected directory")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "target" {
			t.Fatal("failed owned save left an unfinished temporary file", err)
		}
	})
}

func TestVerifiedStateSaveSharedHandlePaths(t *testing.T) {
	state := ownedSaveFixture(t, ownedSaveCase{k: 16})
	before := state.Snapshot()
	dir := t.TempDir()
	control := filepath.Join(dir, "control.json")
	if err := SaveHeaderState(control, before); err != nil {
		t.Fatal(err)
	}
	want := readOwnedSaveBytes(t, control)
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			path := filepath.Join(dir, fmt.Sprintf("worker-%d.json", worker))
			if err := state.Save(path); err != nil {
				failures <- err
				return
			}
			raw, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, want) {
				failures <- fmt.Errorf("independent owned save differs: %v", err)
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if !reflect.DeepEqual(state.Snapshot(), before) {
		t.Fatal("concurrent saves changed their shared immutable handle")
	}
}

// The mutable route receives the same private immutable fixture directly. It is
// the old VerifiedState.Save call shape, with no extra Snapshot allocation.
func BenchmarkOwnedStatePersistence(b *testing.B) {
	for _, k := range []int{16, MaxRetainHeaders} {
		fixture := newSequenceFixtureSize(0, k)
		policy := DefaultPolicy()
		policy.W, policy.RetainHeaders = 6, k
		state, err := NewVerifiedState(fixture.anchor, VerifyOptions{Policy: policy})
		if err != nil {
			b.Fatal(err)
		}
		result, state := state.Extend(fixture.headers)
		if result.Outcome != OutcomeAccept {
			b.Fatal(result)
		}
		control := filepath.Join(b.TempDir(), "control.json")
		if err := SaveHeaderState(control, state.data.state); err != nil {
			b.Fatal(err)
		}
		want := readOwnedSaveBytes(b, control)
		for _, method := range []struct {
			name  string
			write func(string) error
		}{
			{"mutable_validation", func(path string) error { return SaveHeaderState(path, state.data.state) }},
			{"owned_save", state.Save},
		} {
			b.Run(fmt.Sprintf("K%d/%s", k, method.name), func(b *testing.B) {
				path := filepath.Join(b.TempDir(), "state.json")
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if err := method.write(path); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				raw := readOwnedSaveBytes(b, path)
				if !bytes.Equal(raw, want) {
					b.Fatal("measured writer changed complete serialized bytes")
				}
				b.ReportMetric(float64(len(raw)), "state_B")
				fmt.Printf("OWNED_SAVE_BENCH_BYTES K%d/%s %d %x\n", k, method.name, len(raw), sha256.Sum256(raw))
			})
		}
	}
}
