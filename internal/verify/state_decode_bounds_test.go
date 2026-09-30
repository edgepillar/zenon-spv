package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func oversizedRetainedWindow(t *testing.T, genesis GenesisTrustRoot) []byte {
	t.Helper()
	anchor, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	// This small file must hit the count guard before decoding the invalid
	// final row. Otherwise tiny inputs can allocate an unbounded header slice
	// before retained-state validation gets a chance to reject them.
	raw := []byte(fmt.Sprintf(`{"version":1,"genesis":%s,"capacity":%d,"retained_window":[%s"PRIVATE_UNREACHED_ROW"]}`,
		anchor, MaxPersistedHeaders, strings.Repeat("null,", MaxPersistedHeaders)))
	if len(raw) >= int(MaxStateFileBytes) {
		t.Fatal("count-bound fixture unexpectedly exceeds the byte limit")
	}
	return raw
}

func TestStateDecodeStopsAtHeaderCountBeforeDecodingNextRow(t *testing.T) {
	raw := oversizedRetainedWindow(t, sampleState(t).Genesis)
	if loaded, err := decodeHeaderState(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrInvalidRetainedState) || !loaded.Empty() || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("count guard did not stop before the next row: %v", err)
	}
}

func TestRetainedWindowDecodeBoundaries(t *testing.T) {
	headers := sampleState(t).RetainedWindow
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{len(headers), len(headers) + 1} {
		decoded, err := decodeRetainedWindow(raw, limit)
		if err != nil || !reflect.DeepEqual(decoded, headers) {
			t.Fatalf("valid window at limit %d: %v", limit, err)
		}
	}
	if decoded, err := decodeRetainedWindow(raw, len(headers)-1); !errors.Is(err, ErrInvalidRetainedState) || decoded != nil {
		t.Fatalf("over-limit window returned headers: %v", err)
	}
	for _, raw := range []string{`[null,"PRIVATE_UNREACHED_ROW"]`, `[{}, {"Version":2}]`} {
		if decoded, err := decodeRetainedWindow([]byte(raw), 1); !errors.Is(err, ErrInvalidRetainedState) || decoded != nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("count limit did not precede row decoding: %v", err)
		}
	}
	for _, limit := range []int{0, 1} {
		for _, raw := range []string{"null", "[]"} {
			decoded, err := decodeRetainedWindow([]byte(raw), limit)
			if err != nil || len(decoded) != 0 || (decoded == nil) != (raw == "null") {
				t.Fatalf("empty window %s at limit %d: %v", raw, limit, err)
			}
		}
	}
	if _, err := decodeRetainedWindow([]byte(`[null]`), 0); !errors.Is(err, ErrInvalidRetainedState) {
		t.Fatalf("zero limit accepted a row: %v", err)
	}
}

func TestRetainedWindowDecodeRejectsMalformedJSONWithoutMutation(t *testing.T) {
	headers := sampleState(t).RetainedWindow
	for _, raw := range []string{
		``, `{}`, `1`, `"PRIVATE"`, `true`, `[`, `[null,]`, `[null`,
		`["bad"]`, `[{"Version":2}]`, `null []`, `[] null`, `[] trailing`,
	} {
		t.Run(raw, func(t *testing.T) {
			window := retainedHeaderWindow(headers)
			if err := window.UnmarshalJSON([]byte(raw)); err == nil {
				t.Fatal("malformed window accepted")
			}
			if !reflect.DeepEqual([]chain.Header(window), headers) {
				t.Fatal("failed decode mutated the previous window")
			}
		})
	}
}

func TestStateCountBoundCannotBeBypassedByPolicyTruncation(t *testing.T) {
	anchor := sampleState(t).Genesis
	raw := oversizedRetainedWindow(t, anchor)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if state, err := LoadOrInit(path, anchor, Policy{W: 0}); !errors.Is(err, ErrInvalidRetainedState) || !state.Empty() {
		t.Fatalf("policy truncation bypassed the decode bound: %v", err)
	}
	if state, err := LoadTrustedState(path, anchor, VerifyOptions{Policy: Policy{W: 0}}); !errors.Is(err, ErrInvalidRetainedState) || state.data != nil {
		t.Fatalf("oversized window created a trusted handle: %v", err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, after) {
		t.Fatalf("failed loading modified the state file: %v", err)
	}
}

func FuzzRetainedWindowDecode(f *testing.F) {
	for _, seed := range []string{
		`null`, `[]`, `[null]`, `[{}]`, `[{},{}]`, `[{},"bad"]`, `[{},]`,
		`[{"Version":2,"NextFusionPrice":0,"NextWorkPrice":0}]`,
		`[{"Version":2}]`, `[] null`, `null {}`,
	} {
		f.Add([]byte(seed), uint8(1))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 4096 {
			t.Skip()
		}
		limit := int(count % 8)
		var reference []chain.Header
		referenceErr := json.Unmarshal(raw, &reference)
		decoded, err := decodeRetainedWindow(raw, limit)
		if referenceErr != nil || len(reference) > limit {
			if err == nil || decoded != nil {
				t.Fatal("invalid or over-limit window returned headers")
			}
			return
		}
		if err != nil || !reflect.DeepEqual(decoded, reference) {
			t.Fatalf("bounded valid window differs from standard decoding: %v", err)
		}
	})
}
