package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Frozen whole-window decoder from 8ada23c4614de8d2770958304076d1ff834d9c1a.
// The reference does not call decodeRetainedWindowValue or the current parser.
// SHA-256 state_json.go: 297a8ec496f6cef0853cae816f10034d15766b7af4036cbe95e251a6406b53fa.
// SHA-256 state_window_json.go: 947be562839cd40f1d7b82f4a5f3d702cc386e9e96fd3bc3fdd7b8fa67f80f40.
type priorPersistedState struct {
	ProtocolProfile *ProtocolProfile
	Version         uint32
	Genesis         GenesisTrustRoot
	Window          priorRetainedHeaderWindow
	Capacity        int
}

// Preserve field matching and unknown-field compatibility, but reject repeated
// top-level state fields. Later arrays, objects, or nulls must not hide earlier
// evidence from validation. Publish the decoded state only on complete success.
func (state *priorPersistedState) UnmarshalJSON(raw []byte) error {
	var decoded priorPersistedState
	fields := []struct {
		name   string
		target any
	}{
		{"version", &decoded.Version}, {"genesis", &decoded.Genesis},
		{"retained_window", &decoded.Window}, {"capacity", &decoded.Capacity},
		{"protocol_profile", &decoded.ProtocolProfile},
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("%w: state file must be a JSON object", ErrInvalidRetainedState)
	}
	seen := make([]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: invalid state field name", ErrInvalidRetainedState)
		}
		var ignored json.RawMessage
		var target any = &ignored
		for i, field := range fields {
			// Match the Unicode case folding used by encoding/json, after
			// JSON escapes have been resolved by Token.
			if !strings.EqualFold(name, field.name) {
				continue
			}
			if seen[i] {
				return fmt.Errorf("%w: duplicate state field %q", ErrInvalidRetainedState, field.name)
			}
			seen[i] = true
			target = field.target
			break
		}
		if err := d.Decode(target); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("%w: invalid state object terminator", ErrInvalidRetainedState)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing state JSON data", ErrInvalidRetainedState)
	}
	*state = decoded
	return nil
}

// Tiny JSON elements can expand into large header structs. Enforce the count
// limit while decoding, before retained-state validation or policy truncation.
type priorRetainedHeaderWindow []chain.Header

func (window *priorRetainedHeaderWindow) UnmarshalJSON(raw []byte) error {
	decoded, err := priorDecodeRetainedWindow(raw, MaxPersistedHeaders)
	if err != nil {
		return err
	}
	*window = decoded
	return nil
}

func priorDecodeRetainedWindow(raw []byte, maxHeaders int) ([]chain.Header, error) {
	if maxHeaders < 0 {
		return nil, fmt.Errorf("%w: negative header count limit", ErrInvalidRetainedState)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return nil, err
	}
	var decoded []chain.Header
	if first != nil {
		if first != json.Delim('[') {
			return nil, errors.New("retained window: expected an array or null")
		}
		// Preserve the distinction between [] and null in saved-state round trips.
		decoded = make([]chain.Header, 0)
		for d.More() {
			if len(decoded) >= maxHeaders {
				return nil, fmt.Errorf("%w: retained header count exceeds persistence limit", ErrInvalidRetainedState)
			}
			var header chain.Header
			if err := d.Decode(&header); err != nil {
				return nil, err
			}
			decoded = append(decoded, header)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
	}
	var extra json.RawMessage
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("retained window: trailing JSON value")
		}
		return nil, err
	}
	return decoded, nil
}

func priorStateForStreamedWindow(s persistedState) priorPersistedState {
	return priorPersistedState{ProtocolProfile: s.ProtocolProfile, Version: s.Version,
		Genesis: s.Genesis, Window: priorRetainedHeaderWindow(s.Window), Capacity: s.Capacity}
}

func checkStreamedStateWindow(t *testing.T, raw []byte) {
	t.Helper()
	before := stateEncodingBody(1)
	before.ProtocolProfile = &ProtocolProfile{Source: "previous state"}
	got := before
	prior := priorStateForStreamedWindow(before)
	input := bytes.Clone(raw)
	err := got.UnmarshalJSON(raw)
	referenceErr := prior.UnmarshalJSON(raw)
	if (err == nil) != (referenceErr == nil) ||
		errors.Is(err, ErrInvalidRetainedState) != errors.Is(referenceErr, ErrInvalidRetainedState) {
		t.Fatalf("decode outcome differs from prior decoder: current=%v prior=%v", err, referenceErr)
	}
	if err != nil {
		if !reflect.DeepEqual(got, before) {
			t.Fatal("failed decoding changed the existing state")
		}
	} else if !reflect.DeepEqual(priorStateForStreamedWindow(got), prior) {
		t.Fatal("decoded fields, bytes, or nil/empty shape differ from prior decoder")
	}
	if !bytes.Equal(raw, input) {
		t.Fatal("decoding mutated input")
	}
}

func TestStreamedStateWindowReference(t *testing.T) {
	for _, count := range []int{0, 1, 16, 256} {
		for _, version := range []uint32{stateFileVersion, profileStateFileVersion, retentionStateFileVersion} {
			for _, position := range []string{"first", "middle", "last"} {
				t.Run(fmt.Sprintf("K%d/version%d/%s", count, version, position), func(t *testing.T) {
					body := stateEncodingBody(count)
					body.Version = version
					if version != stateFileVersion {
						body.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: body.Genesis,
							V2FromHeight: 102, ValidThrough: ^uint64(0), Source: "<>&\"\\\n\u2028"}
					}
					raw, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(raw, &fields); err != nil {
						t.Fatal(err)
					}
					known := []string{"version", "genesis", "capacity"}
					if body.ProtocolProfile != nil {
						known = append(known, "protocol_profile")
					}
					index := 0
					if position == "middle" {
						index = 2
					}
					if position == "last" {
						index = len(known)
					}
					known = append(known[:index], append([]string{"retained_window"}, known[index:]...)...)
					var pieces []string
					for _, name := range known {
						pieces = append(pieces, fmt.Sprintf("%q:%s", name, fields[name]))
					}
					// Unknown nested state-like fields, repeated unknown fields, escapes and
					// delimiter text must not be interpreted as top-level evidence.
					input := `{"unknown":{"retained_window":[null],"text":"[},]""},"unknown":null,` +
						strings.Join(pieces, ",") + `,"later_unknown":[{},null,[1,2]]}`
					checkStreamedStateWindow(t, []byte(input))
				})
			}
		}
	}
	for _, input := range []string{
		`{"retained_window":null}`, `{"retained_window":[]}`,
		`{"retained_window":[null,{}],"capacity":2}`,
		`{"retained_window":[{"version":2,"nextFusionPrice":0,"nextWorkPrice":0}]}`,
		`{"RETAINED_WINDOW":[{}],"VERSION":3}`,
		`{"retained_window":[{}],"verſion":3}`,
		`{"retained_window":[{"publicKey":"","signature":null}]}`,
	} {
		t.Run(input, func(t *testing.T) { checkStreamedStateWindow(t, []byte(input)) })
	}
}

func TestStreamedStateWindowInvalidReference(t *testing.T) {
	cases := []string{
		"", "null", "[]", "true", "{", `{"retained_window":`,
		`{"retained_window":[}`, `{"retained_window":[null}`,
		`{"retained_window":[null,]}`, `{"retained_window":[{}{}]}`,
		`{"retained_window":[{}]:1}`, `{"retained_window":[{},{}],"capacity":}`,
		`{"retained_window":[{}] "capacity":1}`,
		`{"retained_window":null "capacity":1}`,
		`{"retained_window":{},"capacity":1}`,
		`{"retained_window":"PRIVATE_BAD_ROW"}`,
		`{"retained_window":[{"version":2,"nextFusionPrice":0}]}`,
		`{"retained_window":[{}],"version":3,"VERSION":3}`,
		`{"retained_window":[{}],"capacity":-1.5}`,
		`{"retained_window":[]} null`, `{"retained_window":[]} trailing`,
	}
	for _, first := range []string{"null", "[]", "[null]"} {
		for _, alias := range []string{"retained_window", "RETAINED_WINDOW", `retained_window`} {
			cases = append(cases, fmt.Sprintf(`{"retained_window":%s,"%s":[]}`, first, alias))
		}
	}
	for i, input := range cases {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			checkStreamedStateWindow(t, []byte(input))
		})
	}
}

func TestStreamedStateWindowCountBeforeNextRow(t *testing.T) {
	input := []byte(`{"retained_window":[` + strings.Repeat("null,", MaxPersistedHeaders) +
		`"PRIVATE_UNREACHED_ROW"],"capacity":1}`)
	var state persistedState
	if err := state.UnmarshalJSON(input); !errors.Is(err, ErrInvalidRetainedState) ||
		strings.Contains(err.Error(), "PRIVATE") || state.Window != nil {
		t.Fatalf("count limit did not stop before the next row: %v", err)
	}
	// Existing state-count and policy-truncation controls exercise complete
	// decoding and owned loading too; this check targets the nested value path.
}

func TestStreamedStateWindowTrustedResume(t *testing.T) {
	for mode, name := range []string{"v1", "v1_v2_profile", "v1_v2_schedule"} {
		t.Run(name, func(t *testing.T) {
			fixture := newSequenceFixtureSize(mode, 64)
			opts := fixture.options(t, sequenceModel{w: 6, k: 16})
			state, err := NewVerifiedState(fixture.anchor, opts)
			if err != nil {
				t.Fatal(err)
			}
			result, state := state.Extend(fixture.headers[:16])
			if result.Outcome != OutcomeAccept {
				t.Fatal(result)
			}
			path := filepath.Join(t.TempDir(), "state.json")
			if err := state.Save(path); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadTrustedState(path, fixture.anchor, opts)
			if err != nil || !reflect.DeepEqual(loaded.Snapshot(), state.Snapshot()) {
				t.Fatal("complete saved window did not resume unchanged", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			// Corrupt a header that a smaller capacity would evict. Complete integrity
			// and producer/profile validation must still precede policy truncation.
			var headers []chain.Header
			if err := json.Unmarshal(fields["retained_window"], &headers); err != nil {
				t.Fatal(err)
			}
			headers[0].Signature[0] ^= 1
			fields["retained_window"], err = json.Marshal(headers)
			if err != nil {
				t.Fatal(err)
			}
			corrupt, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			smaller := opts
			smaller.Policy.RetainHeaders = 7
			if invalid, err := LoadTrustedState(path, fixture.anchor, smaller); !errors.Is(err, ErrInvalidRetainedState) || invalid.data != nil {
				t.Fatal("corrupt evicted header became trusted", err)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, corrupt) {
				t.Fatal("refused resume changed state bytes", err)
			}
		})
	}
}

func FuzzStreamedStateWindow(f *testing.F) {
	for _, input := range []string{
		`{}`, `null`, `{"retained_window":null}`, `{"retained_window":[],"capacity":1}`,
		`{"retained_window":[{},null],"version":3}`,
		`{"retained_window":[{}],"RETAINED_WINDOW":null}`,
		`{"retained_window":[{"version":2,"nextFusionPrice":0,"nextWorkPrice":0}]}`,
		`{"retained_window":[{"version":2}]}`,
		`{"retained_window":[{}] "capacity":1}`,
		`{"retained_window":[],"metadata":{"retained_window":[{}]}}`,
	} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		checkStreamedStateWindow(t, raw)
	})
}

var streamedStateBenchmarkSink persistedState
var priorStateBenchmarkSink priorPersistedState

func BenchmarkStreamedStateWindow(b *testing.B) {
	for _, count := range []int{16, 256, MaxRetainHeaders} {
		body := stateEncodingBody(count)
		raw, err := json.Marshal(body)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("K%d/prior", count), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var state priorPersistedState
				if err := state.UnmarshalJSON(raw); err != nil {
					b.Fatal(err)
				}
				priorStateBenchmarkSink = state
			}
		})
		b.Run(fmt.Sprintf("K%d/streamed", count), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var state persistedState
				if err := state.UnmarshalJSON(raw); err != nil {
					b.Fatal(err)
				}
				streamedStateBenchmarkSink = state
			}
		})
	}
	b.Run(fmt.Sprintf("experimental-v3/K%d", MaxRetainHeaders), benchmarkExperimentalV3Window)
}
