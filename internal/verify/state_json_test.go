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
)

func TestStateDecodeRejectsShadowedRetainedWindow(t *testing.T) {
	state := sampleState(t)
	raw, err := json.Marshal(persistedState{Version: stateFileVersion, Genesis: state.Genesis,
		Window: state.RetainedWindow, Capacity: state.Capacity})
	if err != nil {
		t.Fatal(err)
	}
	// A later array must not erase the invalid header before validation.
	input := append([]byte(`{"retained_window":[null],`), raw[1:]...)
	if loaded, err := decodeHeaderState(bytes.NewReader(input), int64(len(input))); !errors.Is(err, ErrInvalidRetainedState) || !loaded.Empty() {
		t.Fatalf("a repeated retained_window hid an invalid earlier header: %v", err)
	}
}

func stateJSONFixture(t *testing.T) (persistedState, []byte) {
	t.Helper()
	state := sampleState(t)
	wire := persistedState{Version: stateFileVersion, Genesis: state.Genesis,
		Window: state.RetainedWindow, Capacity: state.Capacity}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return wire, raw
}

func TestPersistedStateRejectsDuplicateKnownFields(t *testing.T) {
	want, raw := stateJSONFixture(t)
	// Explicit null is a valid absent profile in legacy state, but the field
	// must still occur only once.
	valid := `{"protocol_profile":null,` + string(raw[1:])
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &fields); err != nil {
		t.Fatal(err)
	}
	for field, value := range fields {
		for _, alias := range []string{field, strings.ToUpper(field), fmt.Sprintf(`\u%04x%s`, field[0], field[1:])} {
			t.Run(alias, func(t *testing.T) {
				input := []byte(fmt.Sprintf(`{"%s":%s,`, alias, value) + valid[1:])
				got := want
				if err := json.Unmarshal(input, &got); !errors.Is(err, ErrInvalidRetainedState) {
					t.Fatalf("duplicate known state field accepted: %v", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("failed decoding changed the previous state")
				}
			})
		}
	}
	for _, prefix := range []string{
		`{"ver\u017fion":999,`, `{"gene\u017fis":{},`,
		`{"capacity":0,`, `{"genesis":null,`,
	} {
		if _, err := decodeHeaderState(strings.NewReader(prefix+valid[1:]), MaxStateFileBytes); !errors.Is(err, ErrInvalidRetainedState) {
			t.Fatalf("shadowed configuration accepted: %v", err)
		}
	}
}

func TestPersistedStateCompatibleSingleFields(t *testing.T) {
	want, raw := stateJSONFixture(t)
	valid := string(raw)
	for _, input := range []string{
		valid,
		strings.NewReplacer(`"version"`, `"VERSION"`, `"genesis"`, `"GENESIS"`, `"retained_window"`, `"RETAINED_WINDOW"`, `"capacity"`, `"CAPACITY"`).Replace(valid),
		strings.Replace(valid, `"version"`, `"ver\u017fion"`, 1),
		`{"unknown_private_metadata":{"version":999},"unknown_private_metadata":null,` + valid[1:],
		`{"protocol_profile":null,` + valid[1:],
	} {
		var got persistedState
		if err := json.Unmarshal([]byte(input), &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("unambiguous legacy state changed: %v", err)
		}
		if _, err := decodeHeaderState(strings.NewReader(input), MaxStateFileBytes); err != nil {
			t.Fatalf("valid retained state did not load: %v", err)
		}
	}
}

func TestPersistedStateInvalidDecodeDoesNotMutateReceiver(t *testing.T) {
	want, raw := stateJSONFixture(t)
	for _, input := range []string{
		`null`, `[]`, `true`, `{`, `{"version":1,`,
		string(raw) + ` null`, string(raw[:len(raw)-1]) + `,"version":null}`,
		string(raw[:len(raw)-1]) + `,"retained_window":"PRIVATE_INVALID_VALUE"}`,
	} {
		got := want
		if err := got.UnmarshalJSON([]byte(input)); err == nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("failed parsing changed the previous state or succeeded: %v", err)
		}
	}
}

func TestLoadTrustedStateRejectsShadowedEvidenceBeforeTruncation(t *testing.T) {
	want, raw := stateJSONFixture(t)
	for name, input := range map[string]string{
		"corrupt prefix": `{"retained_window":[null],` + string(raw[1:]),
		"later empty":    string(raw[:len(raw)-1]) + `,"retained_window":[]}`,
		"later null":     string(raw[:len(raw)-1]) + `,"retained_window":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, depth := range []uint64{0, 6} {
				got, err := LoadTrustedState(path, want.Genesis, VerifyOptions{Policy: Policy{W: depth}})
				if !errors.Is(err, ErrInvalidRetainedState) || got.data != nil {
					t.Fatalf("ambiguous state became trusted at W=%d: %v", depth, err)
				}
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != input {
				t.Fatalf("failed resume changed the file: %v", err)
			}
		})
	}
}

func TestPersistedStateRejectsShadowedProtocolProfile(t *testing.T) {
	state, _, _, opts := verifiedStateFixture(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(`{"protocol_profile":null,`), raw[1:]...)
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadTrustedState(path, state.Snapshot().Genesis, opts); !errors.Is(err, ErrInvalidRetainedState) || got.data != nil {
		t.Fatalf("repeated embedded profile became trusted: %v", err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, input) {
		t.Fatalf("failed resume changed its ambiguous profile: %v", err)
	}
}

func FuzzPersistedStateJSON(f *testing.F) {
	for _, seed := range []string{
		`{}`, `null`, `[]`, `{"version":1}`, `{"version":2,"VERSION":1}`,
		`{"retained_window":[null],"retained_window":[]}`,
		`{"protocol_profile":null,"protocol_profile":null}`,
		`{"capacity":1,"unknown":{},"unknown":null}`, `{} {}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		before := persistedState{Version: 1, Capacity: 7, ProtocolProfile: new(ProtocolProfile)}
		got := before
		if err := got.UnmarshalJSON(raw); err != nil {
			if !reflect.DeepEqual(got, before) {
				t.Fatal("failed decoding changed the existing state")
			}
			return
		}
		// Successful parsing must preserve the field interpretation of the
		// standard decoder. It does not imply a cryptographically valid state.
		type legacy persistedState
		var reference legacy
		if err := json.Unmarshal(raw, &reference); err != nil || !reflect.DeepEqual(got, persistedState(reference)) {
			t.Fatalf("accepted state differs from standard decoding: %v", err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var again persistedState
		if err := json.Unmarshal(encoded, &again); err != nil || !reflect.DeepEqual(again, got) {
			t.Fatalf("accepted state did not round-trip: %v", err)
		}
	})
}
