package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func strictProfileFixture() ProtocolProfile {
	return ProtocolProfile{Version: 1, Anchor: GenesisTrustRoot{ChainID: 0, Height: 100, HeaderHash: chain.Hash{1}},
		ValidThrough: 200, V2FromHeight: 150, Source: "synthetic profile"}
}

func TestProtocolProfileRejectsAmbiguousJSON(t *testing.T) {
	want := strictProfileFixture()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	cases := map[string]string{
		"duplicate activation":      `{"v2_from_height":0,` + valid[1:],
		"duplicate schema":          `{"version":2,` + valid[1:],
		"duplicate coverage":        `{"valid_through":999,` + valid[1:],
		"duplicate source":          `{"source":"other source",` + valid[1:],
		"duplicate anchor":          `{"anchor":null,` + valid[1:],
		"escaped duplicate":         `{"v2_from_\u0068eight":0,` + valid[1:],
		"case alias":                strings.Replace(valid, `"v2_from_height"`, `"V2_FROM_HEIGHT"`, 1),
		"missing anchor chain ID":   strings.Replace(valid, `"chain_id":0,`, "", 1),
		"null anchor chain ID":      strings.Replace(valid, `"chain_id":0`, `"chain_id":null`, 1),
		"duplicate anchor chain ID": strings.Replace(valid, `"chain_id":0`, `"chain_id":7,"chain_id":0`, 1),
		"duplicate anchor height":   strings.Replace(valid, `"height":100`, `"height":99,"height":100`, 1),
		"anchor case alias":         strings.Replace(valid, `"chain_id"`, `"CHAIN_ID"`, 1),
		"unknown private field":     `{"private-profile-value":true,` + valid[1:],
		"invalid private value":     strings.Replace(valid, `"version":1`, `"version":"private-profile-value"`, 1),
		"trailing JSON":             valid + `{}`,
	}
	for _, field := range []string{`"version":1`, `"valid_through":200`, `"v2_from_height":150`, `"source":"synthetic profile"`} {
		key, _, _ := strings.Cut(field, ":")
		without := strings.Replace(valid, field+",", "", 1)
		if without == valid {
			without = strings.Replace(valid, ","+field, "", 1)
		}
		cases["missing "+key] = without
		cases["null "+key] = strings.Replace(valid, field, key+":null", 1)
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := LoadProtocolProfile(path); got != nil || !errors.Is(err, ErrInvalidProtocolProfile) {
				t.Fatalf("ambiguous profile loaded: profile=%v err=%v", got, err)
			}
			// Decoding a profile embedded in another schema follows the same
			// rules and must not mutate an existing policy on failure.
			got := want
			err := json.Unmarshal([]byte(input), &got)
			if err == nil || got != want {
				t.Fatalf("failed decoding changed policy or succeeded: profile=%v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "private-profile-value") {
				t.Fatal("private input reached a parser diagnostic")
			}
		})
	}
}

func TestProtocolProfileJSONSizeAndExplicitZero(t *testing.T) {
	want := strictProfileFixture()
	want.V2FromHeight = 0
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	// Internal whitespace counts toward the profile bound, including when a
	// profile is embedded in retained state. Both explicit zero fields work.
	padded := string(raw[:len(raw)-1]) + strings.Repeat(" ", 16*1024-len(raw)) + "}"
	path := filepath.Join(t.TempDir(), "profile.json")
	for _, extra := range []string{"", " "} {
		input := padded[:len(padded)-1] + extra + "}"
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		got, loadErr := LoadProtocolProfile(path)
		var decoded ProtocolProfile
		decodeErr := json.Unmarshal([]byte(input), &decoded)
		if extra == "" {
			if loadErr != nil || decodeErr != nil || got == nil || *got != want || decoded != want {
				t.Fatalf("profile at exact byte cap: load=%v decode=%v", loadErr, decodeErr)
			}
		} else if got != nil || !errors.Is(loadErr, ErrInvalidProtocolProfile) || !errors.Is(decodeErr, ErrInvalidProtocolProfile) {
			t.Fatalf("oversized profile: load=%v decode=%v", loadErr, decodeErr)
		}
	}
}

func TestTrustedResumeRejectsDuplicateProfileFields(t *testing.T) {
	state, _, _, opts := verifiedStateFixture(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	profile := wire["protocol_profile"]
	wire["protocol_profile"] = append([]byte(`{"v2_from_height":999,`), profile[1:]...)
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadTrustedState(path, state.Snapshot().Genesis, opts); !got.Empty() || !errors.Is(err, ErrInvalidProtocolProfile) {
		t.Fatalf("ambiguous retained profile resumed: empty=%v err=%v", got.Empty(), err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, tampered) {
		t.Fatalf("failed resume rewrote its input: %v", err)
	}
}

func FuzzProtocolProfileJSON(f *testing.F) {
	raw, err := json.Marshal(strictProfileFixture())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{string(raw), `null`, `{}`, `{"v2_from_height":0,"v2_from_height":150}`, string(raw) + `{}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		before := strictProfileFixture()
		got := before
		if err := got.UnmarshalJSON([]byte(input)); err != nil {
			if got != before {
				t.Fatal("failed parsing changed an existing profile")
			}
			return
		}
		if len(input) > MaxProtocolProfileBytes || got.Anchor.Validate() != nil {
			t.Fatal("accepted profile violates structural bounds")
		}
		if got.Validate() != nil {
			// Parsing is not policy authorization. Only a validated profile
			// must round-trip through the bounded persistence encoding.
			return
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var again ProtocolProfile
		if err := json.Unmarshal(raw, &again); err != nil || again != got {
			t.Fatalf("decoded profile did not round-trip: %v", err)
		}
	})
}
