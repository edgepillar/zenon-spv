package verify

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProducerScheduleRejectsAmbiguousAuthorityFields(t *testing.T) {
	schedule := fixtureSchedule(t, 2)
	raw, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	cases := map[string]string{
		"chain replaced":          `{"chain_id":999,` + text[1:],
		"case alias":              `{"CHAIN_ID":999,` + text[1:],
		"escaped alias":           `{"chain_\u0069d":999,` + text[1:],
		"coverage replaced":       `{"coverage":[],` + text[1:],
		"entries replaced":        `{"entries":[],` + text[1:],
		"null entries replaced":   `{"entries":null,` + text[1:],
		"hash replaced":           `{"schedule_hash":"` + strings.Repeat("00", 32) + `",` + text[1:],
		"unicode fold alias":      `{"\u017fchedule_hash":"` + strings.Repeat("00", 32) + `",` + text[1:],
		"metadata replaced":       `{"generated_at":0,` + text[1:],
		"peers replaced":          `{"source_peers":["PRIVATE_UNUSED_PEER"],` + text[1:],
		"peer heights replaced":   `{"source_heights":{"PRIVATE_UNUSED_PEER":1},` + text[1:],
		"coverage start replaced": strings.Replace(text, `"from_height":`, `"from_height":0,"from_height":`, 1),
		"coverage end replaced":   strings.Replace(text, `"through_height":`, `"through_height":0,"through_height":`, 1),
		"height replaced":         strings.Replace(text, `"height":`, `"height":0,"height":`, 1),
		"timestamp replaced":      strings.Replace(text, `"timestamp_unix":`, `"timestamp_unix":0,"timestamp_unix":`, 1),
		"producer replaced":       strings.Replace(text, `"producing_addr":`, `"producing_addr":"`+strings.Repeat("00", 20)+`","producing_addr":`, 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			loaded, err := decodeProducerSchedule(strings.NewReader(input), int64(len(input)))
			if err == nil || loaded != nil {
				t.Fatal("ambiguous schedule created a usable producer authority")
			}
			if strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("schedule error echoed private metadata")
			}
		})
	}
}

func TestProducerScheduleRequiresExplicitAuthority(t *testing.T) {
	// Explicit zero is supported for custom chains and slots. Omitting a
	// field must not silently select that value, even with a matching hash.
	schedule, err := NewProducerSchedule(0, []ProducerCoverage{{0, 0}}, []ProducerEntry{{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct {
		name   string
		fields []string
	}{
		{"top", []string{"chain_id", "coverage", "entries", "schedule_hash"}},
		{"coverage", []string{"from_height", "through_height"}},
		{"entries", []string{"height", "timestamp_unix", "producing_addr"}},
	} {
		for _, field := range group.fields {
			for _, missing := range []bool{false, true} {
				name := group.name + "/" + field + "/null"
				if missing {
					name = group.name + "/" + field + "/missing"
				}
				t.Run(name, func(t *testing.T) {
					var object map[string]any
					if err := json.Unmarshal(raw, &object); err != nil {
						t.Fatal(err)
					}
					target := object
					if group.name != "top" {
						target = object[group.name].([]any)[0].(map[string]any)
					}
					if missing {
						delete(target, field)
					} else {
						target[field] = nil
					}
					input, err := json.Marshal(object)
					if err != nil {
						t.Fatal(err)
					}
					if got, err := decodeProducerSchedule(strings.NewReader(string(input)), int64(len(input))); got != nil || err == nil {
						t.Fatal("implicit authority field created a usable schedule")
					}
				})
			}
		}
	}
	for _, metadata := range []string{"", `,"generated_at":null,"source_peers":null,"source_heights":null`} {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"generated_at", "source_peers", "source_heights"} {
			delete(object, field)
		}
		minimal, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		// JSON escaping does not change a canonical field name.
		input := strings.Replace(string(minimal[:len(minimal)-1])+metadata+"}", `"chain_id"`, `"chain_\u0069d"`, 1)
		got, err := decodeProducerSchedule(strings.NewReader(input), int64(len(input)))
		if err != nil || got.ChainID != 0 || got.ScheduleHash != schedule.ScheduleHash {
			t.Fatalf("explicit zero or optional metadata compatibility: %v", err)
		}
		if _, ok := got.LookupEntry(0); !ok {
			t.Fatal("explicit zero entry lost its validated index")
		}
	}
}

func TestProducerScheduleDecodeIsTransactional(t *testing.T) {
	want := fixtureSchedule(t, 2)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`null`, `{}`, `{"source_peers":["PRIVATE_PARTIAL_VALUE"],"PRIVATE_FIELD":1}`,
		`{"entries":[{"height":1}]}`, string(raw) + `{}`, string(raw) + `PRIVATE_TRAILING_DATA`,
		strings.Replace(string(raw), `"producing_addr":`, `"producing_addr":"PRIVATE_ADDRESS","producing_addr":`, 1),
	} {
		got := fixtureSchedule(t, 2)
		got.GeneratedAt = want.GeneratedAt
		if err := got.UnmarshalJSON([]byte(input)); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid direct decode succeeded or disclosed a private value")
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("failed decode changed existing authority or its index")
		}
	}
	if err := want.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := want.LookupEntry(101); ok {
		t.Fatal("successful structural decode retained an old validated index")
	}
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, ok := want.LookupEntry(101); !ok {
		t.Fatal("validation failed to build the newly decoded index")
	}
}

func FuzzProducerScheduleJSON(f *testing.F) {
	seed, err := NewProducerSchedule(0, []ProducerCoverage{{0, 0}}, []ProducerEntry{{}}, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		f.Fatal(err)
	}
	for _, input := range []string{string(raw), `{"chain_id":0,"CHAIN_ID":1}`, `null`, string(raw) + `{}`} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		before := ProducerSchedule{ChainID: 7, GeneratedAt: 11}
		got := before
		if err := got.UnmarshalJSON([]byte(input)); err != nil {
			if !reflect.DeepEqual(got, before) {
				t.Fatal("failed decode published partial fields")
			}
			return
		}
		if !json.Valid([]byte(input)) || got.idx != nil {
			t.Fatal("structural decode accepted trailing data or authorized a schedule")
		}
		canonical, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var again ProducerSchedule
		if err := json.Unmarshal(canonical, &again); err != nil || !reflect.DeepEqual(got, again) {
			t.Fatal("accepted schedule changed during canonical round trip")
		}
		loaded, err := decodeProducerSchedule(strings.NewReader(input), int64(len(input)))
		if err == nil {
			if loaded == nil || loaded.Validate() != nil || loaded.ScheduleHash != computeScheduleHash(loaded.ChainID, loaded.Coverage, loaded.Entries) {
				t.Fatal("loader published an invalid schedule")
			}
		} else if loaded != nil {
			t.Fatal("failed validation published a schedule")
		}
	})
}
