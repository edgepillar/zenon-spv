//go:build candidate_patch_import

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func ownershipStage(events []importEvent) *importStage {
	return &importStage{expected: events, events: []importEvent{}, state: map[string]string{}, limits: importTargetCeilings}
}

func ownershipValue(value string) *string { return &value }

func TestCallbackDetachedBytesAndMetadata(t *testing.T) {
	key, value := make([]byte, 256), make([]byte, 256)
	for i := range key {
		key[i], value[i] = byte(i), byte(255-i)
	}
	wantedKey, wantedValue := hex.EncodeToString(key), hex.EncodeToString(value)
	s := ownershipStage([]importEvent{{"Put", wantedKey, ownershipValue(wantedValue)}})
	s.Put(key, value)
	for i := range key {
		key[i], value[i] = 0, 0
	}
	if s.refusal != "" || len(s.events) != 1 || s.events[0].Key != wantedKey || *s.events[0].Value != wantedValue || s.state[wantedKey] != wantedValue {
		t.Fatal("callback storage retained mutable input bytes")
	}
	if s.events[0].Value == s.expected[0].Value {
		t.Fatal("callback metadata aliases the plan's mutable pointer")
	}
	*s.expected[0].Value = "ee"
	if *s.events[0].Value != wantedValue || s.state[wantedKey] != wantedValue {
		t.Fatal("plan metadata mutation changed callback or map")
	}
	*s.events[0].Value = "ff"
	if *s.expected[0].Value != "ee" || s.state[wantedKey] != wantedValue {
		t.Fatal("callback metadata mutation changed plan or map")
	}
}

func TestCallbackEmptyPutAndDeleteRemainDistinct(t *testing.T) {
	s := ownershipStage([]importEvent{{"Put", "", ownershipValue("")}, {"Delete", "", nil}})
	s.Put(nil, []byte{})
	if value, exists := s.state[""]; !exists || value != "" || s.events[0].Value == nil {
		t.Fatal("empty Put was treated as Delete")
	}
	s.Delete([]byte{})
	if s.refusal != "" || len(s.events) != 2 || len(s.state) != 0 || s.events[1].Value != nil {
		t.Fatal("empty Delete did not retain its distinct callback")
	}
}

func TestCallbackMismatchRecordsActualBytes(t *testing.T) {
	for _, item := range []struct {
		name   string
		wanted importEvent
		key    []byte
		value  []byte
		put    bool
	}{
		{"key-high-nibble", importEvent{"Put", "00", ownershipValue("ff")}, []byte{0x10}, []byte{0xff}, true},
		{"key-low-nibble", importEvent{"Put", "00", ownershipValue("ff")}, []byte{0x01}, []byte{0xff}, true},
		{"key-length", importEvent{"Put", "00", ownershipValue("ff")}, nil, []byte{0xff}, true},
		{"value-high-nibble", importEvent{"Put", "00", ownershipValue("ff")}, []byte{0}, []byte{0xef}, true},
		{"value-low-nibble", importEvent{"Put", "00", ownershipValue("ff")}, []byte{0}, []byte{0xfe}, true},
		{"value-length", importEvent{"Put", "00", ownershipValue("ff")}, []byte{0}, nil, true},
		{"put-for-delete", importEvent{"Delete", "", nil}, nil, nil, true},
		{"delete-for-put", importEvent{"Put", "", ownershipValue("")}, nil, nil, false},
		{"delete-key", importEvent{"Delete", "00", nil}, []byte{1}, nil, false},
		{"uppercase-plan", importEvent{"Put", "FF", ownershipValue("ff")}, []byte{0xff}, []byte{0xff}, true},
		{"odd-plan", importEvent{"Put", "0", ownershipValue("ff")}, []byte{0}, []byte{0xff}, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			s := ownershipStage([]importEvent{item.wanted})
			actual := importEvent{"Delete", hex.EncodeToString(item.key), nil}
			if item.put {
				actual.Operation, actual.Value = "Put", ownershipValue(hex.EncodeToString(item.value))
				s.Put(item.key, item.value)
			} else {
				s.Delete(item.key)
			}
			if s.refusal != "callback_mismatch" || !reflect.DeepEqual(s.events, []importEvent{actual}) || len(s.state) != 0 {
				t.Fatal("mismatch was hidden or actual callback spelling changed")
			}
			s.Put([]byte{9}, []byte{9})
			s.Delete(nil)
			if !reflect.DeepEqual(s.events, []importEvent{actual}) || len(s.state) != 0 {
				t.Fatal("callbacks after refusal changed diagnostics or state")
			}
		})
	}
}

func TestCallbackExtraAndTransientRefusalPreserveState(t *testing.T) {
	for _, reason := range []string{"callback_mismatch", "target_entry_limit", "target_hex_limit"} {
		t.Run(reason, func(t *testing.T) {
			s := ownershipStage(nil)
			s.state, s.hexBytes = map[string]string{"00": "ff"}, 4
			if reason != "callback_mismatch" {
				s.expected = []importEvent{{"Put", "01", ownershipValue("ee")}}
				if reason == "target_entry_limit" {
					s.limits.Entries = 1
				} else {
					s.limits.HexBytes = 4
				}
			}
			s.Put([]byte{1}, []byte{0xee})
			if s.refusal != reason || !reflect.DeepEqual(s.state, map[string]string{"00": "ff"}) || s.hexBytes != 4 || len(s.events) != 1 {
				t.Fatal("refused callback changed the bounded staging map")
			}
			s.Delete([]byte{0})
			if len(s.events) != 1 || s.state["00"] != "ff" {
				t.Fatal("callback after refusal changed the staging map")
			}
		})
	}
}
