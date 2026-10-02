package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestBinaryRecordRequiresExactBoundedIdentity(t *testing.T) {
	digest := strings.Repeat("a", 64)
	raw := `{"command":"zenon-spv","sha256":"` + digest + `"}`
	for _, command := range candidateCommands() {
		t.Run(command, func(t *testing.T) {
			expected := binaryRecord{Command: command, SHA256: digest}
			encoded, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			record, err := parseBinaryRecord(string(encoded) + "\n")
			if err != nil || record != expected {
				t.Fatal("ordinary compiled CLI identity was refused")
			}
		})
	}
	t.Run("field order and bounded whitespace", func(t *testing.T) {
		reordered := `{"sha256":"` + digest + `","command":"zenon-spv"}`
		padded := reordered + strings.Repeat(" ", binaryRecordLimit-len(reordered))
		record, err := parseBinaryRecord(padded)
		if err != nil || record != (binaryRecord{Command: "zenon-spv", SHA256: digest}) {
			t.Fatal("exact record at byte limit was refused")
		}
	})
	for _, tc := range []struct{ name, raw string }{
		{"duplicate command", strings.Replace(raw, `"command":"zenon-spv"`, `"command":"fetch-bundle","command":"zenon-spv"`, 1)},
		{"duplicate digest", strings.Replace(raw, `"sha256":"`, `"sha256":"`+strings.Repeat("b", 64)+`","sha256":"`, 1)},
		{"escaped duplicate", strings.Replace(raw, `"command":"zenon-spv"`, `"comm\u0061nd":"zenon-spv","command":"zenon-spv"`, 1)},
		{"command case alias", strings.Replace(raw, `"command"`, `"Command"`, 1)},
		{"digest case alias", strings.Replace(raw, `"sha256"`, `"SHA256"`, 1)},
		{"unknown field", strings.Replace(raw, `}`, `,"unexpected":"PRIVATE_PATH"}`, 1)},
		{"missing command", `{"sha256":"` + digest + `"}`},
		{"missing digest", `{"command":"zenon-spv"}`},
		{"null command", strings.Replace(raw, `"zenon-spv"`, `null`, 1)},
		{"null digest", strings.Replace(raw, `"`+digest+`"`, `null`, 1)},
		{"empty command", strings.Replace(raw, `"zenon-spv"`, `""`, 1)},
		{"empty digest", strings.Replace(raw, digest, "", 1)},
		{"numeric command", strings.Replace(raw, `"zenon-spv"`, `1`, 1)},
		{"boolean digest", strings.Replace(raw, `"`+digest+`"`, `true`, 1)},
		{"object command", strings.Replace(raw, `"zenon-spv"`, `{}`, 1)},
		{"array digest", strings.Replace(raw, `"`+digest+`"`, `[]`, 1)},
		{"short digest", strings.Replace(raw, digest, digest[:63], 1)},
		{"long digest", strings.Replace(raw, digest, digest+"a", 1)},
		{"uppercase digest", strings.Replace(raw, digest, strings.Repeat("A", 64), 1)},
		{"invalid digest", strings.Replace(raw, digest, "PRIVATE_HASH", 1)},
		{"trailing object", raw + `{}`},
		{"truncated record", raw[:len(raw)-1]},
		{"null record", `null`},
		{"array record", `[]`},
		{"oversize", raw + strings.Repeat(" ", binaryRecordLimit-len(raw)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseBinaryRecord(tc.raw)
			if err == nil || err.Error() != "invalid executable record" || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("ambiguous or invalid identity accepted or private input echoed")
			}
		})
	}
}

func TestReportExecutableObservationsAreConsistentPerCase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]testEvent) []testEvent
		reject bool
	}{
		{"identical repeated root observation", func(e []testEvent) []testEvent {
			return slices.Insert(e, 3, e[2])
		}, false},
		{"identical active child observation", func(e []testEvent) []testEvent {
			repeated := e[2]
			repeated.Test = e[3].Test
			return slices.Insert(e, 4, repeated)
		}, false},
		{"conflicting repeated root observation", func(e []testEvent) []testEvent {
			conflicting := e[2]
			conflicting.Output = strings.ReplaceAll(conflicting.Output, strings.Repeat("a", 64), strings.Repeat("b", 64))
			return slices.Insert(e, 3, conflicting)
		}, true},
		{"conflicting active child observation", func(e []testEvent) []testEvent {
			conflicting := e[2]
			conflicting.Test = e[3].Test
			conflicting.Output = strings.ReplaceAll(conflicting.Output, strings.Repeat("a", 64), strings.Repeat("b", 64))
			return slices.Insert(e, 4, conflicting)
		}, true},
		{"unexpected command for active case", func(e []testEvent) []testEvent {
			e[2].Output = strings.ReplaceAll(e[2].Output, "zenon-spv", "fetch-bundle")
			return e
		}, true},
		{"observation after root completion", func(e []testEvent) []testEvent {
			return slices.Insert(e, 6, e[2])
		}, true},
		{"malformed active record", func(e []testEvent) []testEvent {
			e[2].Output = binaryMarker + `{"command":"zenon-spv","sha256":"` + strings.Repeat("a", 64) + `","unexpected":"PRIVATE_PATH"}`
			return e
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := collectEvents(t, tc.mutate(sampleEvents()))
			if tc.reject {
				if err == nil || err.Error() != "invalid executable record" || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("conflicting or inactive identity accepted or private input echoed")
				}
				return
			}
			if err != nil || c.finish(true) != "passed" || len(c.cases[0].Binaries) != 1 {
				t.Fatal("identical observation changed complete execution or was not deduplicated")
			}
		})
	}
	t.Run("ordinary observations from all seven commands", func(t *testing.T) {
		commands := candidateCommands()
		manifest := []scenario{{"sample", "internal/conformance", "TestExample", commands}}
		c := newCollector(manifest)
		events := sampleEvents()
		output := make([]testEvent, 0, len(commands))
		for _, command := range commands {
			event := events[2]
			event.Output = strings.ReplaceAll(event.Output, "zenon-spv", command)
			output = append(output, event)
		}
		events = append(events[:2], append(output, events[3:]...)...)
		for _, event := range events {
			if err := c.event(event); err != nil {
				t.Fatal(err)
			}
		}
		if c.finish(true) != "passed" || len(c.cases[0].Binaries) != len(commands) {
			t.Fatal("ordinary seven-command execution was lost")
		}
	})
	t.Run("separate cases retain their own execution identities", func(t *testing.T) {
		manifest := []scenario{
			{"first", "internal/conformance", "TestExample", []string{"zenon-spv"}},
			{"second", "internal/conformance", "TestOther", []string{"zenon-spv"}},
		}
		c := newCollector(manifest)
		events := sampleEvents()
		second := sampleEvents()
		for i := range second {
			second[i].Test = strings.ReplaceAll(second[i].Test, "TestExample", "TestOther")
			second[i].Output = strings.ReplaceAll(second[i].Output, strings.Repeat("a", 64), strings.Repeat("b", 64))
		}
		events = append(events[:len(events)-1], second[1:]...)
		for _, event := range events {
			if err := c.event(event); err != nil {
				t.Fatal(err)
			}
		}
		if c.finish(true) != "passed" || len(c.cases[0].Binaries) != 1 || len(c.cases[1].Binaries) != 1 ||
			c.cases[0].Binaries[0].SHA256 == c.cases[1].Binaries[0].SHA256 {
			t.Fatal("independent case observations were conflated")
		}
		raw, err := json.Marshal(c.cases)
		if err != nil || bytes.Contains(raw, []byte("PRIVATE")) {
			t.Fatal("raw diagnostics reached the report")
		}
	})
}
