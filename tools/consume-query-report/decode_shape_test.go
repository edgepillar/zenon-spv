package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Parent entry point at c0753fc2fc40f6fde53da3f1c2b42672e7500ba3.
// Its scan/RawMessage shape implementation is the separately copied PR #117
// reference. Neither reference shape calculation uses the borrowed traversal.
func referenceShapeDecode(raw []byte, destination any) bool {
	if !utf8.Valid(raw) || !consumerTokensBounded(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	if !referenceConsumerScan(d, 0, &nodes) {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	t := reflect.TypeOf(destination)
	if t.Kind() != reflect.Pointer || !referenceConsumerShape(raw, t.Elem()) {
		return false
	}
	return json.Unmarshal(raw, destination) == nil
}

type shapeWorkload struct {
	name     string
	raw      []byte
	accepted bool
	expected expectations
}

func consumerShapeWorkloads(t testing.TB) []shapeWorkload {
	t.Helper()
	r, e := matchingInputs(t)
	cases := []shapeWorkload{{"report", encode(t, r), true, e}}
	base := r.Results[0]
	r.Results, e.Targets = nil, nil
	for i := 0; i < maxTargets; i++ {
		item := base
		item.Reference.Index = uint64(i)
		r.Results = append(r.Results, item)
		e.Targets = append(e.Targets, item.Reference)
	}
	r.Caveats = make([]string, maxTargets)
	for i := range r.Caveats {
		r.Caveats[i] = "x"
	}
	cases = append(cases, shapeWorkload{"dense_batch", encode(t, r), true, e})
	r, e = matchingInputs(t)
	r.Caveats = make([]string, maxTargets)
	for i := range r.Caveats {
		r.Caveats[i] = strings.Repeat("x", maxConsumerStringBytes)
	}
	plain := encode(t, r)
	cases = append(cases, shapeWorkload{"large_plain", plain, true, e})
	r.Caveats = r.Caveats[:170]
	escaped := []byte(strings.ReplaceAll(string(encode(t, r)), strings.Repeat("x", maxConsumerStringBytes), strings.Repeat(`\u0078`, maxConsumerStringBytes)))
	cases = append(cases, shapeWorkload{"large_escaped", escaped, true, e})
	for _, item := range []shapeWorkload{cases[2], cases[3]} {
		raw := append(slices.Clone(item.raw[:len(item.raw)-1]), []byte(`,"PRIVATE_UNKNOWN":false}`)...)
		cases = append(cases, shapeWorkload{"late_unknown_" + strings.TrimPrefix(item.name, "large_"), raw, false, e})
	}
	for _, item := range cases {
		if len(item.raw) > maxReportBytes || !json.Valid(item.raw) {
			t.Fatal("shape workload must be complete JSON within the report byte cap")
		}
	}
	return cases
}

func checkConsumerShapeReference(t testing.TB, raw []byte) (queryReport, bool) {
	t.Helper()
	// Preserve destination behavior too, including json.Unmarshal's partial
	// destination on a scalar type/range error after successful shape checks.
	got, want := queryReport{Version: 73}, queryReport{Version: 73}
	accepted := decodeExact(raw, &got)
	previous := referenceShapeDecode(raw, &want)
	if accepted != previous || !reflect.DeepEqual(got, want) {
		t.Fatal("borrowed shape traversal changed the previous decoder contract")
	}
	return got, accepted
}

func TestConsumerShapeSpans(t *testing.T) {
	t.Run("selected_bounded_workloads", func(t *testing.T) {
		for _, item := range consumerShapeWorkloads(t) {
			t.Run(item.name, func(t *testing.T) {
				got, ok := checkConsumerShapeReference(t, item.raw)
				if ok != item.accepted || ok && (!validReport(got) || matchReport(got, item.expected) != "") {
					t.Fatal("selected shape workload changed its complete batch decision")
				}
			})
		}
	})
	r, _ := matchingInputs(t)
	raw := string(encode(t, r))
	t.Run("decoded_keys_and_order", func(t *testing.T) {
		for name, candidate := range map[string]string{
			"escaped_known_key": strings.ReplaceAll(raw, `"schema_version"`, `"schema_vers\u0069on"`),
			"reordered_fields":  `{"caveats":[],` + strings.Replace(raw[1:], `,"caveats":["PRIVATE_ENDPOINT"]`, "", 1),
			"key_quote_parity":  strings.Replace(raw, `"schema_version":1`, `"schema_version":1,"PRIVATE_\\\"KEY":false`, 1),
		} {
			t.Run(name, func(t *testing.T) {
				if !json.Valid([]byte(candidate)) {
					t.Fatal("selected key control must be complete JSON")
				}
				_, ok := checkConsumerShapeReference(t, []byte(candidate))
				if ok != (name != "key_quote_parity") {
					t.Fatal("escaped or reordered key changed its selected shape")
				}
			})
		}
	})
	t.Run("nullable_optional_and_scalar_destinations", func(t *testing.T) {
		for name, candidate := range map[string]string{
			"nullable_object": strings.Replace(raw, `"error":null`, `"error":{"category":"x","stage":"y"}`, 1),
			"null_optional":   strings.Replace(raw, `"momentum_height":18446744073709551615`, `"momentum_height":null`, 1),
			"null_scalar":     strings.Replace(raw, `"exit_code":0`, `"exit_code":null`, 1),
			"scalar_object":   strings.Replace(raw, `"exit_code":0`, `"exit_code":{"x":[{},"\\\"[]{}"]}`, 1),
			"scalar_array":    strings.Replace(raw, `"exit_code":0`, `"exit_code":[{},"\\\"[]{}"]`, 1),
			"scalar_string":   strings.Replace(raw, `"exit_code":0`, `"exit_code":"0"`, 1),
			"scalar_overflow": strings.ReplaceAll(raw, "18446744073709551615", "18446744073709551616"),
			"wrong_object":    strings.Replace(raw, `"verification_tip":{"hash":"`+strings.Repeat("3", 64)+`","height":18446744073709551615}`, `"verification_tip":[]`, 1),
		} {
			t.Run(name, func(t *testing.T) {
				if candidate == raw || !json.Valid([]byte(candidate)) {
					t.Fatal("selected scalar control must change a complete document")
				}
				_, ok := checkConsumerShapeReference(t, []byte(candidate))
				if ok != (name == "nullable_object") {
					t.Fatal("null or scalar destination changed its selected shape")
				}
			})
		}
	})
	t.Run("string_spans_and_existing_bounds", func(t *testing.T) {
		for _, value := range []string{`[]{}:,"`, `\"[]{}\\`, "x\ny\tz", "\u0078", "\u0000"} {
			r.Caveats = []string{value}
			if _, ok := checkConsumerShapeReference(t, encode(t, r)); !ok {
				t.Fatal("quoted delimiters were interpreted as structural bytes")
			}
		}
		r.Caveats = make([]string, maxTargets+1)
		if _, ok := checkConsumerShapeReference(t, encode(t, r)); ok {
			t.Fatal("shape traversal bypassed the complete token array bound")
		}
		if _, ok := checkConsumerShapeReference(t, []byte(strings.Repeat("[", 17)+raw+strings.Repeat("]", 17))); ok {
			t.Fatal("shape traversal bypassed the complete token depth bound")
		}
	})
	t.Run("fixed_private_process_refusals", func(t *testing.T) {
		for _, item := range consumerShapeWorkloads(t)[4:] {
			_, e := matchingInputs(t)
			dir := t.TempDir()
			report, expected := filepath.Join(dir, "PRIVATE_REPORT"), filepath.Join(dir, "PRIVATE_EXPECTATIONS")
			inputs := map[string][]byte{report: item.raw, expected: encode(t, e)}
			for path, input := range inputs {
				if err := os.WriteFile(path, input, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var out, diagnostics bytes.Buffer
			code := run([]string{"--report", report, "--expectations", expected, "--verifier-exit-code", "0"}, &out, &diagnostics)
			if code != 2 || out.String() != "{\"schema_version\":1,\"status\":\"not_matched\",\"category\":\"invalid_report\",\"checked_targets\":0}\n" || diagnostics.Len() != 0 {
				t.Fatal("large malformed shape changed the fixed private refusal")
			}
			for path, input := range inputs {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(input, after) {
					t.Fatal("shape refusal mutated an input")
				}
			}
		}
	})
}

func FuzzConsumerShapeSpans(f *testing.F) {
	for _, item := range consumerShapeWorkloads(f) {
		f.Add(item.raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxReportBytes {
			return
		}
		checkConsumerShapeReference(t, raw)
	})
}
