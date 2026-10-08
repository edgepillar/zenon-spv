package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Test-only strict decoder copied from PR #117 at
// 3153b9555807ab6422b8b9eb35cfbcd76efe197c. Keep its original literal limits
// and independent traversal/shape checks; do not call the new filter here.

// Bound token traversal before building typed values. Decode integers directly
// into integer fields: no float64 conversion, exponent spelling or silent null
// defaults. Duplicate keys include equivalent escaped spellings.
func referenceConsumerDecode(raw []byte, destination any) bool {
	if !utf8.Valid(raw) {
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

func referenceConsumerScan(d *json.Decoder, depth int, nodes *int) bool {
	(*nodes)++
	if depth > 16 || *nodes > 16384 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	switch v := token.(type) {
	case json.Number:
		return len(v) <= 21 && v != "-0" && !strings.ContainsAny(string(v), ".eE")
	case string:
		return len(v) <= 4096
	case json.Delim:
		switch v {
		case '{':
			keys := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || len(name) > 128 || keys[name] || len(keys) >= 256 {
					return false
				}
				keys[name] = true
				if !referenceConsumerScan(d, depth+1, nodes) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			count := 0
			for d.More() {
				count++
				if count > maxTargets || !referenceConsumerScan(d, depth+1, nodes) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	return true
}

// All fields are required, except explicitly tagged omitempty references.
// Nullable pointers model only the report's documented nullable fields. A
// present optional reference is never allowed to be null. Key matching is
// exact, unlike encoding/json's default case-insensitive struct matching.
func referenceConsumerShape(raw []byte, t reflect.Type) bool {
	raw = bytes.TrimSpace(raw)
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return true
		}
		return referenceConsumerShape(raw, t.Elem())
	}
	if bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		if raw[0] != '{' {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			name := parts[0]
			value, exists := fields[name]
			optional := len(parts) == 2 && parts[1] == "omitempty"
			if !exists {
				if optional {
					continue
				}
				return false
			}
			if optional && bytes.Equal(bytes.TrimSpace(value), []byte("null")) || !referenceConsumerShape(value, field.Type) {
				return false
			}
			delete(fields, name)
		}
		return len(fields) == 0
	case reflect.Slice:
		if raw[0] != '[' {
			return false
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return false
		}
		for _, value := range values {
			if !referenceConsumerShape(value, t.Elem()) {
				return false
			}
		}
	}
	return true // json.Unmarshal checks scalar types and integer ranges.
}

func checkConsumerDecodeReference(t testing.TB, raw []byte) (queryReport, bool) {
	t.Helper()
	var got, want queryReport
	actual := decodeExact(raw, &got)
	expected := referenceConsumerDecode(raw, &want)
	if actual != expected || !reflect.DeepEqual(got, want) {
		t.Fatal("prefilter changed the previous decoder decision or values")
	}
	return got, actual
}
func caveatInput(t testing.TB, encoded string) []byte {
	t.Helper()
	r, _ := matchingInputs(t)
	return bytes.Replace(encode(t, r), []byte("PRIVATE_ENDPOINT"), []byte(encoded), 1)
}
func oversizedConsumerInput(t testing.TB, field string, size int) []byte {
	t.Helper()
	r, _ := matchingInputs(t)
	raw := encode(t, r)
	switch field {
	case "string":
		raw = bytes.Replace(raw, []byte("PRIVATE_ENDPOINT"), bytes.Repeat([]byte{'x'}, size), 1)
	case "integer":
		raw = bytes.Replace(raw, []byte("18446744073709551615"), bytes.Repeat([]byte{'7'}, size), 1)
	default:
		t.Fatal("unknown synthetic token workload")
	}
	if len(raw) > maxReportBytes || !json.Valid(raw) {
		t.Fatal("oversized token control must be complete JSON within the byte policy")
	}
	return raw
}
func TestConsumerTokenPrefilter(t *testing.T) {
	t.Run("valid_escaped_string_boundaries", func(t *testing.T) {
		_, expected := matchingInputs(t)
		for _, encoded := range []string{
			strings.Repeat("7", 4096), strings.Repeat(`\u0078`, 4096), strings.Repeat(`\u0000`, 4096),
			strings.Repeat(`\n`, 4096), strings.Repeat(`\"`, 4096), strings.Repeat(`\\`, 4096),
			strings.Repeat(`\\\"`, 2048), strings.Repeat(`\/`, 4096), strings.Repeat("\u00e9", 2048),
			strings.Repeat(`\u00e9`, 2048), strings.Repeat(`\ud83d\ude00`, 1024), strings.Repeat(`\ud800`, 1365),
		} {
			raw := caveatInput(t, encoded)
			got, ok := checkConsumerDecodeReference(t, raw)
			if !ok || !consumerTokensBounded(raw) || !validReport(got) || matchReport(got, expected) != "" {
				t.Fatal("valid escaped boundary or quoted digits were refused")
			}
		}
	})
	t.Run("oversized_tokens_retain_refusals", func(t *testing.T) {
		for _, size := range []int{24577, 32768, 256 << 10, 1 << 20, 3 << 20} {
			for _, field := range []string{"string", "integer"} {
				raw := oversizedConsumerInput(t, field, size)
				if _, ok := checkConsumerDecodeReference(t, raw); ok || consumerTokensBounded(raw) {
					t.Fatal("oversized token bypassed early refusal")
				}
			}
		}
		for _, encoded := range []string{strings.Repeat("x", 4097), strings.Repeat(`\u0078`, 4097), strings.Repeat(`\ud83d\ude00`, 1025)} {
			if _, ok := checkConsumerDecodeReference(t, caveatInput(t, encoded)); ok {
				t.Fatal("decoded string bound changed")
			}
		}
	})
	t.Run("numeric_and_syntax_boundaries", func(t *testing.T) {
		for _, raw := range [][]byte{
			[]byte("0"), []byte("-0"), []byte(strings.Repeat("7", 21)), []byte(strings.Repeat("7", 22)),
			[]byte("-9223372036854775808"), []byte("18446744073709551615"), []byte("1.0"), []byte("1e+20"),
			[]byte(`"123456789012345678901234567890"`), []byte(`"\\\"7"`), []byte(`"\\"`),
			[]byte("null"), []byte("{} {}"), []byte(`"unterminated\`), []byte(`"\u00"`), []byte("[--1]"),
		} {
			var a, b json.Number
			x, y := decodeExact(raw, &a), referenceConsumerDecode(raw, &b)
			if x != y || a != b {
				t.Fatal("scalar lexical guard changed the previous decoder")
			}
			checkConsumerDecodeReference(t, raw)
		}
		// A maximum legal escaped token must not hide a later oversized number.
		raw := caveatInput(t, strings.Repeat(`\u0078`, 4096))
		raw = append(raw, []byte(" "+strings.Repeat("7", 22))...)
		if _, ok := checkConsumerDecodeReference(t, raw); ok || consumerTokensBounded(raw) {
			t.Fatal("earlier string hid a later oversized token")
		}
	})
	t.Run("generated_strings_fit_the_encoded_ceiling", func(t *testing.T) {
		// encoding/json independently escapes bytes and UTF-8 without relying on
		// the filter's byte-counting or quote/backslash traversal.
		alphabet := []string{"x", "7", "\x00", "\n", "\t", "\\", "\"", "\u00e9", "\u754c", "\U0001f600"}
		for rotation := range len(alphabet) {
			var value strings.Builder
			for i := 0; value.Len() < 4096; i++ {
				next := alphabet[(i+rotation)%len(alphabet)]
				if value.Len()+len(next) > 4096 {
					break
				}
				value.WriteString(next)
			}
			token := encode(t, value.String())
			if !consumerTokensBounded(token) {
				t.Fatal("accepted decoded string exceeded the lexical ceiling")
			}
			var got, want string
			if !decodeExact(token, &got) || !referenceConsumerDecode(token, &want) || got != want || got != value.String() {
				t.Fatal("encoding changed accepted string bytes")
			}
		}
	})
	t.Run("fixed_process_refusals_and_privacy", func(t *testing.T) {
		r, e := matchingInputs(t)
		dir := t.TempDir()
		reportPath := filepath.Join(dir, "PRIVATE_REPORT.json")
		expectedPath := filepath.Join(dir, "PRIVATE_EXPECTATIONS.json")
		for _, field := range []string{"string", "integer"} {
			for _, input := range []string{"report", "expectations"} {
				reportRaw, expectedRaw := encode(t, r), encode(t, e)
				category := "invalid_report"
				if input == "report" {
					reportRaw = oversizedConsumerInput(t, field, 1<<20)
				} else {
					category = "invalid_expectations"
					if field == "integer" {
						expectedRaw = bytes.Replace(expectedRaw, []byte("18446744073709551615"), bytes.Repeat([]byte{'7'}, 32768), 1)
					} else {
						expectedRaw = bytes.Replace(expectedRaw, []byte(e.Context), bytes.Repeat([]byte{'x'}, 32768), 1)
					}
					if !json.Valid(expectedRaw) || len(expectedRaw) > maxExpectationsBytes {
						t.Fatal("expectation control changed its byte or syntax boundary")
					}
				}
				for path, raw := range map[string][]byte{reportPath: reportRaw, expectedPath: expectedRaw} {
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal("cannot prepare private refusal control")
					}
				}
				var out, diagnostics bytes.Buffer
				code := run([]string{"--report", reportPath, "--expectations", expectedPath, "--verifier-exit-code", "0"}, &out, &diagnostics)
				want := `{"schema_version":1,"status":"not_matched","category":"` + category + `","checked_targets":0}` + "\n"
				if code != 2 || out.String() != want || diagnostics.Len() != 0 {
					t.Fatal("oversized token changed the fixed private refusal")
				}
				for path, wantBytes := range map[string][]byte{reportPath: reportRaw, expectedPath: expectedRaw} {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, wantBytes) {
						t.Fatal("refusal mutated an input")
					}
				}
			}
		}
	})
}
func FuzzConsumerTokenPrefilter(f *testing.F) {
	r, _ := matchingInputs(f)
	for _, seed := range [][]byte{encode(f, r), caveatInput(f, strings.Repeat(`\u0078`, 4096)), caveatInput(f, strings.Repeat("x", 4097)), []byte(`{"n":123456789012345678901234}`), []byte(`"\\\"7"`), []byte(`{"a":"\ud800"}`), []byte("{\"a\":\"\xff\"}")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		checkConsumerDecodeReference(t, raw)
	})
}
