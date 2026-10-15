package proof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Exact bodies from bbd5546d63b3657f5119ff57a86b23d473283d73, with only
// receiver types adapted. The row reference keeps append growth; the flat
// reference leaves the new private capacity hint unset. Other callbacks remain
// shared to isolate storage without changing JSON interpretation.
type growingBundleRowsReference[T any] bundleRows[T]

func (rows *growingBundleRowsReference[T]) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return err
	}
	var decoded []T
	if first != nil {
		if first != json.Delim('[') {
			return fmt.Errorf("bundle %s must be an array or null", rows.field)
		}
		decoded = make([]T, 0)
		decode := rows.decode
		if decode == nil {
			decode = func(d *json.Decoder, row *T) error { return d.Decode(row) }
		}
		for d.More() {
			if rows.limit > 0 && len(decoded) >= rows.limit {
				return &BundleCountLimitError{Field: rows.field, Limit: rows.limit}
			}
			if rows.budget != nil && rows.budget.remaining == 0 {
				return &BundleCountLimitError{Field: rows.budget.field, Limit: rows.budget.limit}
			}
			var row T
			// Decode into a fresh owned slice slot instead of making each row
			// escape separately through the callback. Neither the slice nor a
			// partially decoded slot reaches the receiver on failure.
			decoded = append(decoded, row)
			if err := decode(d, &decoded[len(decoded)-1]); err != nil {
				return err
			}
			if rows.budget != nil {
				rows.budget.remaining--
			}
		}
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("bundle %s has trailing JSON data", rows.field)
	}
	*rows.target = decoded
	return nil
}

type growingFlatEvidenceJSONReference flatEvidenceJSON

func (flat *growingFlatEvidenceJSONReference) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*flat.target = nil
		return nil
	}
	var decoded FlatContentEvidence
	if *flat.target != nil {
		// Repeated objects retain omitted fields under encoding/json's legacy
		// merge rules. Repeated arrays still consume the shared row budget.
		decoded = **flat.target
	}
	wire := struct {
		Headers bundleRows[chain.AccountHeader] `json:"sorted_headers"`
	}{Headers: bundleRows[chain.AccountHeader]{target: &decoded.SortedHeaders,
		field: "commitments.flat.sorted_headers", limit: flat.decoder.limits.MaxFlatEvidenceMembers, budget: flat.decoder.flat,
	}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*flat.target = &decoded
	return nil
}

var flatCapacityOracleCases = []string{
	"[]", "[null]", "[{},null,[]]",
	`["brackets[{}],quote\"slash\\"]`,
	`[0,-1.25e-3,true,false,null]`,
	`[{"a":[1,{"b":"x"}],"b":{}},null]`,
	`[["a,b",null],{"s":"\u005b"}]`,
	`[{"s":"\ud800"},{"s":"\\\\\\\"[]{},"}]`,
}

func TestFlatRowCapacityHint(t *testing.T) {
	cases := append([]string(nil), flatCapacityOracleCases...)
	for value := range 256 {
		for _, object := range []any{
			[]any{string([]byte{byte(value)}), map[string]any{"quoted": "\"[]{}\\,"}},
			[]any{map[string]any{"s": string(bytes.Repeat([]byte{byte(value)}, 17))}, []any{true, nil, value}},
		} {
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, string(raw))
		}
	}
	validCases := 0
	for _, raw := range cases {
		for _, padding := range []int{0, 127, 128, 4096} {
			contents := append(bytes.Repeat([]byte{' '}, padding), []byte(raw[1:])...)
			var oracle []json.RawMessage
			encoded := append([]byte{'['}, contents...)
			if err := json.Unmarshal(encoded, &oracle); err != nil {
				t.Fatal("invalid oracle fixture", err)
			}
			before := bytes.Clone(contents)
			for _, ceiling := range []int{-1, 0, 1, 2, 3, 16, 100000, int(^uint(0) >> 1)} {
				expected := max(0, min(ceiling, 100000, len(contents)/128, len(oracle)))
				if got := flatRowsCapacityHint(contents, ceiling); got != expected {
					t.Fatalf("hint differs from independent array oracle: got=%d want=%d", got, expected)
				}
				if !bytes.Equal(contents, before) {
					t.Fatal("hint changed encoded input")
				}
				validCases++
			}
		}
	}
	if validCases != 16640 {
		t.Fatal("valid hint matrix changed", validCases)
	}
	// At every selected position, all byte values must remain safe even when
	// they make the input malformed. A hint never validates these bytes.
	contents := []byte(`{"s":"\\\"[{},]","n":[true,null,{}]},null]` + strings.Repeat(" ", 4096))
	adverseCases := 0
	for position := range 32 {
		original := contents[position]
		for value := range 256 {
			contents[position] = byte(value)
			before := bytes.Clone(contents)
			got := flatRowsCapacityHint(contents, 31)
			if got < 0 || got > min(31, 100000, len(contents)/128) || !bytes.Equal(before, contents) {
				t.Fatal("malformed hint escaped its storage bounds")
			}
			adverseCases++
		}
		contents[position] = original
	}
	if adverseCases != 8192 {
		t.Fatal("adverse hint matrix changed")
	}
	// A long array independently exercises the fixed ceiling and its neighbors.
	large := []byte(strings.Repeat("null"+strings.Repeat(" ", 123)+",", 100002) + "null]")
	if !json.Valid(append([]byte{'['}, large...)) {
		t.Fatal("invalid ceiling fixture")
	}
	for _, ceiling := range []int{0, 99999, 100000, 100001} {
		if flatRowsCapacityHint(large, ceiling) != min(ceiling, 100000) {
			t.Fatal("fixed initial-capacity ceiling changed")
		}
	}
	t.Log(`flat-row-capacity-hint {"schema_version":1,"valid_oracle_cases":16640,"adverse_byte_cases":8192,"fixed_ceiling_cases":4}`)
}

func compareFlatCapacityRows[T any](t testing.TB, raw []byte, limit, total int, direct bool, callback bundleRowCallback[T]) {
	t.Helper()
	input := bytes.Clone(raw)
	var results [2]bundleRowObservation[T]
	for mode := range results {
		seed := make([]T, 1)
		before, err := json.Marshal(seed)
		if err != nil {
			t.Fatal(err)
		}
		got := seed
		budget := newRowBudget("test_total_rows", total)
		decode, budgets := callback()
		rows := bundleRows[T]{target: &got, field: "test_rows", limit: limit, budget: budget, decode: decode, capacityHint: flatRowsCapacityHint}
		var target json.Unmarshaler = &rows
		if mode == 1 {
			old := growingBundleRowsReference[T](rows)
			target = &old
		}
		if direct {
			err = target.UnmarshalJSON(raw)
		} else {
			err = json.Unmarshal(raw, target)
		}
		if err != nil {
			after, marshalErr := json.Marshal(got)
			if marshalErr != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(got, seed) {
				t.Fatal("failed hinted rows changed the receiver")
			}
		}
		if !bytes.Equal(raw, input) {
			t.Fatal("hinted rows changed encoded input")
		}
		results[mode] = bundleRowObservation[T]{got, err, append(budgets(), bundleRowRemaining(budget))}
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf("hint changed projection, concrete errors or budgets: current=%+v reference=%+v", results[0], results[1])
	}
}

func TestFlatRowCapacityReference(t *testing.T) {
	cases := append(append([]string(nil), bundleRowCommonCases...),
		`[{"height":7,"height":null}]`,
		`[{"hash":"bad"}]`,
		`[{"flat":{"sorted_headers":[null,null]},"flat":null}]`,
		`[{"flat":{"sorted_headers":[null,null]},"flat":{"sorted_headers":[null,"PRIVATE_UNREACHED"]}}]`,
		`[{"blocks":[null,null],"blocks":[null,"PRIVATE_UNREACHED"]}]`,
		`[{"blocks":[{"amount":"12345"}]}]`,
		`[{"proof_nodes":["AQID","PRIVATE_UNREACHED"]}]`,
		`[{"version":2,"nextFusionPrice":0,"nextWorkPrice":null}]`,
		`[{"unknown":{"meta":"`+strings.Repeat("x", 256)+`"}},null,{}]`)
	count := 0
	for _, kind := range []string{"account_headers", "headers", "commitments", "segments", "state_proofs", "proof_nodes"} {
		t.Run(kind, func(t *testing.T) {
			for _, raw := range cases {
				for _, padding := range []int{0, 256} {
					selected := raw
					if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "[") {
						opening := strings.IndexByte(raw, '[')
						selected = raw[:opening+1] + strings.Repeat(" ", padding) + raw[opening+1:]
					}
					for _, direct := range []bool{false, true} {
						for _, limit := range []int{0, 1, 3} {
							for _, total := range []int{0, 1, 4} {
								switch kind {
								case "account_headers":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, plainBundleRowCallback[chain.AccountHeader])
								case "headers":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, plainBundleRowCallback[chain.Header])
								case "commitments":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, commitmentBundleRowCallback)
								case "segments":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, segmentBundleRowCallback)
								case "state_proofs":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, stateProofBundleRowCallback)
								case "proof_nodes":
									compareFlatCapacityRows(t, []byte(selected), limit, total, direct, proofNodeBundleRowCallback)
								}
								count++
							}
						}
					}
				}
			}
		})
	}
	if count != 6480 {
		t.Fatal("hinted reference matrix changed", count)
	}
	t.Log(`flat-row-capacity-reference {"schema_version":1,"cases":6480,"concrete_types":6,"entry_paths":2,"padding_variants":2,"errors_and_budgets_checked":true}`)
}

func compareFlatCapacityEvidence(t testing.TB, raw []byte, limit, total int, direct bool) {
	t.Helper()
	type result struct {
		flat      *FlatContentEvidence
		err       error
		remaining int
	}
	var results [2]result
	for mode := range results {
		seed := FlatContentEvidence{SortedHeaders: []chain.AccountHeader{{Height: 77, Hash: chain.Hash{77}}}}
		before, _ := json.Marshal(seed)
		got := &seed
		e := newEvidenceDecoder(DecodeLimits{MaxFlatEvidenceMembers: limit, MaxTotalFlatEvidenceMembers: total})
		current := flatEvidenceJSON{target: &got, decoder: &e}
		var target json.Unmarshaler = &current
		if mode == 1 {
			old := growingFlatEvidenceJSONReference(current)
			target = &old
		}
		var err error
		if direct {
			err = target.UnmarshalJSON(raw)
		} else {
			err = json.Unmarshal(raw, target)
		}
		if err != nil {
			after, _ := json.Marshal(got)
			if !bytes.Equal(after, before) {
				t.Fatal("failed flat decode changed existing evidence")
			}
		}
		results[mode] = result{got, err, bundleRowRemaining(e.flat)}
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf("flat merge, concrete error or charged budget differs: current=%+v reference=%+v", results[0], results[1])
	}
}

func TestFlatRowCapacityIntegration(t *testing.T) {
	cases := []string{
		"null", "{}", `{"sorted_headers":[]}`,
		`{"SORTED_HEADER\u017f":[null,{}],"sorted_headers":null}`,
		`{"sorted_headers":[null,null],"SORTED_HEADERS":[null,"PRIVATE_UNREACHED"]}`,
		`{"sorted_headers":true,"sorted_headers":[]}`,
		`{"sorted_headers":[{"hash":"bad"},null,null]}`,
		`{"sorted_headers":[null,null,null,"PRIVATE_UNREACHED"]}`,
		`{"unknown":{"brackets":"\\\"[{}],"},"sorted_headers":[{}]}`,
		`{"sorted_headers":[null],`,
		`{"sorted_headers":[null]} {}`,
		"true", "[]",
	}
	for _, raw := range cases {
		for _, direct := range []bool{false, true} {
			for _, limit := range []int{0, 1, 3} {
				for _, total := range []int{0, 1, 4} {
					compareFlatCapacityEvidence(t, []byte(raw), limit, total, direct)
				}
			}
		}
	}
	// Actual production flat decoding must use the hint and preserve complete rows.
	members := make([]chain.AccountHeader, 1000)
	for i := range members {
		members[i] = chain.AccountHeader{Address: chain.Address{byte(i)}, Height: uint64(i + 1), Hash: chain.Hash{byte(i), byte(i >> 8)}}
	}
	encoded, err := json.Marshal(FlatContentEvidence{SortedHeaders: members})
	if err != nil {
		t.Fatal(err)
	}
	var got *FlatContentEvidence
	e := newEvidenceDecoder(DecodeLimits{MaxFlatEvidenceMembers: 1000, MaxTotalFlatEvidenceMembers: 1000})
	if err := json.Unmarshal(encoded, &flatEvidenceJSON{target: &got, decoder: &e}); err != nil || got == nil || !reflect.DeepEqual(got.SortedHeaders, members) || cap(got.SortedHeaders) != 1000 || e.flat.remaining != 0 {
		t.Fatal("production flat capacity, rows or exact budget changed", err)
	}
	encoded[0] = 'x'
	if !reflect.DeepEqual(got.SortedHeaders, members) {
		t.Fatal("flat rows borrowed encoded input")
	}
	original := got.SortedHeaders
	var repeated *FlatContentEvidence
	e = newEvidenceDecoder(DecodeLimits{})
	raw, _ := json.Marshal(FlatContentEvidence{SortedHeaders: members})
	if err := json.Unmarshal(raw, &flatEvidenceJSON{target: &repeated, decoder: &e}); err != nil {
		t.Fatal(err)
	}
	repeated.SortedHeaders[0].Hash[0] ^= 1
	if !reflect.DeepEqual(original, members) || !reflect.DeepEqual(repeated.SortedHeaders[1:], members[1:]) {
		t.Fatal("hinted rows or repeated decodes alias")
	}
}

var flatHintAllocationSink int

func TestFlatRowCapacityGuards(t *testing.T) {
	if size := reflect.TypeOf(chain.AccountHeader{}).Size(); size > 64 {
		t.Fatal("account-header size exceeds the hint's stated bound", size)
	}
	if flatCapacityMaxRows != 100000 || flatCapacityWireBytes != 128 {
		t.Fatal("hint storage policy changed")
	}
	for _, tc := range []struct {
		name                             string
		limit, total, remaining, ceiling int
	}{
		{"unbounded", 0, 0, -1, int(^uint(0) >> 1)}, {"array", 2, 0, -1, 2}, {"aggregate", 0, 3, 1, 1},
		{"both", 2, 3, 1, 1}, {"empty_budget", 2, 3, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []chain.AccountHeader
			budget := newRowBudget("test_total_rows", tc.total)
			if budget != nil {
				budget.remaining = tc.remaining
			}
			seen := -1
			rows := bundleRows[chain.AccountHeader]{target: &got, field: "test_rows", limit: tc.limit, budget: budget,
				capacityHint: func(contents []byte, ceiling int) int { seen = ceiling; return flatRowsCapacityHint(contents, ceiling) }}
			if err := json.Unmarshal([]byte("["+strings.Repeat(" ", 256)+"{}]"), &rows); tc.ceiling == 0 {
				if err == nil || seen != 0 || got != nil {
					t.Fatal("empty budget reserved or accepted a row")
				}
			} else if err != nil || seen != tc.ceiling || len(got) != 1 || cap(got) != 1 {
				t.Fatal("hint did not respect the active row ceiling", err)
			}
		})
	}
	// Dense invalid input cannot obtain a large initial allocation from tiny rows.
	dense := []byte(strings.Repeat("null,", 10000) + "null]")
	if got := flatRowsCapacityHint(dense, 100000); got != min(10001, len(dense)/128) {
		t.Fatal("wire-byte reservation bound changed")
	}
	raw := []byte(`{"height":7,"s":"[]\\\"{},"},null]` + strings.Repeat(" ", 4096))
	if allocations := testing.AllocsPerRun(100, func() { flatHintAllocationSink = flatRowsCapacityHint(raw, 1000) }); allocations != 0 {
		t.Fatal("capacity hint allocated", allocations)
	}
}

func FuzzFlatRowCapacityHint(f *testing.F) {
	for _, raw := range append(append([]string(nil), flatCapacityOracleCases...), `{"sorted_headers":[null,null],"sorted_headers":null}`, "[", "[] null") {
		f.Add([]byte(raw), uint8(3))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 64<<10 {
			return
		}
		before := bytes.Clone(raw)
		ceiling := int(count)
		hint := flatRowsCapacityHint(raw, ceiling)
		if hint < 0 || hint > min(ceiling, 100000, len(raw)/128) || !bytes.Equal(raw, before) {
			t.Fatal("arbitrary hint escaped its storage or input bounds")
		}
		for _, direct := range []bool{false, true} {
			compareFlatCapacityRows(t, raw, int(count%6), int((count/6)%6), direct, plainBundleRowCallback[chain.AccountHeader])
			compareFlatCapacityEvidence(t, raw, int(count%6), int((count/6)%6), direct)
		}
	})
}

// Complete synthetic arrays isolate backing-storage growth. Encoding and a
// full projection check are outside timing. No proof, peak RSS, production
// budget or whole-CI timing claim follows from these allocation observations.
func BenchmarkFlatRowCapacity(b *testing.B) {
	for _, members := range []int{1000, 100000} {
		want := make([]chain.AccountHeader, members)
		for i := range want {
			want[i] = chain.AccountHeader{Address: chain.Address{byte(i), byte(i >> 8)}, Height: uint64(i + 1), Hash: chain.Hash{byte(i), byte(i >> 8)}}
		}
		raw, err := json.Marshal(want)
		if err != nil {
			b.Fatal(err)
		}
		for _, mode := range []string{"growing_reference", "hinted"} {
			b.Run(fmt.Sprintf("members_%d/%s", members, mode), func(b *testing.B) {
				decode := func() ([]chain.AccountHeader, error) {
					var got []chain.AccountHeader
					rows := bundleRows[chain.AccountHeader]{target: &got, field: "flat.sorted_headers", limit: members, capacityHint: flatRowsCapacityHint}
					var target json.Unmarshaler = &rows
					if mode == "growing_reference" {
						old := growingBundleRowsReference[chain.AccountHeader](rows)
						target = &old
					}
					err := json.Unmarshal(raw, target)
					return got, err
				}
				got, err := decode()
				if err != nil || !reflect.DeepEqual(got, want) || (mode == "hinted" && cap(got) != members) {
					b.Fatal("capacity benchmark projection or reservation differs", err)
				}
				capacity := cap(got)
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for range b.N {
					got, err := decode()
					if err != nil || len(got) != members || got[0] != want[0] || got[members/2] != want[members/2] || got[members-1] != want[members-1] || cap(got) != capacity {
						b.Fatal("capacity benchmark decode changed", err)
					}
				}
				b.ReportMetric(float64(capacity), "capacity-rows/op")
			})
		}
	}
}
