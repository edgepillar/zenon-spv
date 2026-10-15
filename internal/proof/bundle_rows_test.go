package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Exact helper body from de6f10b083fe1b692c082b5d5a75b2c8fea3e445, with
// only its receiver type adapted. Keep the old per-row allocation in this
// test-only reference; nested callback implementations remain shared.
type allocatingBundleRowsReference[T any] bundleRows[T]

func (rows *allocatingBundleRowsReference[T]) UnmarshalJSON(raw []byte) error {
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
			if err := decode(d, &row); err != nil {
				return err
			}
			decoded = append(decoded, row)
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

type bundleRowObservation[T any] struct {
	rows    []T
	err     error
	budgets []int
}

func bundleRowRemaining(budget *rowBudget) int {
	if budget == nil {
		return -1
	}
	return budget.remaining
}

type bundleRowCallback[T any] func() (func(*json.Decoder, *T) error, func() []int)

func plainBundleRowCallback[T any]() (func(*json.Decoder, *T) error, func() []int) {
	return nil, func() []int { return nil }
}

func compareBundleRowSlots[T any](t testing.TB, raw []byte, limit, total int, direct bool, callback bundleRowCallback[T]) {
	t.Helper()
	input := bytes.Clone(raw)
	var observations [2]bundleRowObservation[T]
	for mode := range observations {
		seed := make([]T, 1)
		before, err := json.Marshal(seed)
		if err != nil {
			t.Fatal(err)
		}
		got := seed
		budget := newRowBudget("test_total_rows", total)
		decode, budgets := callback()
		rows := bundleRows[T]{target: &got, field: "test_rows", limit: limit, budget: budget, decode: decode}
		var target json.Unmarshaler = &rows
		if mode == 1 {
			reference := allocatingBundleRowsReference[T](rows)
			target = &reference
		}
		if direct {
			err = target.UnmarshalJSON(raw)
		} else {
			err = json.Unmarshal(raw, target)
		}
		if err != nil {
			after, marshalErr := json.Marshal(got)
			if marshalErr != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(got, seed) {
				t.Fatal("failed row decode changed the receiver or its backing data")
			}
		}
		if !bytes.Equal(raw, input) {
			t.Fatal("row decode changed the encoded input")
		}
		observations[mode] = bundleRowObservation[T]{got, err, append(budgets(), bundleRowRemaining(budget))}
	}
	if !reflect.DeepEqual(observations[0], observations[1]) {
		t.Fatalf("row projection, concrete error details or consumed budgets differ: current=%+v reference=%+v", observations[0], observations[1])
	}
}

func commitmentBundleRowCallback() (func(*json.Decoder, *CommitmentEvidence) error, func() []int) {
	e := newEvidenceDecoder(DecodeLimits{MaxFlatEvidenceMembers: 2, MaxTotalFlatEvidenceMembers: 3})
	return e.commitment, func() []int { return []int{bundleRowRemaining(e.flat)} }
}

func segmentBundleRowCallback() (func(*json.Decoder, *AccountSegment) error, func() []int) {
	e := newEvidenceDecoder(DecodeLimits{MaxSegmentBlocks: 2, MaxTotalSegmentBlocks: 3, MaxAccountAmountBytes: 4})
	return e.segment, func() []int { return []int{bundleRowRemaining(e.blocks)} }
}

func stateProofBundleRowCallback() (func(*json.Decoder, *StateValueProof) error, func() []int) {
	e := newEvidenceDecoder(DecodeLimits{MaxStateProofNodes: 2, MaxStateProofBytes: 3})
	return e.stateProof, func() []int { return nil }
}

func proofNodeBundleRowCallback() (func(*json.Decoder, *[]byte) error, func() []int) {
	budget := &proofByteBudget{limit: 3, remaining: 3}
	return budget.decodeNode, func() []int { return []int{budget.remaining} }
}

var bundleRowCommonCases = []string{
	`null`, `[]`, `[null]`, `[{},null,{}]`, `[null,null,null,null]`,
	`{}`, `true`, `1`, `"PRIVATE"`, ``, `[`, `[,{}]`, `[{},]`, `["bad"]`,
	`[] null`, `[{}] {}`, `[{},false]`, `[{},1]`, `[{},[]]`,
	" \n\t[null,{}]\r\n", `[{"unknown":{"s":"\\\"{}[],:","a":[true,null,1e-9]}}]`,
}

func TestBundleRowOwnedSlotsReference(t *testing.T) {
	checks := 0
	for _, direct := range []bool{false, true} {
		entry := "stdlib"
		if direct {
			entry = "direct"
		}
		for _, kind := range []string{"account_headers", "headers", "commitments", "segments", "state_proofs", "proof_nodes"} {
			t.Run(entry+"/"+kind, func(t *testing.T) {
				cases := append([]string(nil), bundleRowCommonCases...)
				switch kind {
				case "account_headers":
					cases = append(cases, `[{"height":7,"HEIGHT":null}]`, `[{"height":18446744073709551615}]`,
						`[{"height":18446744073709551616}]`, `[{"height":-1}]`, `[{"hash":"bad"}]`,
						`[{"addre\u017fs":null,"height":true}]`, `[{"address":"\u0000"}]`)
				case "headers":
					cases = append(cases, `[{"version":2}]`, `[{"version":2,"nextFusionPrice":0,"nextWorkPrice":0}]`,
						`[{"version":2,"nextFusionPrice":0,"nextWorkPrice":null}]`, `[{"publicKey":"AA==","signature":"AQ=="}]`,
						`[{"height":-1}]`, `[{"hash":"bad"}]`, `[{"publicKey":"!"}]`)
				case "commitments":
					cases = append(cases, `[{"flat":{"sorted_headers":[null,{}]},"flat":{}}]`,
						`[{"flat":{"sorted_headers":[null,{}]},"flat":null},{"FLAT":{"SORTED_HEADER\u017f":[null,"PRIVATE_UNREACHED"]}}]`,
						`[{"flat":{"sorted_headers":[null,null],"sorted_headers":[null,"PRIVATE_UNREACHED"]}}]`,
						`[{"flat":1,"flat":{}}]`, `[{"height":-1}]`, `[{"target":{"hash":"bad"}}]`,
						`[{"flat":{"sorted_headers":[null,null,"PRIVATE_UNREACHED"]}}]`)
				case "segments":
					cases = append(cases, `[{"blocks":[null,{}],"BLOCK\u017f":[null,"PRIVATE_UNREACHED"]}]`,
						`[{"blocks":[null,null]},{"blocks":[null,"PRIVATE_UNREACHED"]}]`,
						`[{"blocks":[{"amount":"12345"}]}]`, `[{"blocks":1,"blocks":[]}]`,
						`[{"blocks":[{"data":"AQID","signature":"AA=="}]}]`, `[{"address":"bad"}]`,
						`[{"blocks":[null,null,"PRIVATE_UNREACHED"]}]`)
				case "state_proofs":
					cases = append(cases, `[{"proof_nodes":["AQID",null]}]`, `[{"proof_nodes":["AQID","PRIVATE_UNREACHED"]}]`,
						`[{"proof_nodes":["AQID"],"PROOF_NODE\u017f":["PRIVATE_UNREACHED"]}]`,
						`[{"proof_nodes":[null,null,"PRIVATE_UNREACHED"]}]`, `[{"proof_nodes":["AQIDBA=="]}]`,
						`[{"proof_nodes":{},"proof_nodes":[]}]`, `[{"proof_nodes":["!"]}]`)
				case "proof_nodes":
					cases = append(cases, `["AQID",null]`, `["AQID","PRIVATE_UNREACHED"]`, `["AQIDBA=="]`,
						`["!"]`, `["AQ==","Ag==","Aw=="]`, `["AQ==",null,"AgM="]`, `["AQID",""]`)
				}
				for _, raw := range cases {
					for _, limit := range []int{0, 1, 3} {
						for _, total := range []int{0, 1, 4} {
							switch kind {
							case "account_headers":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, plainBundleRowCallback[chain.AccountHeader])
							case "headers":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, plainBundleRowCallback[chain.Header])
							case "commitments":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, commitmentBundleRowCallback)
							case "segments":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, segmentBundleRowCallback)
							case "state_proofs":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, stateProofBundleRowCallback)
							case "proof_nodes":
								compareBundleRowSlots(t, []byte(raw), limit, total, direct, proofNodeBundleRowCallback)
							}
							checks++
						}
					}
				}
			})
		}
	}
	if checks != 3024 {
		t.Fatalf("row reference matrix changed: %d", checks)
	}
	t.Log(`bundle-row-owned-slots-reference {"schema_version":1,"cases":3024,"concrete_types":6,"entry_paths":2,"concrete_errors_checked":true,"consumed_budgets_checked":true,"input_preservation":true}`)
}

func TestBundleRowOwnedSlotsDecodeOrdering(t *testing.T) {
	sentinel := errors.New("selected row failed")
	for _, tc := range []struct {
		name, raw           string
		limit, total, calls int
		field               string
	}{
		{"array_first", `[1,2,3]`, 2, 2, 2, "test_rows"},
		{"aggregate_first", `[1,2,3]`, 3, 1, 1, "test_total_rows"},
		{"early_error", `[1,-1,3]`, 3, 3, 2, ""},
		{"unreached_error", `[1,2,-1]`, 2, 3, 2, "test_rows"},
		{"success", `[1,2,3]`, 3, 3, 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reference := range []bool{false, true} {
				got := []int{77}
				budget := newRowBudget("test_total_rows", tc.total)
				calls := 0
				rows := bundleRows[int]{target: &got, field: "test_rows", limit: tc.limit, budget: budget,
					decode: func(d *json.Decoder, row *int) error {
						calls++
						if *row != 0 {
							t.Fatal("callback received an earlier row's value")
						}
						if err := d.Decode(row); err != nil {
							return err
						}
						if *row < 0 {
							return sentinel
						}
						return nil
					}}
				var target json.Unmarshaler = &rows
				if reference {
					old := allocatingBundleRowsReference[int](rows)
					target = &old
				}
				err := json.Unmarshal([]byte(tc.raw), target)
				if calls != tc.calls {
					t.Fatalf("count refusal reached an excess callback: %d", calls)
				}
				consumed := calls
				if tc.name == "early_error" {
					consumed--
				}
				if budget.remaining != tc.total-consumed {
					t.Fatal("failed callback consumed or refunded a row slot")
				}
				if tc.field != "" {
					var count *BundleCountLimitError
					if !errors.As(err, &count) || count.Field != tc.field {
						t.Fatalf("count refusal ordering changed: %v", err)
					}
				} else if tc.name == "early_error" {
					if !errors.Is(err, sentinel) {
						t.Fatal("callback error identity changed")
					}
				} else if err != nil || !reflect.DeepEqual(got, []int{1, 2, 3}) {
					t.Fatal("exact-budget successful decode changed")
				}
				if err != nil && !reflect.DeepEqual(got, []int{77}) {
					t.Fatal("failed row escaped to the receiver")
				}
			}
		})
	}
}

func TestBundleRowOwnedSlotsOwnership(t *testing.T) {
	type ownedRow struct {
		Index int      `json:"index"`
		Data  []byte   `json:"data"`
		Words []string `json:"words"`
	}
	want := make([]ownedRow, 1024)
	for i := range want {
		want[i] = ownedRow{i, []byte{byte(i), byte(i >> 8)}, []string{fmt.Sprint(i), "original"}}
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []bool{false, true} {
		target := []ownedRow{{77, []byte{77}, []string{"preserved"}}}
		original := target
		oldBytes, _ := json.Marshal(original)
		decode := func(input []byte, limit int) error {
			rows := bundleRows[ownedRow]{target: &target, field: "owned_rows", limit: limit}
			if reference {
				old := allocatingBundleRowsReference[ownedRow](rows)
				return json.Unmarshal(input, &old)
			}
			return json.Unmarshal(input, &rows)
		}
		if err := decode(raw, len(want)); err != nil || !reflect.DeepEqual(target, want) {
			t.Fatal("owned row decode lost a field", err)
		}
		first := target
		if err := decode(raw, len(want)); err != nil || !reflect.DeepEqual(target, want) {
			t.Fatal("repeated decode changed its interpretation", err)
		}
		target[0].Index = -1
		target[0].Data[0] ^= 1
		target[0].Words[0] = "changed"
		if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(target[1:], want[1:]) {
			t.Fatal("distinct decodes or adjacent rows share mutable backing data")
		}
		if after, _ := json.Marshal(original); !bytes.Equal(after, oldBytes) {
			t.Fatal("successful decode reused the original receiver's storage")
		}
		before, _ := json.Marshal(target)
		bad := append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"PRIVATE_UNREACHED"]`)...)
		for _, limit := range []int{len(want), len(want) + 1} {
			if err := decode(bad, limit); err == nil {
				t.Fatal("count or late type failure unexpectedly succeeded")
			}
			if after, _ := json.Marshal(target); !bytes.Equal(after, before) {
				t.Fatal("failed decode changed previously returned rows")
			}
		}
		// No encoded input buffer may remain behind the returned rows.
		input := bytes.Clone(raw)
		if err := decode(input, len(want)); err != nil {
			t.Fatal(err)
		}
		for i := range input {
			input[i] = 'x'
		}
		if !reflect.DeepEqual(target, want) {
			t.Fatal("returned rows borrowed their strings or bytes from JSON input")
		}
	}
}

func FuzzBundleRowOwnedSlots(f *testing.F) {
	for _, raw := range append(append([]string(nil), bundleRowCommonCases...),
		`[{"flat":{"sorted_headers":[null,null]},"flat":null}]`,
		`[{"blocks":[{"amount":"12345"}]}]`, `[{"proof_nodes":["AQID","PRIVATE_UNREACHED"]}]`) {
		f.Add([]byte(raw), uint8(2))
	}
	f.Fuzz(func(t *testing.T, raw []byte, count uint8) {
		if len(raw) > 4096 {
			return
		}
		limit, total := int(count%6), int((count/6)%6)
		for _, direct := range []bool{false, true} {
			compareBundleRowSlots(t, raw, limit, total, direct, plainBundleRowCallback[chain.AccountHeader])
			compareBundleRowSlots(t, raw, limit, total, direct, plainBundleRowCallback[chain.Header])
			compareBundleRowSlots(t, raw, limit, total, direct, commitmentBundleRowCallback)
			compareBundleRowSlots(t, raw, limit, total, direct, segmentBundleRowCallback)
			compareBundleRowSlots(t, raw, limit, total, direct, stateProofBundleRowCallback)
			compareBundleRowSlots(t, raw, limit, total, direct, proofNodeBundleRowCallback)
		}
	})
}

// Complete synthetic account-header arrays isolate row storage, with encoding
// and full projection checks outside timing. Both modes retain every field and
// use the same count guard. These are allocation observations, not proofs,
// peak RSS, device budgets, sustainable throughput or whole-CI timing claims.
func BenchmarkProofBundleRowOwnedSlots(b *testing.B) {
	for _, members := range []int{1000, 100000} {
		want := make([]chain.AccountHeader, members)
		for i := range want {
			want[i] = chain.AccountHeader{Address: chain.Address{byte(i), byte(i >> 8)}, Height: uint64(i + 1), Hash: chain.Hash{byte(i), byte(i >> 8)}}
		}
		raw, err := json.Marshal(want)
		if err != nil {
			b.Fatal(err)
		}
		for _, mode := range []string{"allocating_reference", "owned_slots"} {
			b.Run(fmt.Sprintf("members_%d/%s", members, mode), func(b *testing.B) {
				decode := func() ([]chain.AccountHeader, error) {
					var got []chain.AccountHeader
					rows := bundleRows[chain.AccountHeader]{target: &got, field: "flat.sorted_headers", limit: members}
					var target json.Unmarshaler = &rows
					if mode == "allocating_reference" {
						old := allocatingBundleRowsReference[chain.AccountHeader](rows)
						target = &old
					}
					err := json.Unmarshal(raw, target)
					return got, err
				}
				got, err := decode()
				if err != nil || !reflect.DeepEqual(got, want) {
					b.Fatal("benchmark's complete row projection differs", err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				b.ResetTimer()
				for range b.N {
					got, err := decode()
					if err != nil || len(got) != members || got[0] != want[0] || got[members/2] != want[members/2] || got[members-1] != want[members-1] {
						b.Fatal("benchmark decode or selected rows differ", err)
					}
				}
			})
		}
	}
}
