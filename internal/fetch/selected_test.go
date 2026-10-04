package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestSelectedMomentumHeightParsing(t *testing.T) {
	for _, value := range []string{"", "0", "84", "101", "85,85", "90,85", "85,", ",85", "85,,90", "085", "+85", " 85", "85 ", "1.0", "-1", "18446744073709551616", strings.Repeat("9", (32<<10)+1), strings.Repeat("85,", 1024) + "90"} {
		t.Run(value[:min(len(value), 32)], func(t *testing.T) {
			if heights, err := ParseMomentumHeights(value, 84, 100); heights != nil || err == nil {
				t.Fatal("invalid or unbounded evidence selection accepted")
			}
		})
	}
	for _, bounds := range [][2]uint64{{0, 100}, {100, 100}, {101, 100}} {
		if _, err := ParseMomentumHeights("100", bounds[0], bounds[1]); err == nil {
			t.Fatal("invalid selection window accepted")
		}
	}
	got, err := ParseMomentumHeights("85,90,100", 84, 100)
	if err != nil || !reflect.DeepEqual(got, []uint64{85, 90, 100}) {
		t.Fatal("valid explicit window refused or reordered")
	}
	var parts []string
	for h := uint64(2); h <= 1025; h++ {
		parts = append(parts, strconv.FormatUint(h, 10))
	}
	if got, err := ParseMomentumHeights(strings.Join(parts, ","), 1, 1025); err != nil || len(got) != MaxSelectedMomentumHeights {
		t.Fatal("maximum bounded selection refused")
	}
	if got, err := ParseMomentumHeights(strconv.FormatUint(math.MaxUint64, 10), math.MaxUint64-1, math.MaxUint64); err != nil || len(got) != 1 {
		t.Fatal("maximum height overflowed")
	}
}

func TestSelectedMomentumQueriesBindEveryHeight(t *testing.T) {
	for _, mode := range []string{"valid", "wrong height", "changed hash", "missing row", "extra row", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			server, requests := paginatedPeer(t, false, func(index int, rows []any) []any {
				if index == 1 {
					switch mode {
					case "wrong height":
						rows[0] = emptyContentMomentum(31)
					case "changed hash":
						rows[0].(map[string]any)["hash"] = hashHex(chain.Hash{})
					case "missing row":
						return nil
					case "extra row":
						return append(rows, rows[0])
					}
				}
				return rows
			})
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got, err := NewClient(server.URL).FetchSelectedDetailed(ctx, []uint64{10, 30, math.MaxUint64})
			if mode == "valid" {
				if err != nil || len(got) != 3 || !reflect.DeepEqual(requests(), []rangePage{{10, 1}, {30, 1}, {math.MaxUint64, 1}}) {
					t.Fatal("selected query fetched other heights or changed order")
				}
			} else {
				want := ErrQueryMismatch
				calls := 2
				if mode == "changed hash" {
					want = ErrHashMismatch
				}
				if mode == "cancelled" {
					want, calls = context.Canceled, 0
				}
				if got != nil || !errors.Is(err, want) || len(requests()) != calls {
					t.Fatal("failed selection exposed a prefix or retried")
				}
			}
		})
	}
	server, requests := paginatedPeer(t, false, nil)
	defer server.Close()
	for _, heights := range [][]uint64{nil, {0}, {10, 10}, {30, 10}, make([]uint64, MaxSelectedMomentumHeights+2)} {
		for _, multi := range []bool{false, true} {
			var got []DetailedHeader
			var err error
			if multi {
				got, err = NewMultiClient([]string{server.URL}).FetchSelectedDetailed(context.Background(), heights)
			} else {
				got, err = NewClient(server.URL).FetchSelectedDetailed(context.Background(), heights)
			}
			if got != nil || err == nil || len(requests()) != 0 {
				t.Fatal("invalid selection contacted an RPC")
			}
		}
	}
	if got, err := NewMultiClient([]string{server.URL, server.URL}).FetchSelectedDetailed(context.Background(), []uint64{10}); got != nil || !errors.Is(err, ErrInvalidPeerConfiguration) || len(requests()) != 0 {
		t.Fatal("invalid quorum selection contacted an RPC")
	}
}

func TestSelectedMomentumBudgetsAreShared(t *testing.T) {
	for _, mode := range []string{"bytes", "bytes exhausted", "evidence"} {
		t.Run(mode, func(t *testing.T) {
			server, requests := paginatedPeer(t, false, func(index int, rows []any) []any {
				if mode == "evidence" {
					row := rows[0].(map[string]any)
					content := []rpcAccountHdr{{Address: zeroQueryAddress, Height: 1, Hash: hashHex(chain.Hash{})}}
					row["content"] = content
					contentHash, err := contentHashOf(content)
					if err != nil {
						t.Error(err)
					}
					h := chain.Header{Version: 1, ChainIdentifier: 1, Height: row["height"].(uint64), TimestampUnix: row["timestamp"].(uint64), DataHash: sha3sum(nil), ContentHash: contentHash}
					row["hash"] = hashHex(h.ComputeHash())
					if index == 1 {
						row["content"] = []any{"PRIVATE_UNREACHED_MEMBER"}
					}
				}
				return rows
			})
			defer server.Close()
			budget, evidence := newRPCResponseBudget(), newRPCEvidenceDecoder()
			want := ErrResponseTooLarge
			calls := 2
			if mode != "evidence" {
				// A single valid response fits; the next exceeds what remains.
				raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": []any{emptyContentMomentum(10)}}})
				if err != nil {
					t.Fatal(err)
				}
				budget.remaining = int64(len(raw)) + 2 // JSON encoder newline, then one byte.
				if mode == "bytes exhausted" {
					budget.remaining--
					calls = 1
				}
			} else {
				want = ErrResponseTooComplex
				evidence.maxMembers, evidence.remaining = 1, 1
			}
			got, err := NewClient(server.URL).fetchSelectedDetailed(context.Background(), []uint64{10, 30, 50}, evidence, budget)
			if got != nil || !errors.Is(err, want) || len(requests()) != calls {
				t.Fatalf("shared selected-response limit failed: n=%d requests=%d err=%v", len(got), len(requests()), err)
			}
		})
	}
}

func TestSelectedMomentumQuorumRequiresWholeSelection(t *testing.T) {
	for _, mode := range []string{"agree", "partial", "disagree"} {
		t.Run(mode, func(t *testing.T) {
			first, aCalls := paginatedPeer(t, false, func(index int, rows []any) []any {
				if mode == "partial" && index == 1 {
					rows[0].(map[string]any)["hash"] = hashHex(chain.Hash{})
				}
				return rows
			})
			defer first.Close()
			second, bCalls := paginatedPeer(t, false, func(index int, rows []any) []any {
				if mode == "partial" && index == 0 {
					rows[0].(map[string]any)["hash"] = hashHex(chain.Hash{})
				}
				if mode == "disagree" && index == 1 {
					rows[0].(map[string]any)["publicKey"] = "AA=="
				}
				return rows
			})
			defer second.Close()
			multi := NewMultiClient([]string{first.URL, second.URL})
			multi.Quorum = 1
			got, err := multi.FetchSelectedDetailed(context.Background(), []uint64{10, 30})
			if mode == "agree" {
				if err != nil || len(got) != 2 || len(aCalls()) != 2 || len(bCalls()) != 2 {
					t.Fatal("whole selected peer agreement refused")
				}
			} else {
				want, bCount := ErrPeerDisagreement, 2
				if mode == "partial" {
					want, bCount = ErrNotEnoughPeers, 1
				}
				if got != nil || !errors.Is(err, want) || len(aCalls()) != 2 || len(bCalls()) != bCount {
					t.Fatal("partial or disagreeing selected peers supplied a quorum")
				}
			}
		})
	}
}
