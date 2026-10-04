package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

type rangePage struct{ start, count uint64 }

// These unsigned synthetic rows exercise transport/query binding only.
func paginatedPeer(t *testing.T, account bool, mutate func(int, []any) []any) (*httptest.Server, func() []rangePage) {
	t.Helper()
	var prototype rpcAccountBlock
	var parsed chain.AccountBlock
	if account {
		prototype = queryAccountBlock(t, 10, zeroQueryAddress)
		var err error
		parsed, err = convertAndVerifyAccountBlock(prototype)
		if err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var pages []rangePage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid range request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		index, method := 0, "ledger.getMomentumsByHeight"
		if account {
			index, method = 1, "ledger.getAccountBlocksByHeight"
			var address string
			if len(request.Params) != 3 || json.Unmarshal(request.Params[0], &address) != nil || address != zeroQueryAddress {
				t.Error("account pagination changed the selected address")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		var page rangePage
		if request.Method != method || len(request.Params) != index+2 ||
			json.Unmarshal(request.Params[index], &page.start) != nil || json.Unmarshal(request.Params[index+1], &page.count) != nil {
			t.Error("invalid height parameters")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		pages = append(pages, page)
		pageIndex := len(pages) - 1
		mu.Unlock()
		if page.count > 1024 {
			_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"count parameter is too big"}}`)
			return
		}
		rows := make([]any, page.count)
		for i := range rows {
			height := page.start + uint64(i)
			if account {
				block, body := prototype, parsed
				block.Height, body.Height = height, height
				block.Hash = hashHex(body.ComputeHash())
				rows[i] = block
			} else {
				rows[i] = emptyContentMomentum(height)
			}
		}
		if mutate != nil {
			rows = mutate(pageIndex, rows)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": rows}})
	}))
	return server, func() []rangePage {
		mu.Lock()
		defer mu.Unlock()
		return append([]rangePage(nil), pages...)
	}
}

func TestHeightRangesRespectNodePageLimit(t *testing.T) {
	for _, account := range []bool{false, true} {
		for _, bounds := range [][2]uint64{{10, 1}, {10, 1024}, {10, 1025}, {10, 2049}, {math.MaxUint64 - 1024, 1025}} {
			t.Run(fmt.Sprintf("account=%v/start=%d/count=%d", account, bounds[0], bounds[1]), func(t *testing.T) {
				server, requests := paginatedPeer(t, account, nil)
				defer server.Close()
				client := NewClient(server.URL)
				var heights []uint64
				if account {
					blocks, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, bounds[0], bounds[1])
					if err != nil {
						t.Fatal(err)
					}
					for _, b := range blocks {
						heights = append(heights, b.Height)
					}
				} else {
					blocks, err := client.FetchByHeight(context.Background(), bounds[0], bounds[1])
					if err != nil {
						t.Fatal(err)
					}
					for _, b := range blocks {
						heights = append(heights, b.Height)
					}
				}
				if uint64(len(heights)) != bounds[1] {
					t.Fatal("incomplete assembled range")
				}
				for i, height := range heights {
					if height != bounds[0]+uint64(i) {
						t.Fatal("page boundary lost query binding")
					}
				}
				var want []rangePage
				for offset := uint64(0); offset < bounds[1]; {
					size := min(bounds[1]-offset, 1024)
					want = append(want, rangePage{bounds[0] + offset, size})
					offset += size
				}
				if !reflect.DeepEqual(requests(), want) {
					t.Fatalf("unexpected requested pages: %v", requests())
				}
			})
		}
	}
}

func TestUnusableLaterPageDiscardsRangeAndStopsFetching(t *testing.T) {
	for _, account := range []bool{false, true} {
		for _, failure := range []string{"wrong height", "bad hash", "short page", "extra row"} {
			t.Run(fmt.Sprintf("account=%v/%s", account, failure), func(t *testing.T) {
				server, requests := paginatedPeer(t, account, func(page int, rows []any) []any {
					if page != 1 {
						return rows
					}
					switch failure {
					case "short page":
						return rows[:len(rows)-1]
					case "extra row":
						return append(rows, rows[0])
					}
					if account {
						b := rows[0].(rpcAccountBlock)
						if failure == "wrong height" {
							b.Height--
						} else {
							b.Hash = hashHex(chain.Hash{})
						}
						rows[0] = b
					} else {
						b := rows[0].(map[string]any)
						if failure == "wrong height" {
							b["height"] = b["height"].(uint64) - 1
						} else {
							b["hash"] = hashHex(chain.Hash{})
						}
					}
					return rows
				})
				defer server.Close()
				client := NewClient(server.URL)
				var err error
				var count int
				if account {
					rows, fetchErr := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 10, 2049)
					count, err = len(rows), fetchErr
				} else {
					rows, fetchErr := client.FetchByHeightDetailed(context.Background(), 10, 2049)
					count, err = len(rows), fetchErr
				}
				cause := ErrQueryMismatch
				if failure == "bad hash" {
					cause = ErrHashMismatch
				}
				if count != 0 || !errors.Is(err, cause) || len(requests()) != 2 {
					t.Fatalf("late failure returned rows, lost cause or fetched another page: n=%d err=%v pages=%v", count, err, requests())
				}
			})
		}
	}
}

func TestPaginatedRangeByteBudgetIsShared(t *testing.T) {
	for _, remaining := range []int64{1, 0} {
		t.Run(fmt.Sprint(remaining), func(t *testing.T) {
			// Charge the first complete response, leaving only zero or one byte
			// for the second page. Both pages individually fit the normal limit.
			server, requests := paginatedPeer(t, false, nil)
			defer server.Close()
			// Determine the deterministic first-page size without a preliminary RPC.
			rows := make([]any, 1024)
			for i := range rows {
				rows[i] = emptyContentMomentum(10 + uint64(i))
			}
			raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"list": rows}})
			if err != nil {
				t.Fatal(err)
			}
			budget := &rpcResponseBudget{remaining: int64(len(raw)) + 1 + remaining}
			evidence := newRPCEvidenceDecoder()
			got, err := fetchHeightRange(context.Background(), NewClient(server.URL), "ledger.getMomentumsByHeight", 10, 1025,
				func(h, n uint64) []any { return []any{h, n} }, evidence.momentum,
				func(m rpcMomentum, _ uint64) (uint64, error) { return m.Height, nil }, budget)
			if got != nil || !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("byte budget reset across pages: n=%d err=%v", len(got), err)
			}
			if len(requests()) != 1+int(remaining) {
				t.Fatal("exhausted budget made another request")
			}
		})
	}
}

func TestPaginatedRangeCancellationDiscardsRange(t *testing.T) {
	server, requests := paginatedPeer(t, false, nil)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evidence := newRPCEvidenceDecoder()
	got, err := fetchHeightRange(ctx, NewClient(server.URL), "ledger.getMomentumsByHeight", 10, 1025,
		func(h, n uint64) []any { return []any{h, n} }, evidence.momentum,
		func(m rpcMomentum, index uint64) (uint64, error) {
			if index == 1023 {
				cancel()
			}
			return m.Height, nil
		}, newRPCResponseBudget())
	if got != nil || !errors.Is(err, context.Canceled) || len(requests()) != 1 {
		t.Fatalf("cancelled range returned a prefix or fetched another page: n=%d err=%v", len(got), err)
	}
}

func TestMultiPeerCannotCombineDifferentPeersPartialPages(t *testing.T) {
	// One peer supplies only the first valid page; the other supplies no valid
	// first page. Page-wise quorum must not assemble them into a usable peer.
	first, firstRequests := paginatedPeer(t, false, func(page int, rows []any) []any {
		if page == 1 {
			rows[0].(map[string]any)["hash"] = hashHex(chain.Hash{})
		}
		return rows
	})
	defer first.Close()
	second, secondRequests := paginatedPeer(t, false, func(page int, rows []any) []any {
		if page == 0 {
			rows[0].(map[string]any)["hash"] = hashHex(chain.Hash{})
		}
		return rows
	})
	defer second.Close()
	multi := NewMultiClient([]string{first.URL, second.URL})
	multi.Quorum = 1
	got, err := multi.FetchByHeightDetailed(context.Background(), 10, 1025)
	if got != nil || !errors.Is(err, ErrNotEnoughPeers) || len(firstRequests()) != 2 || len(secondRequests()) != 1 {
		t.Fatalf("partial peer pages supplied quorum: n=%d err=%v", len(got), err)
	}
}

func TestPaginatedRangeEvidenceBudgetIsShared(t *testing.T) {
	server, requests := paginatedPeer(t, false, func(page int, rows []any) []any {
		if page == 0 {
			row := rows[len(rows)-1].(map[string]any)
			content := []rpcAccountHdr{{Address: zeroQueryAddress, Height: 1, Hash: hashHex(chain.Hash{})}}
			row["content"] = content
			contentHash, err := contentHashOf(content)
			if err != nil {
				t.Error(err)
			}
			h := chain.Header{Version: 1, ChainIdentifier: 1, Height: row["height"].(uint64), TimestampUnix: row["timestamp"].(uint64), DataHash: sha3sum(nil), ContentHash: contentHash}
			row["hash"] = hashHex(h.ComputeHash())
		} else {
			rows[0].(map[string]any)["content"] = []any{"PRIVATE_UNREACHED_MEMBER"}
		}
		return rows
	})
	defer server.Close()
	evidence := &rpcEvidenceDecoder{maxMembers: 1, remaining: 1}
	got, err := fetchHeightRange(context.Background(), NewClient(server.URL), "ledger.getMomentumsByHeight", 10, 1025,
		func(h, n uint64) []any { return []any{h, n} }, evidence.momentum,
		func(m rpcMomentum, _ uint64) (DetailedHeader, error) { return convertAndVerifyDetailed(m) }, newRPCResponseBudget())
	if got != nil || !errors.Is(err, ErrResponseTooComplex) || len(requests()) != 2 {
		t.Fatalf("nested evidence budget reset across pages: n=%d err=%v", len(got), err)
	}
}
