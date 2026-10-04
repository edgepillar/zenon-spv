package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const zeroQueryAddress = "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"

func TestMomentumQueriesBindRequestedRange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		start   uint64
		heights []uint64
		valid   bool
	}{
		{"matching", 10, []uint64{10, 11}, true},
		{"shifted", 10, []uint64{11, 12}, false},
		{"duplicate", 10, []uint64{10, 10}, false},
		{"gap", 10, []uint64{10, 12}, false},
		{"reversed", 10, []uint64{11, 10}, false},
		{"maximum height", math.MaxUint64, []uint64{math.MaxUint64}, true},
		{"maximum range end", math.MaxUint64 - 1, []uint64{math.MaxUint64 - 1, math.MaxUint64}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := make([]any, len(tc.heights))
			for i, h := range tc.heights {
				list[i] = emptyContentMomentum(h)
			}
			server := httptest.NewServer((&fakeRPC{responses: map[string]any{
				"ledger.getMomentumsByHeight": map[string]any{"list": list},
			}}).handler(t))
			defer server.Close()
			client := NewClient(server.URL)
			for _, detailed := range []bool{false, true} {
				var n int
				var err error
				if detailed {
					var headers []DetailedHeader
					headers, err = client.FetchByHeightDetailed(context.Background(), tc.start, uint64(len(list)))
					n = len(headers)
				} else {
					var headers []chain.Header
					headers, err = client.FetchByHeight(context.Background(), tc.start, uint64(len(list)))
					n = len(headers)
				}
				if tc.valid {
					if err != nil || n != len(list) {
						t.Fatalf("matching query failed: detailed=%v n=%d err=%v", detailed, n, err)
					}
				} else if !errors.Is(err, ErrQueryMismatch) || n != 0 {
					t.Fatalf("mismatched range returned evidence: detailed=%v n=%d err=%v", detailed, n, err)
				}
			}
		})
	}
}

// Reuse the repository's existing public fixture and recompute synthetic
// mutations. These tests check query binding, not signature or chain validity.
func queryAccountBlock(t *testing.T, height uint64, address string) rpcAccountBlock {
	t.Helper()
	raw, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result rpcAccountBlockList `json:"result"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	block := response.Result.List[0]
	parsed, err := convertAndVerifyAccountBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeZenonAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Height, parsed.Address = height, chain.Address(decoded)
	if height > 1 {
		parsed.PreviousHash = chain.Hash{1}
	}
	if parsed.Address.IsEmbeddedAddress() {
		parsed.BlockType = chain.BlockTypeContractSend
	}
	block.PreviousHash, block.BlockType = hashHex(parsed.PreviousHash), parsed.BlockType
	block.Height, block.Address, block.Hash = height, address, hashHex(parsed.ComputeHash())
	block.PublicKey, block.Signature = "", ""
	if _, err := convertAndVerifyAccountBlock(block); err != nil {
		t.Fatal(err)
	}
	return block
}

func TestAccountQueriesBindRequestedAddressAndRange(t *testing.T) {
	const otherAddress = "z1qxemdeddedxaccelerat0rxxxxxxxxxxp4tk22"
	for _, tc := range []struct {
		name      string
		heights   []uint64
		addresses []string
		request   string
		valid     bool
	}{
		{"matching", []uint64{10, 11}, []string{zeroQueryAddress, zeroQueryAddress}, zeroQueryAddress, true},
		{"uppercase query", []uint64{10, 11}, []string{zeroQueryAddress, zeroQueryAddress}, strings.ToUpper(zeroQueryAddress), true},
		{"wrong account", []uint64{10, 11}, []string{otherAddress, otherAddress}, zeroQueryAddress, false},
		{"mixed accounts", []uint64{10, 11}, []string{zeroQueryAddress, otherAddress}, zeroQueryAddress, false},
		{"shifted", []uint64{11, 12}, []string{zeroQueryAddress, zeroQueryAddress}, zeroQueryAddress, false},
		{"duplicate", []uint64{10, 10}, []string{zeroQueryAddress, zeroQueryAddress}, zeroQueryAddress, false},
		{"gap", []uint64{10, 12}, []string{zeroQueryAddress, zeroQueryAddress}, zeroQueryAddress, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := make([]rpcAccountBlock, len(tc.heights))
			for i, h := range tc.heights {
				list[i] = queryAccountBlock(t, h, tc.addresses[i])
			}
			server := httptest.NewServer((&fakeRPC{responses: map[string]any{
				"ledger.getAccountBlocksByHeight": rpcAccountBlockList{List: list},
			}}).handler(t))
			defer server.Close()
			blocks, err := NewClient(server.URL).FetchAccountBlocksByHeight(context.Background(), tc.request, 10, 2)
			if tc.valid {
				if err != nil || len(blocks) != 2 {
					t.Fatalf("matching query failed: n=%d err=%v", len(blocks), err)
				}
			} else if !errors.Is(err, ErrQueryMismatch) || len(blocks) != 0 {
				t.Fatalf("mismatched query returned evidence: n=%d err=%v", len(blocks), err)
			}
		})
	}
}

func TestFrontierCannotSubstituteRequestedHeight(t *testing.T) {
	server := httptest.NewServer((&fakeRPC{responses: map[string]any{
		"ledger.getFrontierMomentum":  emptyContentMomentum(100),
		"ledger.getMomentumsByHeight": map[string]any{"list": []any{emptyContentMomentum(1)}},
	}}).handler(t))
	defer server.Close()
	header, err := NewMultiClient([]string{server.URL}).FetchFrontierAtAgreedHeight(context.Background(), 6)
	if !errors.Is(err, ErrNotEnoughPeers) || header.Height != 0 {
		t.Fatalf("replayed frontier target returned evidence: height=%d err=%v", header.Height, err)
	}
}

type rangeQueryClient interface {
	FetchByHeight(context.Context, uint64, uint64) ([]chain.Header, error)
	FetchByHeightDetailed(context.Context, uint64, uint64) ([]DetailedHeader, error)
	FetchAccountBlocksByHeight(context.Context, string, uint64, uint64) ([]chain.AccountBlock, error)
}

func TestInvalidQueriesMakeNoRPCRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for name, client := range map[string]rangeQueryClient{
		"single": NewClient(server.URL), "multi": NewMultiClient([]string{server.URL}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, bounds := range [][2]uint64{{0, 1}, {1, 0}, {0, 0}, {math.MaxUint64, 2}, {2, math.MaxUint64}, {1, MaxRangeQueryCount + 1}} {
				h, err := client.FetchByHeight(context.Background(), bounds[0], bounds[1])
				if !errors.Is(err, ErrInvalidQuery) || len(h) != 0 {
					t.Fatalf("invalid header query: bounds=%v err=%v", bounds, err)
				}
				d, err := client.FetchByHeightDetailed(context.Background(), bounds[0], bounds[1])
				if !errors.Is(err, ErrInvalidQuery) || len(d) != 0 {
					t.Fatalf("invalid detailed query: bounds=%v err=%v", bounds, err)
				}
				b, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, bounds[0], bounds[1])
				if !errors.Is(err, ErrInvalidQuery) || len(b) != 0 {
					t.Fatalf("invalid account query: bounds=%v err=%v", bounds, err)
				}
			}
			for _, address := range []string{"", "private-invalid-address", "z1Qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"} {
				b, err := client.FetchAccountBlocksByHeight(context.Background(), address, 1, 1)
				if !errors.Is(err, ErrInvalidQuery) || len(b) != 0 {
					t.Fatalf("invalid account address: %v", err)
				}
				if address != "" && strings.Contains(err.Error(), address) {
					t.Fatal("invalid query echoed the address")
				}
			}
			if requests.Load() != 0 {
				t.Fatal("invalid local query reached a peer")
			}
		})
	}
}

func TestQuorumCountsOnlyQueryMatchingPeers(t *testing.T) {
	makePeer := func(height uint64, address string) string {
		server := httptest.NewServer((&fakeRPC{responses: map[string]any{
			"ledger.getMomentumsByHeight":     map[string]any{"list": []any{emptyContentMomentum(height)}},
			"ledger.getAccountBlocksByHeight": rpcAccountBlockList{List: []rpcAccountBlock{queryAccountBlock(t, 10, address)}},
		}}).handler(t))
		t.Cleanup(server.Close)
		return server.URL
	}
	wrong := makePeer(11, "z1qxemdeddedxaccelerat0rxxxxxxxxxxp4tk22")
	matching := makePeer(10, zeroQueryAddress)
	for _, q := range []int{1, 2} {
		client := NewMultiClient([]string{wrong, matching})
		client.Quorum = q
		check := func(n int, err error) {
			t.Helper()
			if q == 1 {
				if err != nil || n != 1 {
					t.Fatalf("matching quorum failed: n=%d err=%v", n, err)
				}
			} else if !errors.Is(err, ErrNotEnoughPeers) || n != 0 {
				t.Fatalf("mismatched peer counted toward quorum: n=%d err=%v", n, err)
			}
		}
		h, err := client.FetchByHeight(context.Background(), 10, 1)
		check(len(h), err)
		d, err := client.FetchByHeightDetailed(context.Background(), 10, 1)
		check(len(d), err)
		b, err := client.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 10, 1)
		check(len(b), err)
	}
}
