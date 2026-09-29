package fetch

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestRPCAccountEnvelopeRefusesBeforeHashAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*rpcAccountBlock, *chain.AccountBlock)
		want error
	}{
		{"future version", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.Version, b.Version = 2, 2 }, chain.ErrUnsupportedAccountBlockVersion},
		{"missing chain", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.ChainIdentifier, b.ChainIdentifier = 0, 0 }, chain.ErrInvalidAccountBlockEnvelope},
		{"zero height", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.Height, b.Height = 0, 0 }, chain.ErrInvalidAccountBlockEnvelope},
		{"missing parent", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.Height, b.Height = 2, 2 }, chain.ErrInvalidAccountBlockEnvelope},
		{"first block parent", func(w *rpcAccountBlock, b *chain.AccountBlock) {
			b.PreviousHash[0] = 1
			w.PreviousHash = hashHex(b.PreviousHash)
		}, chain.ErrInvalidAccountBlockEnvelope},
		{"unsupported type", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.BlockType, b.BlockType = 99, 99 }, chain.ErrUnsupportedAccountBlockType},
		{"genesis type", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.BlockType, b.BlockType = 1, 1 }, chain.ErrUnsupportedAccountBlockType},
		{"contract type on user", func(w *rpcAccountBlock, b *chain.AccountBlock) { w.BlockType, b.BlockType = 4, 4 }, chain.ErrInvalidAccountBlockEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := queryAccountBlock(t, 1, zeroQueryAddress)
			b, err := convertAndVerifyAccountBlock(wire)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&wire, &b)
			wire.Hash = hashHex(b.ComputeHash())
			if _, err := convertAndVerifyAccountBlock(wire); !errors.Is(err, tc.want) {
				t.Fatalf("hash-consistent invalid envelope survived: %v", err)
			}
		})
	}
	// Layout rejection precedes decoding fields using the v1 interpretation.
	if _, err := convertAndVerifyAccountBlock(rpcAccountBlock{Version: 2, Hash: "invalid"}); !errors.Is(err, chain.ErrUnsupportedAccountBlockVersion) {
		t.Fatalf("future version was decoded as v1: %v", err)
	}
}

func TestUnsupportedAccountVersionReturnsNoPartialBatchOrQuorumVote(t *testing.T) {
	good := []rpcAccountBlock{queryAccountBlock(t, 1, zeroQueryAddress), queryAccountBlock(t, 2, zeroQueryAddress)}
	bad := append([]rpcAccountBlock(nil), good...)
	bad[1].Version = 2
	server := func(blocks []rpcAccountBlock) *httptest.Server {
		return httptest.NewServer((&fakeRPC{responses: map[string]any{
			"ledger.getAccountBlocksByHeight": rpcAccountBlockList{List: blocks},
		}}).handler(t))
	}
	a, b := server(good), server(bad)
	defer a.Close()
	defer b.Close()
	if got, err := NewClient(b.URL).FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 2); !errors.Is(err, chain.ErrUnsupportedAccountBlockVersion) || got != nil {
		t.Fatalf("partial invalid-version batch returned: len=%d err=%v", len(got), err)
	}
	multi := NewMultiClient([]string{a.URL, b.URL})
	if got, err := multi.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 2); !errors.Is(err, ErrNotEnoughPeers) || got != nil {
		t.Fatalf("unsupported version counted toward quorum: len=%d err=%v", len(got), err)
	}
	multi.Quorum = 1
	if got, err := multi.FetchAccountBlocksByHeight(context.Background(), zeroQueryAddress, 1, 2); err != nil || len(got) != 2 {
		t.Fatalf("usable evidence lost with lower quorum: len=%d err=%v", len(got), err)
	}
}
