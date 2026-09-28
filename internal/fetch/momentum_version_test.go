package fetch

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestClient_UnsupportedMomentumVersion(t *testing.T) {
	for _, version := range []uint64{0, 3, ^uint64(0)} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			m := emptyContentMomentum(42)
			if version == 0 {
				delete(m, "version")
			} else {
				m["version"] = version
			}
			m["hash"] = recomputeAlternateHash(m)
			rpc := &fakeRPC{responses: map[string]any{"ledger.getFrontierMomentum": m}}
			srv := httptest.NewServer(rpc.handler(t))
			defer srv.Close()
			h, err := NewClient(srv.URL).FetchFrontier(context.Background())
			if !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
				t.Fatalf("fetch error = %v, want unsupported header version", err)
			}
			if !h.HeaderHash.IsZero() {
				t.Error("fetch returned a header from an unsupported layout")
			}
		})
	}
}

func TestClient_UnsupportedVersionReturnsNoPartialBatch(t *testing.T) {
	unsupported := emptyContentMomentum(43)
	unsupported["version"] = uint64(3)
	unsupported["hash"] = recomputeAlternateHash(unsupported)
	rpc := &fakeRPC{responses: map[string]any{
		"ledger.getMomentumsByHeight": map[string]any{
			"list": []any{emptyContentMomentum(42), unsupported},
		},
	}}
	srv := httptest.NewServer(rpc.handler(t))
	defer srv.Close()
	headers, err := NewClient(srv.URL).FetchByHeight(context.Background(), 42, 2)
	if !errors.Is(err, chain.ErrUnsupportedHeaderVersion) {
		t.Fatalf("fetch error = %v, want unsupported header version", err)
	}
	if len(headers) != 0 {
		t.Error("mixed-version batch returned partial evidence")
	}
}
