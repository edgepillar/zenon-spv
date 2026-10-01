package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func checkpointFixture(height uint64) chain.Header {
	h := chain.Header{Version: 1, ChainIdentifier: 1, Height: height, PreviousHash: chain.Hash{1},
		TimestampUnix: 1700000000 + height, DataHash: sha3.Sum256(nil), ContentHash: sha3.Sum256(nil), ChangesHash: chain.Hash{2}}
	signCheckpoint(&h, 0)
	return h
}

func TestCheckpointDerivationValidLayouts(t *testing.T) {
	for _, version := range []uint64{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			header := checkpointFixture(42)
			header.Version = version
			if version == 2 {
				header.NextFusionPrice, header.NextWorkPrice = 1000, 1000
			}
			signCheckpoint(&header, 0)
			urls := make([]string, 3)
			for i := range urls {
				urls[i], _ = checkpointPeer(t, func(uint64) chain.Header { return header }, false)
			}
			if got, err := crossCheckAtHeight(context.Background(), urls, 42); err != nil || got != header.HeaderHash {
				t.Fatalf("valid layout refused: %v", err)
			}
		})
	}
}

func TestCheckpointCommandPublishesOnlyCompleteObservations(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-failure=%t", failure), func(t *testing.T) {
			urls := make([]string, 2)
			for i := range urls {
				urls[i], _ = checkpointPeer(t, func(height uint64) chain.Header {
					h := checkpointFixture(height)
					if failure && height == 43 {
						h.Signature[0] ^= 1
					}
					return h
				}, false)
			}
			var out, diagnostics bytes.Buffer
			err := runWithOutput([]string{"--peers", strings.Join(urls, ","), "--heights", "43,42"}, &out, &diagnostics)
			if failure {
				if err == nil || out.Len() != 0 {
					t.Fatal("later height failure published a partial checkpoint list")
				}
				return
			}
			if err != nil || diagnostics.Len() != 0 || strings.Contains(out.String(), "PRIVATE") {
				t.Fatalf("successful derivation failed or disclosed private data: %v", err)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), "checkpoints.go", "package verify\n"+out.String(), 0); err != nil {
				t.Fatalf("stdout is not a standalone Go declaration: %v", err)
			}
			for _, height := range []uint64{42, 43} {
				row := fmt.Sprintf("{Height: %d, HeaderHash: mustHash(%q)}", height, fmt.Sprintf("%x", checkpointFixture(height).HeaderHash))
				if !strings.Contains(out.String(), row) {
					t.Fatal("published checkpoint differs from the observed signed header")
				}
			}
			if strings.Index(out.String(), "Height: 42") >= strings.Index(out.String(), "Height: 43") ||
				!strings.Contains(out.String(), "external provenance review required") {
				t.Fatal("output lost sorted heights or its external trust boundary")
			}
		})
	}
}

func TestCheckpointInvalidInputsBeforeRPC(t *testing.T) {
	url, calls := checkpointPeer(t, checkpointFixture, false)
	for _, args := range [][]string{
		{"--peers", url + "," + url, "--heights", "42"},
		{"--peers", url + "," + url + "/b", "--heights", "0,42"},
		{"--peers", url + "," + url + "/b", "--heights", "1,42"},
		{"--peers", url + "," + url + "/b", "--heights", "42,42"},
		{"--peers", url + "," + url + "/b", "--heights", "PRIVATE_HEIGHT"},
		{"--peers", url + "," + url + "/b", "--heights", "42", "--timeout", "0"},
		{"--peers", url + "," + url + "/b", "--heights", "42", "PRIVATE_POSITIONAL_ARGUMENT"},
	} {
		var out, diagnostics bytes.Buffer
		err := runWithOutput(args, &out, &diagnostics)
		if err == nil || calls.Load() != 0 || out.Len() != 0 || strings.Contains(err.Error()+diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid inputs reached RPC or disclosed private values")
		}
	}
	for _, urls := range [][]string{{}, {url}, {url, " "}, {url, " " + url + " "}} {
		if hash, err := crossCheckAtHeight(context.Background(), urls, 42); err == nil || hash != (chain.Hash{}) || calls.Load() != 0 {
			t.Fatal("invalid direct-call peer configuration reached RPC")
		}
	}
}

func TestCheckpointHelpHidesEnvironmentPeers(t *testing.T) {
	t.Setenv("ZENON_SPV_PEERS", "https://PRIVATE_USER:PRIVATE_PASSWORD@private.invalid/PRIVATE_PATH?token=PRIVATE_TOKEN")
	var out, diagnostics bytes.Buffer
	err := runWithOutput([]string{"--help"}, &out, &diagnostics)
	if !errors.Is(err, flag.ErrHelp) || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") || !strings.Contains(diagnostics.String(), "-peers") {
		t.Fatal("help leaked environment endpoints or lost supported options")
	}
}

type checkpointWriter func([]byte) (int, error)

func (f checkpointWriter) Write(p []byte) (int, error) { return f(p) }

func TestCheckpointOutputFailure(t *testing.T) {
	a, _ := checkpointPeer(t, checkpointFixture, false)
	b, _ := checkpointPeer(t, checkpointFixture, false)
	for _, short := range []bool{false, true} {
		cause := errors.New("PRIVATE_OUTPUT_ERROR")
		if short {
			cause = io.ErrShortWrite
		}
		writes := 0
		out := checkpointWriter(func(p []byte) (int, error) {
			writes++
			if short {
				return len(p) / 2, nil
			}
			return 0, cause
		})
		err := runWithOutput([]string{"--peers", a + "," + b, "--heights", "42"}, out, io.Discard)
		if !errors.Is(err, cause) || writes != 1 || strings.Contains(err.Error(), "PRIVATE") || !strings.Contains(err.Error(), "incomplete") {
			t.Fatal("output failure was ignored, retried, or disclosed private details")
		}
	}
}

func signCheckpoint(h *chain.Header, seedByte byte) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = seedByte
	key := ed25519.NewKeyFromSeed(seed)
	h.HeaderHash = h.ComputeHash()
	h.PublicKey = key.Public().(ed25519.PublicKey)
	h.Signature = ed25519.Sign(key, h.HeaderHash[:])
}

func checkpointPeer(t *testing.T, header func(uint64) chain.Header, unavailable bool) (string, *atomic.Int64) {
	t.Helper()
	calls := new(atomic.Int64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if unavailable {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var req struct {
			ID     json.RawMessage
			Method string
			Params []uint64
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "ledger.getMomentumsByHeight" || len(req.Params) != 2 || req.Params[1] != 1 {
			t.Error("unexpected checkpoint request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h := header(req.Params[0])
		wire := map[string]any{"version": h.Version, "chainIdentifier": h.ChainIdentifier, "height": h.Height,
			"hash": h.HeaderHash, "previousHash": h.PreviousHash, "timestamp": h.TimestampUnix, "changesHash": h.ChangesHash,
			"data": "", "content": []any{}, "publicKey": h.PublicKey, "signature": h.Signature,
			"nextFusionPrice": h.NextFusionPrice, "nextWorkPrice": h.NextWorkPrice}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": []any{wire}}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL + "/PRIVATE_RPC_PATH?token=PRIVATE_RPC_TOKEN", calls
}

func TestCheckpointDerivationRefusesInvalidObservations(t *testing.T) {
	for _, name := range []string{"invalid signatures", "missing signatures", "wrong chain", "one failed peer", "different signer", "duplicate endpoints"} {
		t.Run(name, func(t *testing.T) {
			urls := make([]string, 3)
			for i := range urls {
				urls[i], _ = checkpointPeer(t, func(height uint64) chain.Header {
					h := checkpointFixture(height)
					switch name {
					case "invalid signatures":
						h.Signature[0] ^= 1
					case "missing signatures":
						h.Signature = nil
					case "wrong chain":
						h.ChainIdentifier = 99
						signCheckpoint(&h, 0)
					case "different signer":
						if i == 2 {
							signCheckpoint(&h, 1)
						}
					}
					return h
				}, name == "one failed peer" && i == 2)
			}
			if name == "duplicate endpoints" {
				urls[2] = urls[1]
			}
			if hash, err := crossCheckAtHeight(context.Background(), urls, 42); err == nil || hash != (chain.Hash{}) {
				t.Fatal("invalid observation produced a usable mainnet checkpoint")
			}
		})
	}
}
