package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func genesisFixture() chain.Header {
	h := chain.Header{Version: 1, ChainIdentifier: 1, Height: 1, TimestampUnix: 1700000000,
		DataHash: sha3.Sum256(nil), ContentHash: sha3.Sum256(nil), ChangesHash: chain.Hash{2}}
	h.HeaderHash = h.ComputeHash()
	return h
}

func genesisPeer(t *testing.T, header chain.Header, unavailable bool) (string, *atomic.Int64) {
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "ledger.getMomentumsByHeight" ||
			len(req.Params) != 2 || req.Params[0] != 1 || req.Params[1] != 1 {
			t.Error("unexpected genesis query")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire := map[string]any{"version": header.Version, "chainIdentifier": header.ChainIdentifier, "height": header.Height,
			"hash": header.HeaderHash, "previousHash": header.PreviousHash, "timestamp": header.TimestampUnix, "changesHash": header.ChangesHash,
			"data": "", "content": []any{}, "publicKey": "", "signature": "", "nextFusionPrice": header.NextFusionPrice, "nextWorkPrice": header.NextWorkPrice}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"list": []any{wire}}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL + "/PRIVATE_RPC_PATH?token=PRIVATE_RPC_TOKEN", calls
}

func TestGenesisRefusesUnpinnedOrIncompleteObservations(t *testing.T) {
	for _, name := range []string{"embedded pin mismatch", "explicit empty pin", "wrong chain", "wrong genesis layout", "nonzero previous hash", "one failed peer", "duplicate endpoints"} {
		t.Run(name, func(t *testing.T) {
			h := genesisFixture()
			switch name {
			case "wrong chain":
				h.ChainIdentifier = 99
			case "wrong genesis layout":
				h.Version, h.NextFusionPrice, h.NextWorkPrice = 2, 1000, 1000
			case "nonzero previous hash":
				h.PreviousHash[0] = 1
			}
			h.HeaderHash = h.ComputeHash()
			urls := make([]string, 3)
			for i := range urls {
				urls[i], _ = genesisPeer(t, h, name == "one failed peer" && i == 2)
			}
			if name == "duplicate endpoints" {
				urls[2] = urls[1]
			}
			args := []string{"--peers", strings.Join(urls, ",")}
			if name == "explicit empty pin" {
				args = append(args, "--expected", "")
			} else if name != "embedded pin mismatch" {
				args = append(args, "--expected", fmt.Sprintf("%x", h.HeaderHash))
			}
			var out, diagnostics bytes.Buffer
			err := runWithOutput(args, &out, &diagnostics)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error()+diagnostics.String(), "PRIVATE") {
				t.Fatal("invalid genesis observations reported success or disclosed private inputs")
			}
		})
	}
}

func TestGenesisExplicitPinAcceptsMatchingUnsignedObservation(t *testing.T) {
	h := genesisFixture()
	a, _ := genesisPeer(t, h, false)
	b, _ := genesisPeer(t, h, false)
	for _, prefix := range []string{"", "0x"} {
		var out, diagnostics bytes.Buffer
		err := runWithOutput([]string{"--peers", a + "," + b, "--expected", prefix + fmt.Sprintf("%x", h.HeaderHash)}, &out, &diagnostics)
		if err != nil || diagnostics.Len() != 0 || !strings.Contains(out.String(), "2/2 configured peers match the explicit expected hash") ||
			!strings.Contains(out.String(), fmt.Sprintf("Observed hash: %x", h.HeaderHash)) || strings.Contains(out.String(), "signed envelope") ||
			strings.Contains(out.String(), "PRIVATE") || !strings.Contains(out.String(), "does not establish operator independence") {
			t.Fatalf("explicit genesis pin lost its bounded meaning: %v", err)
		}
	}
}

func TestGenesisInvalidConfigurationBeforeRPC(t *testing.T) {
	url, calls := genesisPeer(t, genesisFixture(), false)
	base := []string{"--peers", url + "," + url + "/b"}
	for _, extra := range [][]string{
		{"--expected", ""}, {"--expected", strings.Repeat("00", 32)}, {"--expected", "PRIVATE_HASH"},
		{"--expected", strings.Repeat("z", 64)}, {"--timeout", "0"}, {"--timeout", "-1s"}, {"PRIVATE_POSITIONAL_ARGUMENT"},
		{"--peers", url + ", " + url + " "}, {"--peers", url},
	} {
		var out, diagnostics bytes.Buffer
		err := runWithOutput(append(append([]string{}, base...), extra...), &out, &diagnostics)
		if err == nil || calls.Load() != 0 || out.Len() != 0 || strings.Contains(err.Error()+diagnostics.String(), "PRIVATE") {
			t.Fatal("invalid genesis configuration reached RPC or disclosed private values")
		}
	}
}

func TestGenesisHelpHidesEnvironmentPeers(t *testing.T) {
	t.Setenv("ZENON_SPV_PEERS", "https://PRIVATE_USER:PRIVATE_PASSWORD@private.invalid/PRIVATE_PATH?token=PRIVATE_TOKEN")
	var out, diagnostics bytes.Buffer
	err := runWithOutput([]string{"--help"}, &out, &diagnostics)
	if !errors.Is(err, flag.ErrHelp) || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE") || !strings.Contains(diagnostics.String(), "-expected") {
		t.Fatal("genesis help leaked environment endpoints or lost expected-hash usage")
	}
}

type genesisWriter func([]byte) (int, error)

func (f genesisWriter) Write(p []byte) (int, error) { return f(p) }

func TestGenesisOutputFailure(t *testing.T) {
	h := genesisFixture()
	a, _ := genesisPeer(t, h, false)
	b, _ := genesisPeer(t, h, false)
	for _, short := range []bool{false, true} {
		cause := errors.New("PRIVATE_OUTPUT_ERROR")
		if short {
			cause = io.ErrShortWrite
		}
		writes := 0
		out := genesisWriter(func(p []byte) (int, error) {
			writes++
			if short {
				return len(p) / 2, nil
			}
			return 0, cause
		})
		err := runWithOutput([]string{"--peers", a + "," + b, "--expected", fmt.Sprintf("%x", h.HeaderHash)}, out, io.Discard)
		if !errors.Is(err, cause) || writes != 1 || strings.Contains(err.Error(), "PRIVATE") || !strings.Contains(err.Error(), "incomplete") {
			t.Fatal("report failure was ignored, retried, or disclosed private details")
		}
	}
}
