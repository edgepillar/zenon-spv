package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0x3639/zenon-spv/internal/verify"
)

func TestCompiledNodeDerivedCustomGenesis(t *testing.T) {
	c := loadHistoricalGenesisCorpus(t)
	mainnet, err := verify.MainnetGenesis()
	if err != nil {
		t.Fatal("cannot load the embedded mainnet anchor")
	}
	binary := buildQueryCLIs(t, "verify-mainnet-genesis")["verify-mainnet-genesis"]
	var calls atomic.Int64
	var failLast atomic.Bool
	var observation atomic.Value
	observation.Store(string(c.Vector.Momentum))
	urls := make([]string, 3)
	for i := range urls {
		peerIndex := i
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if peerIndex == 2 && failLast.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params []uint64        `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
				req.Method != "ledger.getMomentumsByHeight" || !slices.Equal(req.Params, []uint64{1, 1}) {
				t.Error("unexpected custom genesis request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"list": []json.RawMessage{json.RawMessage(observation.Load().(string))}},
			}); err != nil {
				t.Error("cannot write the local genesis response")
			}
		}))
		t.Cleanup(peer.Close)
		urls[i] = strings.Replace(peer.URL, "://", "://PRIVATE_RPC_USER:PRIVATE_RPC_PASSWORD@", 1) +
			"/PRIVATE_RPC_PATH?key=PRIVATE_RPC_TOKEN"
	}
	dir := t.TempDir()
	anchorPath := writeCLIJSON(t, dir, "PRIVATE_ANCHOR.json", c.Anchor)
	unchanged := protectCLIState(t, anchorPath)
	base := []string{"--peers", strings.Join(urls, ",")}
	pinned := append(append([]string{}, base...), "--genesis-config", anchorPath)
	hash := fmt.Sprintf("%x", c.Anchor.HeaderHash)
	run := func(t *testing.T, expectedCalls int64, args ...string) queryCLIResult {
		t.Helper()
		before := calls.Load()
		result := runQueryCLI(t, binary, args...)
		if calls.Load()-before != expectedCalls {
			t.Fatal("genesis command contacted an unexpected number of peers")
		}
		combined := append(append([]byte{}, result.stdout...), result.stderr...)
		for _, private := range []string{dir, anchorPath, "PRIVATE_RPC", "PRIVATE_ANCHOR", "PRIVATE_GENESIS_CONTENT"} {
			if bytes.Contains(combined, []byte(private)) {
				t.Fatal("genesis command disclosed private input or endpoint details")
			}
		}
		unchanged()
		return result
	}
	refused := func(t *testing.T, result queryCLIResult) {
		t.Helper()
		if result.code != 1 || len(result.stdout) != 0 || len(result.stderr) == 0 {
			t.Fatal("untrusted genesis input produced success or partial success output")
		}
	}
	t.Run("explicit_custom_anchor", func(t *testing.T) {
		result := run(t, 3, pinned...)
		if result.code != 0 || len(result.stderr) != 0 ||
			!bytes.Contains(result.stdout, []byte("3/3 configured peers match")) ||
			!bytes.Contains(result.stdout, []byte("explicit")) ||
			!bytes.Contains(result.stdout, []byte("chain_id=3 height=1 version=1")) ||
			!bytes.Contains(result.stdout, []byte("Observed hash: "+hash)) ||
			!bytes.Contains(result.stdout, []byte("Peer agreement does not establish operator independence, canonical history, or finality.")) {
			t.Fatal("custom anchor failed or overstated the genesis observation guarantee")
		}
	})
	t.Run("default_remains_mainnet", func(t *testing.T) {
		refused(t, run(t, 3, base...))
	})
	t.Run("explicit_expected_remains_mainnet", func(t *testing.T) {
		refused(t, run(t, 3, append(append([]string{}, base...), "--expected", hash)...))
	})
	t.Run("every_configured_peer_required", func(t *testing.T) {
		failLast.Store(true)
		defer failLast.Store(false)
		result := run(t, 3, pinned...)
		refused(t, result)
		if !bytes.Contains(result.stderr, []byte("peer[3]")) {
			t.Fatal("unavailable peer was not identified by its sanitized index")
		}
	})
	t.Run("wrong_anchor", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			anchor verify.GenesisTrustRoot
		}{
			{"chain_id", verify.GenesisTrustRoot{ChainID: 1, Height: 1, HeaderHash: c.Anchor.HeaderHash}},
			{"header_hash", verify.GenesisTrustRoot{ChainID: 3, Height: 1, HeaderHash: mainnet.HeaderHash}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := writeCLIJSON(t, dir, "PRIVATE_ANCHOR_"+tc.name+".json", tc.anchor)
				refused(t, run(t, 3, append(append([]string{}, base...), "--genesis-config", path)...))
			})
		}
	})
	t.Run("invalid_observation", func(t *testing.T) {
		// Only rejection cases alter node-produced wire fields. They never
		// manufacture a replacement hash or a successful SPV-generated envelope.
		for _, tc := range []struct {
			name  string
			field string
			value any
		}{
			{"chain_id", "chainIdentifier", uint64(1)},
			{"header_hash", "hash", strings.Repeat("1", 64)},
			{"height", "height", uint64(2)},
			{"layout", "version", uint64(2)},
			{"previous_hash", "previousHash", strings.Repeat("1", 64)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var wire map[string]json.RawMessage
				if err := json.Unmarshal(c.Vector.Momentum, &wire); err != nil {
					t.Fatal("cannot decode the node-produced genesis observation")
				}
				wire[tc.field] = marshalCLIValue(t, tc.value)
				observation.Store(string(marshalCLIValue(t, wire)))
				defer observation.Store(string(c.Vector.Momentum))
				refused(t, run(t, 3, pinned...))
			})
		}
	})
	t.Run("invalid_config_before_rpc", func(t *testing.T) {
		valid := string(marshalCLIValue(t, c.Anchor))
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{"empty", ""},
			{"malformed", "{"},
			{"oversized", strings.Repeat(" ", verify.MaxGenesisConfigBytes+1)},
			{"missing_chain_id", `{"height":1,"header_hash":"` + hash + `"}`},
			{"missing_height", `{"chain_id":3,"header_hash":"` + hash + `"}`},
			{"missing_header_hash", `{"chain_id":3,"height":1}`},
			{"null_chain_id", `{"chain_id":null,"height":1,"header_hash":"` + hash + `"}`},
			{"null_height", `{"chain_id":3,"height":null,"header_hash":"` + hash + `"}`},
			{"null_header_hash", `{"chain_id":3,"height":1,"header_hash":null}`},
			{"duplicate_chain_id", `{"chain_id":1,"chain_id":3,"height":1,"header_hash":"` + hash + `"}`},
			{"duplicate_height", `{"chain_id":3,"height":2,"height":1,"header_hash":"` + hash + `"}`},
			{"duplicate_header_hash", `{"chain_id":3,"height":1,"header_hash":"` + hash + `","header_hash":"` + hash + `"}`},
			{"escaped_duplicate_field", `{"chain_id":3,"chain_\u0069d":3,"height":1,"header_hash":"` + hash + `"}`},
			{"differently_cased_field", `{"Chain_id":3,"height":1,"header_hash":"` + hash + `"}`},
			{"unknown_field", strings.TrimSuffix(valid, "}") + `,"PRIVATE_GENESIS_CONTENT":"PRIVATE_GENESIS_CONTENT"}`},
			{"second_json_value", valid + " {}"},
			{"zero_height", `{"chain_id":3,"height":0,"header_hash":"` + hash + `"}`},
			{"non_genesis_height", `{"chain_id":3,"height":2,"header_hash":"` + hash + `"}`},
			{"zero_header_hash", `{"chain_id":3,"height":1,"header_hash":"` + strings.Repeat("0", 64) + `"}`},
			{"malformed_header_hash", `{"chain_id":3,"height":1,"header_hash":"PRIVATE_GENESIS_CONTENT"}`},
			{"overflow_chain_id", `{"chain_id":18446744073709551616,"height":1,"header_hash":"` + hash + `"}`},
			{"fractional_height", `{"chain_id":3,"height":1.5,"header_hash":"` + hash + `"}`},
			{"string_chain_id", `{"chain_id":"3","height":1,"header_hash":"` + hash + `"}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(dir, "PRIVATE_ANCHOR_invalid_"+tc.name+".json")
				if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
					t.Fatal("cannot prepare the invalid anchor input")
				}
				refused(t, run(t, 0, append(append([]string{}, base...), "--genesis-config", path)...))
			})
		}
		for _, tc := range []struct {
			name string
			path string
		}{
			{"missing_file", filepath.Join(dir, "PRIVATE_ANCHOR_missing.json")},
			{"directory", dir},
			{"empty_option", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refused(t, run(t, 0, append(append([]string{}, base...), "--genesis-config", tc.path)...))
			})
		}
	})
	t.Run("conflicting_or_duplicate_flags_before_rpc", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			args []string
		}{
			{"expected_after_config", append(append([]string{}, pinned...), "--expected", hash)},
			{"config_after_expected", append(append([]string{}, base...), "--expected", hash, "--genesis-config", anchorPath)},
			{"duplicate_config", append(append([]string{}, pinned...), "-genesis-config="+anchorPath)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refused(t, run(t, 0, tc.args...))
			})
		}
	})
}
