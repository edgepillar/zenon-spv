package conformance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCompiledFetchTargetConflictPreservesOutputs(t *testing.T) {
	binary := buildQueryCLIs(t, "fetch-bundle")["fetch-bundle"]
	for _, multi := range []bool{false, true} {
		for _, stdout := range []bool{false, true} {
			for _, proofOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("multi=%t/stdout=%t/proof-only=%t", multi, stdout, proofOnly), func(t *testing.T) {
					c, headers, _ := transitionFixture(t)
					rows := make([]json.RawMessage, len(c.Transition.Vectors))
					for i, vector := range c.Transition.Vectors {
						rows[i] = vector.Momentum
					}
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(rows[5], &fields); err != nil {
						t.Fatal(err)
					}
					signature := slices.Clone(headers[5].Signature)
					signature[0] ^= 1
					fields["signature"], _ = json.Marshal(signature)
					selected, _ := json.Marshal(fields)
					newPeer := func() string {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							var req struct {
								ID     json.RawMessage
								Method string
								Params []uint64
							}
							if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
								t.Error(err)
								return
							}
							var result any
							switch {
							case req.Method == "ledger.getFrontierMomentum":
								result = json.RawMessage(selected)
							case req.Method == "ledger.getMomentumsByHeight" && slices.Equal(req.Params, []uint64{2006, 1}):
								result = map[string]any{"list": []json.RawMessage{selected}}
							case req.Method == "ledger.getMomentumsByHeight" && slices.Equal(req.Params, []uint64{2001, 6}):
								result = map[string]any{"list": rows}
							default:
								t.Error("unexpected request after selected-target conflict")
								w.WriteHeader(http.StatusBadRequest)
								return
							}
							if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}); err != nil {
								t.Error(err)
							}
						}))
						t.Cleanup(server.Close)
						return strings.Replace(server.URL, "://", "://PRIVATE_USER:PRIVATE_PASSWORD@", 1) + "/PRIVATE_RPC_PATH?key=PRIVATE_TOKEN"
					}
					dir := t.TempDir()
					bundle := writeCLIJSON(t, dir, "PRIVATE_BUNDLE.json", map[string]bool{"existing": true})
					checkpoint := writeCLIJSON(t, dir, "PRIVATE_CHECKPOINT.json", map[string]bool{"existing": true})
					checkBundle, checkCheckpoint := protectCLIState(t, bundle), protectCLIState(t, checkpoint)
					output := bundle
					if stdout {
						output = "-"
					}
					args := []string{"--count", "5", "--out", output, "--safety-margin", "0"}
					if multi {
						args = append(args, "--peers", newPeer()+","+newPeer())
					} else {
						args = append(args, "--rpc", newPeer())
					}
					if proofOnly {
						// The peer rejects any account query: target binding must
						// fail before the collector requests segment evidence.
						args = append(args, "--proof-only", "--segments", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f:1")
					} else {
						args = append(args, "--checkpoint", checkpoint)
					}
					result := runQueryCLI(t, binary, args...)
					if result.code != 1 || len(result.stdout) != 0 || string(result.stderr) != "fetch-bundle: fetched range differs from the selected target\n" {
						t.Fatal("changed target emitted candidate output or lost its safe CLI failure")
					}
					checkBundle()
					checkCheckpoint()
				})
			}
		}
	}
}
