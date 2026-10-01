package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestBundleRefusesChangedTargetBeforePublication(t *testing.T) {
	for _, selection := range []string{"single frontier", "multi pinned", "multi frontier"} {
		for _, mutation := range []string{"hash", "key", "signature"} {
			for _, proofOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/proof-only=%t", selection, mutation, proofOnly), func(t *testing.T) {
					transform := func(method string, params []uint64, h chain.Header, row json.RawMessage) json.RawMessage {
						if h.Height != 1006 || method != "ledger.getFrontierMomentum" && (len(params) != 2 || params[1] != 1) {
							return row
						}
						var fields map[string]json.RawMessage
						if err := json.Unmarshal(row, &fields); err != nil {
							t.Error(err)
							return row
						}
						switch mutation {
						case "hash":
							h.TimestampUnix++
							h.HeaderHash = h.ComputeHash()
							fields["timestamp"], _ = json.Marshal(h.TimestampUnix)
							fields["hash"], _ = json.Marshal(h.HeaderHash)
						case "key":
							h.PublicKey = slices.Clone(h.PublicKey)
							h.PublicKey[0] ^= 1
							fields["publicKey"], _ = json.Marshal(h.PublicKey)
						case "signature":
							h.Signature = slices.Clone(h.Signature)
							h.Signature[0] ^= 1
							fields["signature"], _ = json.Marshal(h.Signature)
						}
						changed, _ := json.Marshal(fields)
						return changed
					}
					a, _ := bundleFixturePeer(t, transform)
					b, _ := bundleFixturePeer(t, transform)
					t.Setenv("ZENON_SPV_RPC", "")
					t.Setenv("ZENON_SPV_PEERS", "")
					dir := t.TempDir()
					bundle, checkpoint := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "checkpoint.json")
					before := []byte("existing private output\n")
					infos := make(map[string]os.FileInfo)
					for _, path := range []string{bundle, checkpoint} {
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
						info, err := os.Stat(path)
						if err != nil {
							t.Fatal(err)
						}
						infos[path] = info
					}
					args := []string{"--count", "5", "--out", bundle, "--safety-margin", "0"}
					if selection == "single frontier" {
						args = append(args, "--rpc", a)
					} else {
						args = append(args, "--peers", a+","+b)
						if selection == "multi pinned" {
							args = append(args, "--height", "1006")
						}
					}
					if proofOnly {
						args = append(args, "--proof-only", "--commitments", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f")
					} else {
						args = append(args, "--checkpoint", checkpoint)
					}
					err := run(args)
					if err == nil || !strings.Contains(err.Error(), "fetched range differs from the selected target") {
						t.Fatalf("changed selected target was not refused before output: %v", err)
					}
					for path, original := range infos {
						body, readErr := os.ReadFile(path)
						current, statErr := os.Stat(path)
						if readErr != nil || statErr != nil || !bytes.Equal(body, before) || !os.SameFile(original, current) ||
							current.Mode() != original.Mode() || !current.ModTime().Equal(original.ModTime()) {
							t.Fatal("changed target replaced or modified an output")
						}
					}
					assertNoOutputTemps(t, dir)
				})
			}
		}
	}
}
