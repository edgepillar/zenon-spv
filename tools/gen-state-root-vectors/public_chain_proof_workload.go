//go:build candidate_public_chain_proof_workload && (darwin || linux)

// SPDX-License-Identifier: GPL-3.0-only
// Measure finite read-only requests against real public Chain managers.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/cache/storage"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const nodeRevision = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
const runtimeTree = "053c87e5bc4addd1bb70a467cb34facd439e66bc"

type selection struct {
	Schema   string `json:"schema"`
	Revision string `json:"node_revision"`
	Tree     string `json:"runtime_tree"`
	Patch    struct {
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	} `json:"genesis_patch"`
	Identifier struct {
		Hash   string `json:"hash"`
		Height uint64 `json:"height"`
	} `json:"genesis_identifier"`
	Keys []struct {
		Domain string `json:"domain"`
		Key    string `json:"raw_key"`
	} `json:"keys"`
	Requests       int    `json:"requests"`
	Workers        []int  `json:"workers"`
	AcceptedHeader bool   `json:"accepted_header_binding"`
	AcceptedValue  bool   `json:"production_state_value_accepted"`
	Consumer       string `json:"consumer_result"`
}

type observation struct {
	Key      string `json:"raw_key"`
	Root     string `json:"root"`
	Present  bool   `json:"present_in_projection"`
	Value    string `json:"value_hex"`
	ProofSHA string `json:"proof_sha256"`
	ProofLen int    `json:"proof_bytes"`
	RowSHA   string `json:"row_sha256"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, reason string) {
	if !ok {
		panic(reason)
	}
}
func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func unhex(text string, limit int) []byte {
	raw, err := hex.DecodeString(text)
	must(err)
	require(hex.EncodeToString(raw) == text && len(raw) <= limit, "canonical bounded hex")
	return raw
}
func framed(root types.Hash, key, value, proof []byte) [32]byte {
	h := sha256.New()
	for _, raw := range [][]byte{key, value, root[:], proof} {
		if raw == nil {
			_, err := h.Write([]byte{0})
			must(err)
		} else {
			_, err := h.Write([]byte{1})
			must(err)
		}
		must(binary.Write(h, binary.BigEndian, uint64(len(raw))))
		_, err := h.Write(raw)
		must(err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func usage() map[string]any {
	var u syscall.Rusage
	must(syscall.Getrusage(syscall.RUSAGE_SELF, &u))
	factor, unit := int64(1), "bytes"
	if runtime.GOOS == "linux" {
		factor, unit = 1024, "KiB"
	}
	return map[string]any{"native_peak_rss": u.Maxrss, "native_peak_rss_unit": unit,
		"SELF_lifetime_peak_rss_through_capture_bytes": u.Maxrss * factor,
		"SELF_user_cpu_ns":   u.Utime.Sec*1e9 + int64(u.Utime.Usec)*1000,
		"SELF_system_cpu_ns": u.Stime.Sec*1e9 + int64(u.Stime.Usec)*1000,
		"cpu_precision":      "native timeval microseconds converted to nanoseconds"}
}
func heap() map[string]uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]uint64{"heap_alloc_bytes": m.HeapAlloc, "total_alloc_bytes": m.TotalAlloc,
		"mallocs": m.Mallocs, "num_gc": uint64(m.NumGC)}
}

func main() {
	started := time.Now()
	root := flag.String("root", "", "new owned case directory, or the selected closed stores for reopen")
	input := flag.String("selection", "", "caller-pinned independent key selection")
	pin := flag.String("selection-sha256", "", "exact selection SHA-256")
	workers := flag.Int("workers", 0, "selected closed-loop request concurrency")
	reopen := flag.Bool("reopen", false, "reuse only this experiment's already closed stores")
	flag.Parse()
	require(flag.NArg() == 0 && filepath.IsAbs(*root) && filepath.Clean(*root) == *root && *input != "" && len(*pin) == 64, "selected invocation")
	for p := filepath.Clean(*root); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		must(err)
		require(info.IsDir() && info.Mode()&os.ModeSymlink == 0, "ordinary directory ancestors")
		if filepath.Dir(p) == p {
			break
		}
	}
	entries, err := os.ReadDir(*root)
	must(err)
	if !*reopen {
		require(len(entries) == 0, "fresh owned case root required")
	} else {
		require(len(entries) == 3, "exact closed ledger/cache/tree stores required")
		for _, e := range entries {
			require(e.IsDir() && (e.Name() == "ledger" || e.Name() == "cache" || e.Name() == "tree"), "selected store names")
		}
	}
	f, err := os.Open(*input)
	must(err)
	raw, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	must(err)
	must(f.Close())
	require(len(raw) <= 128<<10 && sum(raw) == *pin, "selection bytes and digest")
	var selected selection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	must(decoder.Decode(&selected))
	var trailing any
	require(decoder.Decode(&trailing) == io.EOF, "exact selection JSON")
	require(selected.Schema == "source-genesis-public-chain-proof-workload-v1" && selected.Revision == nodeRevision && selected.Tree == runtimeTree &&
		selected.Requests == 4096 && len(selected.Keys) == 128 && len(selected.Workers) == 3 && selected.Workers[0] == 1 && selected.Workers[1] == 4 && selected.Workers[2] == 16 &&
		!selected.AcceptedHeader && !selected.AcceptedValue && selected.Consumer == "REFUSED", "fixed workload and authority")
	require(*workers == 1 || *workers == 4 || *workers == 16, "selected worker count")
	keys := make([][]byte, len(selected.Keys))
	seen := map[string]bool{}
	for i, key := range selected.Keys {
		keys[i] = unhex(key.Key, 4096)
		require(len(keys[i]) > 0 && !seen[key.Key] && (key.Domain == "balance" || key.Domain == "contract_storage" || key.Domain == "absent_balance" || key.Domain == "excluded_ledger_key"), "distinct selected key domains")
		seen[key.Key] = true
	}
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	encoder := json.NewEncoder(output)
	emit := func(stage string, row map[string]any) {
		row["stage"] = stage
		row["workers"] = *workers
		row["reopen"] = *reopen
		must(encoder.Encode(row))
	}
	emit("selection", map[string]any{"selection_sha256": *pin, "requests": selected.Requests, "keys": len(keys),
		"go_version": runtime.Version(), "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOMAXPROCS": runtime.GOMAXPROCS(0),
		"public_Chain_Init_selected": true, "Chain_Start_selected": false, "full_node_or_network_started": false,
		"wallet_signing_or_broadcast": false, "accepted_header_binding": false, "consumer_result": "REFUSED"})
	g, err := genesis.MakeEmbeddedGenesisConfig()
	must(err)
	first := g.GetGenesisMomentum()
	dump := g.GetGenesisTransaction().Changes.Dump()
	require(first.Hash == first.ComputeHash() && first.Hash.String() == selected.Identifier.Hash && first.Height == selected.Identifier.Height &&
		first.Height == 1 && first.Version == 1 && first.StateRoot == types.ZeroHash && len(first.PublicKey) == 0 && len(first.Signature) == 0 &&
		len(dump) == selected.Patch.Bytes && sum(dump) == selected.Patch.SHA256, "source-derived unsigned genesis")
	emit("source-genesis", map[string]any{"identifier": first.Identifier(), "patch_sha256": sum(dump), "patch_bytes": len(dump), "header_state_root": first.StateRoot.String()})
	c := chain.NewChain(db.NewLevelDBManager(filepath.Join(*root, "ledger")), storage.NewCacheDBManager(*root), g, filepath.Join(*root, "tree"), false)
	closed := false
	defer func() {
		if !closed {
			_ = c.Stop()
		}
	}()
	initStarted := time.Now()
	must(c.Init())
	initElapsed := time.Since(initStarted).Nanoseconds()
	require(c.StateTreeReady() && c.GetFrontierMomentumStore().Identifier() == first.Identifier() && c.GetFrontierCacheStore().Identifier() == first.Identifier(), "real managers ready at full source identity")
	emit("initialized", map[string]any{"init_elapsed_ns": initElapsed, "heap_snapshot": heap(), "usage_through_capture": usage()})
	beforeHeap, beforeUsage := heap(), usage()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	gate := make(chan struct{})
	var group sync.WaitGroup
	samples := make([]observation, len(keys))
	digests := make([][32]byte, selected.Requests)
	durations := make([]int64, selected.Requests)
	for worker := 0; worker < *workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			<-gate
			for index := worker; index < selected.Requests; index += *workers {
				select {
				case <-ctx.Done():
					return
				default:
				}
				key := keys[index%len(keys)]
				began := time.Now()
				root, rootErr := c.StateRoot(first.Identifier())
				value, proof, proofErr := c.GetProof(first.Identifier(), key)
				durations[index] = time.Since(began).Nanoseconds()
				if rootErr != nil || proofErr != nil {
					select {
					case failed <- fmt.Errorf("public root/proof request failed: %v %v", rootErr, proofErr):
					default:
					}
					cancel()
					return
				}
				digests[index] = framed(root, key, value, proof)
				if index < len(keys) {
					samples[index] = observation{hex.EncodeToString(key), root.String(), value != nil, hex.EncodeToString(value), sum(proof), len(proof), hex.EncodeToString(digests[index][:])}
				}
			}
		}(worker)
	}
	phaseStarted := time.Now()
	close(gate)
	group.Wait()
	elapsed := time.Since(phaseStarted).Nanoseconds()
	select {
	case err := <-failed:
		panic(err)
	default:
	}
	aggregate := sha256.New()
	for _, digest := range digests {
		require(digest != [32]byte{}, "all requests completed")
		_, err := aggregate.Write(digest[:])
		must(err)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	emit("requests-completed", map[string]any{"root_calls": selected.Requests, "proof_calls": selected.Requests,
		"batch_elapsed_ns": elapsed, "api_pair_p50_ns": durations[(len(durations)-1)/2], "api_pair_p95_ns": durations[(len(durations)*95+99)/100-1], "api_pair_max_ns": durations[len(durations)-1],
		"ordered_request_rows_sha256": hex.EncodeToString(aggregate.Sum(nil)), "first_cycle_observations": samples,
		"heap_before": beforeHeap, "heap_after": heap(), "usage_before": beforeUsage, "usage_after": usage(),
		"request_model":                      "fixed closed-loop workers; API pair latency excludes time before the worker starts the request",
		"heap_snapshots_are_not_phase_peaks": true, "cache_state_qualified": false})
	require(c.GetFrontierMomentumStore().Identifier() == first.Identifier() && c.GetFrontierCacheStore().Identifier() == first.Identifier() && c.StateTreeReady(), "read-only requests preserve frontiers")
	stopStarted := time.Now()
	must(c.Stop())
	closed = true
	stopElapsed := time.Since(stopStarted).Nanoseconds()
	require(!c.StateTreeReady(), "stopped chain is unready")
	got, rootErr := c.StateRoot(first.Identifier())
	value, proof, proofErr := c.GetProof(first.Identifier(), keys[0])
	require(got == types.ZeroHash && rootErr != nil && value == nil && proof == nil && proofErr != nil, "closed manager requests refuse")
	emit("stopped", map[string]any{"stop_elapsed_ns": stopElapsed, "main_elapsed_through_report_ns": time.Since(started).Nanoseconds(),
		"closed_root_and_proof_refused": true, "usage_through_capture": usage(), "process_peak_RSS_through_exit_measured": false,
		"accepted_header_binding": false, "production_state_value_accepted": false, "consumer_result": "REFUSED"})
}
