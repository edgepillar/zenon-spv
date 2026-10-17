//go:build candidate_raw_kv_roundtrip_successor

// SPDX-License-Identifier: GPL-3.0-only
// Controlled raw NodeTree storage transport; no authenticated snapshot or chain.
package trie

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const rawKvSelectionSHA = "5052b65d63205d8bbe3fc14a22e72fcead69cce83710d75d2bec2f3701ce3b68"
const rawKvDumpLimit = 8 << 20

type rawKvIdentifier struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
}
type rawKvChange struct {
	Operation string `json:"operation"`
	Key       string `json:"key"`
	Value     string `json:"value"`
}
type rawKvHistory struct {
	Identifier rawKvIdentifier `json:"identifier"`
	Changes    []rawKvChange   `json:"changes"`
}
type rawKvSelection struct {
	FormatVersion uint64            `json:"format_version"`
	Kind          string            `json:"kind"`
	Policies      []string          `json:"policies"`
	InitialTip    uint64            `json:"initial_tip"`
	TailTip       uint64            `json:"tail_tip"`
	Rollback      rawKvIdentifier   `json:"rollback_identifier"`
	Fork          rawKvIdentifier   `json:"fork_identifier"`
	ForkHeight    uint64            `json:"fork_changes_reuse_height"`
	Keys          []string          `json:"keys"`
	ProofKeys     []string          `json:"proof_keys"`
	Queries       []rawKvIdentifier `json:"query_identifiers"`
	History       []rawKvHistory    `json:"history"`
	EmptyDeletes  bool              `json:"empty_Put_means_delete_in_selected_L1_fold"`
	BalanceAgreed bool              `json:"balance_value_encoding_agreed"`
}
type rawKvManifest struct {
	Records    uint64 `json:"records"`
	KeyBytes   uint64 `json:"key_bytes"`
	ValueBytes uint64 `json:"value_bytes"`
	SHA256     string `json:"sha256"`
}
type rawKvDumpSelection struct {
	Bytes   uint64 `json:"bytes"`
	Records uint64 `json:"records"`
	SHA256  string `json:"sha256"`
}
type rawKvQuery struct {
	Identifier rawKvIdentifier `json:"identifier"`
	Error      string          `json:"error"`
	ProofError string          `json:"proof_error"`
	Root       string          `json:"root"`
}
type rawKvProof struct {
	Identifier rawKvIdentifier `json:"identifier"`
	Key        string          `json:"key"`
	Value      string          `json:"value"`
	Present    bool            `json:"present"`
	Proof      string          `json:"proof"`
	Error      string          `json:"error"`
}
type rawKvSnapshot struct {
	Name     string             `json:"name"`
	Frontier rawKvIdentifier    `json:"frontier"`
	Manifest rawKvManifest      `json:"record_manifest"`
	Dump     rawKvDumpSelection `json:"dump_selection"`
	Queries  []rawKvQuery       `json:"root_queries"`
	Proofs   []rawKvProof       `json:"proofs"`
}

func rawKvMust(err error) {
	if err != nil {
		panic(err)
	}
}
func rawKvRequire(ok bool) {
	if !ok {
		panic("selected raw KV roundtrip contract refused")
	}
}
func rawKvSHA(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
func rawKvHex(text string, minimum, maximum int) []byte {
	raw, err := hex.DecodeString(text)
	rawKvMust(err)
	rawKvRequire(len(raw) >= minimum && len(raw) <= maximum && hex.EncodeToString(raw) == text)
	return raw
}
func (id rawKvIdentifier) node() types.HashHeight {
	var hash types.Hash
	copy(hash[:], rawKvHex(id.Hash, 32, 32))
	rawKvRequire(id.Height > 0 && id.Height <= 65)
	return types.HashHeight{Hash: hash, Height: id.Height}
}
func rawKvID(id types.HashHeight) rawKvIdentifier {
	return rawKvIdentifier{Hash: hex.EncodeToString(id.Hash[:]), Height: id.Height}
}
func rawKvError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoVersion):
		return "no-version"
	case errors.Is(err, ErrVersionIdentityMismatch):
		return "version-hash-mismatch"
	case errors.Is(err, ErrVersionIdentityMissing):
		return "version-hash-missing"
	case errors.Is(err, ErrCorrupt):
		return "corrupt"
	case errors.Is(err, ErrFormatMismatch):
		return "format-mismatch"
	default:
		return "unclassified"
	}
}
func rawKvNoLinks(path string) {
	for {
		info, err := os.Lstat(path)
		rawKvMust(err)
		rawKvRequire(info.Mode()&os.ModeSymlink == 0)
		parent := filepath.Dir(path)
		if parent == path {
			return
		}
		path = parent
	}
}
func rawKvInputs() (rawKvSelection, string) {
	path, err := filepath.Abs(os.Getenv("ZENON_RAW_KV_SELECTION"))
	rawKvMust(err)
	rawKvNoLinks(path)
	before, err := os.Lstat(path)
	rawKvMust(err)
	rawKvRequire(before.Mode().IsRegular() && before.Size() > 0 && before.Size() <= 1<<20)
	f, err := os.Open(path)
	rawKvMust(err)
	opened, err := f.Stat()
	rawKvMust(err)
	rawKvRequire(os.SameFile(before, opened))
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	rawKvMust(err)
	rawKvMust(f.Close())
	after, err := os.Lstat(path)
	rawKvMust(err)
	rawKvRequire(os.SameFile(before, after) && int64(len(raw)) == before.Size() &&
		after.Size() == before.Size() && after.Mode() == before.Mode() && after.ModTime() == before.ModTime())
	digest := rawKvSHA(raw)
	rawKvRequire(digest == rawKvSelectionSHA && digest == os.Getenv("ZENON_RAW_KV_SELECTION_SHA256"))
	var selected rawKvSelection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	rawKvMust(decoder.Decode(&selected))
	var extra any
	rawKvRequire(decoder.Decode(&extra) == io.EOF)
	rawKvRequire(selected.FormatVersion == 1 && selected.Kind == "selected-successor-raw-kv-roundtrip" &&
		selected.InitialTip == 64 && selected.TailTip == 65 && selected.ForkHeight == 61 &&
		selected.Rollback.Height == 60 && selected.Fork.Height == 61 &&
		selected.EmptyDeletes && !selected.BalanceAgreed && len(selected.History) == 65 &&
		len(selected.Keys) == 64 && len(selected.ProofKeys) == 9 && len(selected.Queries) == 130)
	policies, err := json.Marshal(selected.Policies)
	rawKvMust(err)
	rawKvRequire(string(policies) == "[\"archive\",\"retain-5\"]")
	for index, row := range selected.History {
		rawKvRequire(row.Identifier.Height == uint64(index+1) && len(row.Changes) <= 67)
		row.Identifier.node()
		for _, change := range row.Changes {
			rawKvRequire(change.Operation == "put" || change.Operation == "delete")
			rawKvHex(change.Key, 1, 128)
			rawKvHex(change.Value, 0, 1<<20)
			rawKvRequire(change.Operation != "delete" || change.Value == "")
		}
	}
	for _, key := range append(append([]string{}, selected.Keys...), selected.ProofKeys...) {
		rawKvHex(key, 1, 128)
	}
	for _, id := range selected.Queries {
		id.node()
	}
	return selected, digest
}
func rawKvOpen(path string, fresh bool) *leveldb.DB {
	rawKvNoLinks(filepath.Dir(path))
	_, err := os.Lstat(path)
	if fresh {
		rawKvRequire(os.IsNotExist(err))
	} else {
		rawKvMust(err)
		rawKvNoLinks(path)
	}
	handle, err := leveldb.OpenFile(path, &opt.Options{
		ErrorIfExist: fresh, ErrorIfMissing: !fresh,
		BlockCacheCapacity: 1 << 20, WriteBuffer: 1 << 20, OpenFilesCacheCapacity: 16,
	})
	rawKvMust(err)
	return handle
}
func rawKvWithTree(path string, fresh bool, action func(*NodeTree)) {
	handle := rawKvOpen(path, fresh)
	defer func() { rawKvMust(handle.Close()) }()
	tree, err := NewNodeTree(handle)
	rawKvMust(err)
	action(tree)
}
func rawKvApply(tree *NodeTree, row rawKvHistory, id rawKvIdentifier, policy string) {
	patch := db.NewPatch()
	for _, change := range row.Changes {
		key, value := rawKvHex(change.Key, 1, 128), rawKvHex(change.Value, 0, 1<<20)
		if change.Operation == "delete" {
			patch.Delete(key)
		} else {
			// Logical L1 values: do not apply the enableDelete DB wrapper.
			patch.Put(key, value)
		}
	}
	rawKvMust(tree.Update(patch))
	rawKvMust(tree.Commit(id.node()))
	if policy == "retain-5" && id.Height > 5 {
		rawKvMust(tree.Prune(id.Height - 5))
	}
}
func rawKvCapture(path, name string, selected rawKvSelection) (rawKvSnapshot, []byte) {
	handle := rawKvOpen(path, false)
	defer func() { rawKvMust(handle.Close()) }()
	tree, err := NewNodeTree(handle)
	rawKvMust(err)
	snapshot := rawKvSnapshot{Name: name, Frontier: rawKvID(tree.FrontierIdentifier()),
		Queries: []rawKvQuery{}, Proofs: []rawKvProof{}}
	patch := db.NewPatch()
	digest := sha256.New()
	var previous []byte
	func() {
		iter := handle.NewIterator(nil, nil)
		defer iter.Release()
		for iter.Next() {
			key, value := append([]byte(nil), iter.Key()...), append([]byte(nil), iter.Value()...)
			rawKvRequire(len(key) > 0 && len(key) <= 128 && len(value) <= 1<<20 &&
				snapshot.Manifest.Records < 32768 && (previous == nil || bytes.Compare(previous, key) < 0))
			previous = key
			snapshot.Manifest.Records++
			snapshot.Manifest.KeyBytes += uint64(len(key))
			snapshot.Manifest.ValueBytes += uint64(len(value))
			rawKvRequire(snapshot.Manifest.KeyBytes+snapshot.Manifest.ValueBytes <= rawKvDumpLimit)
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(key)))
			digest.Write(length[:])
			digest.Write(key)
			binary.BigEndian.PutUint64(length[:], uint64(len(value)))
			digest.Write(length[:])
			digest.Write(value)
			patch.Put(key, value)
		}
		rawKvMust(iter.Error())
	}()
	snapshot.Manifest.SHA256 = hex.EncodeToString(digest.Sum(nil))
	// Dump aliases Batch data. Own a fixed buffer through Load, Replay and Write.
	dump := append([]byte(nil), patch.Dump()...)
	rawKvRequire(len(dump) > 0 && len(dump) <= rawKvDumpLimit)
	snapshot.Dump = rawKvDumpSelection{Bytes: uint64(len(dump)), Records: snapshot.Manifest.Records, SHA256: rawKvSHA(dump)}
	for _, id := range selected.Queries {
		root, rootError := tree.Root(id.node())
		_, _, probeError := tree.Prove(id.node(), rawKvHex(selected.ProofKeys[0], 1, 128))
		snapshot.Queries = append(snapshot.Queries, rawKvQuery{Identifier: id,
			Error: rawKvError(rootError), ProofError: rawKvError(probeError), Root: hex.EncodeToString(root[:])})
		if rootError != nil {
			continue
		}
		for _, key := range selected.ProofKeys {
			value, proof, proofError := tree.Prove(id.node(), rawKvHex(key, 1, 128))
			row := rawKvProof{Identifier: id, Key: key, Value: hex.EncodeToString(value),
				Proof: hex.EncodeToString(proof), Error: rawKvError(proofError)}
			if proofError == nil {
				rawKvRequire(len(proof) >= 99 && len(proof) <= 16384 && proof[0] <= 1)
				row.Present = proof[0] == 1
			}
			snapshot.Proofs = append(snapshot.Proofs, row)
		}
	}
	rawKvRequire(snapshot.Dump.SHA256 == rawKvSHA(dump))
	return snapshot, dump
}
func rawKvRestore(path string, dump []byte) map[string]any {
	before := rawKvSHA(dump)
	patch, err := db.NewPatchFromDump(dump)
	// Load can leave a partial index after an error: never Replay on that path.
	rawKvMust(err)
	batch := new(leveldb.Batch)
	rawKvMust(patch.Replay(batch))
	handle := rawKvOpen(path, true)
	func() {
		defer func() { rawKvMust(handle.Close()) }()
		rawKvMust(handle.Write(batch, &opt.WriteOptions{Sync: true}))
	}()
	after := rawKvSHA(dump)
	rawKvRequire(before == after)
	return map[string]any{"input_sha256_before": before, "input_sha256_after": after,
		"load_error": "", "replay_error": "", "write_error": "",
		"raw_batch_write_calls": 1, "write_sync": true,
		"crash_or_hardware_power_loss_qualified": false}
}
func TestCandidateRawKVRoundtripSuccessor(t *testing.T) {
	selected, selectionSHA := rawKvInputs()
	policy := os.Getenv("ZENON_RAW_KV_POLICY")
	rawKvRequire(policy == "archive" || policy == "retain-5")
	workspace, err := filepath.Abs(os.Getenv("ZENON_RAW_KV_WORKSPACE"))
	rawKvMust(err)
	rawKvNoLinks(filepath.Dir(workspace))
	_, err = os.Lstat(workspace)
	rawKvRequire(os.IsNotExist(err))
	rawKvMust(os.Mkdir(workspace, 0o700))
	seed, restored := filepath.Join(workspace, "seed"), filepath.Join(workspace, "restored")
	rawKvWithTree(seed, true, func(tree *NodeTree) {
		for _, row := range selected.History[:64] {
			rawKvApply(tree, row, row.Identifier, policy)
		}
	})
	snapshots := []rawKvSnapshot{}
	dumps := map[string]string{}
	capture := func(path, name string) []byte {
		snapshot, dump := rawKvCapture(path, name, selected)
		text := hex.EncodeToString(dump)
		if previous, exists := dumps[snapshot.Dump.SHA256]; exists {
			rawKvRequire(previous == text)
		} else {
			dumps[snapshot.Dump.SHA256] = text
		}
		snapshots = append(snapshots, snapshot)
		return dump
	}
	initial := capture(seed, "seed-64")
	replay := rawKvRestore(restored, initial)
	capture(restored, "restored-64")
	rawKvWithTree(restored, false, func(tree *NodeTree) {
		row := selected.History[64]
		rawKvApply(tree, row, row.Identifier, policy)
	})
	capture(restored, "tail-65")
	rawKvWithTree(restored, false, func(tree *NodeTree) { rawKvMust(tree.Truncate(selected.Rollback.node())) })
	capture(restored, "rollback-60")
	rawKvWithTree(restored, false, func(tree *NodeTree) {
		rawKvApply(tree, selected.History[selected.ForkHeight-1], selected.Fork, policy)
	})
	capture(restored, "fork-61")
	observed := map[string]any{
		"format_version": 1, "kind": "successor-raw-kv-roundtrip-observation",
		"policy": policy, "selection_sha256": selectionSHA, "snapshots": snapshots,
		"dump_objects": dumps, "replay": replay,
		"source": map[string]any{
			"node_revision":            "9c71ae82fc983e16f914ae085d4034030c8ebe3b",
			"original_node_tree":       "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6",
			"selected_runtime_tree":    "e60c875a06361f04d05301c0e4c61fd429995c5a",
			"experimental_disk_format": 3, "source_blobs": 467,
			"Go_version": runtime.Version(), "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH,
		},
		"scope": map[string]any{
			"component":               "common/trie with raw LevelDB and common/db Patch primitives",
			"chain_wrappers_executed": false, "full_node_started": false,
			"existing_database_adopted": false, "authenticated_snapshot_import": false,
			"accepted_header_binding": false, "balance_value_encoding_agreed": false,
			"representative_resources_qualified": false, "consumer_result": "REFUSED",
			"production_state_value_accepted": false,
		},
	}
	raw, err := json.Marshal(observed)
	rawKvMust(err)
	rawKvRequire(len(raw) <= 32<<20)
	fmt.Printf("RAW_KV_ROUNDTRIP_OBSERVATION=%s\n", raw)
}
