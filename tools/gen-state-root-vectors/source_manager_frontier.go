//go:build candidate_source_manager_frontier

// SPDX-License-Identifier: GPL-3.0-only
// Exercise storage-only Add/Pop on one owned copy of the source-genesis ledger.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/inconshreveable/log15"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const (
	managerFormat = "source-manager-frontier-control/v1"
	ownerMarker   = "SOURCE_MANAGER_CONTROL"
	ownerContents = "zenon-source-manager-control/v1\n"
	managerNode   = "9c71ae82fc983e16f914ae085d4034030c8ebe3b"
	managerTree   = "d0f5dfb09e737a806cfc743bb6ba9ddd101ebcd6"
	managerBase   = "d0ffb31dece29d9d8459fbcf5cf542eb395712f5a1f906cd7f5409578f70a6fb"
)

var managerHashes = [...]string{
	"9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0",
	"fbc0141b8c93cd6e0e11247159c5da334822a6f4d734c8bd0e82dcb7fa16e5c6",
	"6b5066cef7935d4f780d3bd77880da41bfe7062d72b6631dae76ab16dd68875b",
	"8ffc5356f6c15cdca83760846c211669cae270f4a5c89c6b06054805a0b61245",
}

type managerCounts struct {
	Records       uint64 `json:"records"`
	WireBytes     uint64 `json:"wire_bytes"`
	SHA256        string `json:"sha256"`
	TypedBalances uint64 `json:"typed_balance_records"`
	EmptyBalances uint64 `json:"typed_balance_present_empty"`
	ZeroBalances  uint64 `json:"typed_balance_raw_zero32"`
	tombstones    uint64
}

type managerCommit struct {
	before, after types.HashHeight
	name          string
}

func (c managerCommit) Identifier() types.HashHeight { return c.after }
func (c managerCommit) Previous() types.HashHeight   { return c.before }
func (c managerCommit) Serialize() ([]byte, error) {
	// Deliberately not a network Momentum. Only the storage Manager is selected.
	return []byte("zenon-storage-control/v1:" + c.name), nil
}

type managerTransaction struct {
	commit managerCommit
	patch  db.Patch
}

func (t *managerTransaction) GetCommits() []db.Commit { return []db.Commit{t.commit} }
func (t *managerTransaction) StealChanges() db.Patch  { p := t.patch; t.patch = nil; return p }

func managerIdentifier(stage int) types.HashHeight {
	raw, _ := hex.DecodeString(managerHashes[stage])
	var hash types.Hash
	copy(hash[:], raw)
	return types.HashHeight{Hash: hash, Height: uint64(stage + 1)}
}

func managerKey() []byte {
	key := append([]byte{3}, bytes.Repeat([]byte{0xee}, 20)...)
	key = append(key, 3)
	return append(key, bytes.Repeat([]byte{0xdd}, 10)...)
}

func managerRoot(root string) bool {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	for p := root; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		return false
	}
	marker := filepath.Join(root, ownerMarker)
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(ownerContents)) {
		return false
	}
	raw, err := os.ReadFile(marker)
	if err != nil || string(raw) != ownerContents {
		return false
	}
	ledger := filepath.Join(root, "ledger")
	info, err = os.Lstat(ledger)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	files, err := os.ReadDir(ledger)
	if err != nil || len(files) < 3 || len(files) > 64 {
		return false
	}
	for _, file := range files {
		info, err := file.Info()
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func managerDigest(text string) bool {
	raw, err := hex.DecodeString(text)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == text
}

func managerFrontier(view db.DB, stage int) (managerCounts, error) {
	var result managerCounts
	if view == nil || db.GetFrontierIdentifier(view) != managerIdentifier(stage) {
		return result, errors.New("frontier identity")
	}
	value, err := view.Get(managerKey())
	present, hasErr := view.Has(managerKey())
	wantPresent := stage == 1 || stage == 2
	if hasErr != nil || present != wantPresent || (wantPresent && err != nil) ||
		(!wantPresent && !errors.Is(err, leveldb.ErrNotFound)) ||
		(stage == 1 && len(value) != 0) || (stage == 2 && !bytes.Equal(value, make([]byte, 32))) {
		return result, errors.New("selected key state")
	}
	iterator := view.NewIterator(nil)
	defer iterator.Release()
	stream := sha256.New()
	var previous []byte
	var batch leveldb.Batch
	var scanned uint64
	for iterator.Next() {
		key, value := iterator.Key(), iterator.Value()
		if len(key) > 1024 || len(value) > 1<<20 || scanned >= 2_000_000 ||
			(scanned != 0 && bytes.Compare(previous, key) >= 0) {
			return managerCounts{}, errors.New("record bound or ordering")
		}
		scanned++
		previous = append(previous[:0], key...)
		// The original enableDeleteIterator enumerates physical tombstones too:
		// Value is empty both for a tombstone and for a present-empty value.
		// Use the same immutable view's point semantics to distinguish them.
		if len(value) == 0 {
			point, getErr := view.Get(key)
			exists, hasErr := view.Has(key)
			if hasErr != nil {
				return managerCounts{}, errors.New("empty-row presence")
			}
			if errors.Is(getErr, leveldb.ErrNotFound) && !exists {
				result.tombstones++
				continue
			}
			if getErr != nil || !exists || len(point) != 0 {
				return managerCounts{}, errors.New("empty-row disagreement")
			}
		}
		// Original goleveldb encoder; independent of the ordinary export encoder.
		batch.Reset()
		batch.Put(key, value)
		wire := batch.Dump()
		if uint64(len(wire)) > (64<<20)-result.WireBytes {
			return managerCounts{}, errors.New("byte bound")
		}
		_, _ = stream.Write(wire)
		result.Records++
		result.WireBytes += uint64(len(wire))
		if len(key) == 32 && key[0] == 3 && key[21] == 3 {
			result.TypedBalances++
			if len(value) == 0 {
				result.EmptyBalances++
			}
			if len(value) == 32 && bytes.Equal(value, make([]byte, 32)) {
				result.ZeroBalances++
			}
		}
	}
	if iterator.Error() != nil || result.Records == 0 || db.GetFrontierIdentifier(view) != managerIdentifier(stage) {
		return managerCounts{}, errors.New("frontier incomplete")
	}
	result.SHA256 = hex.EncodeToString(stream.Sum(nil))
	return result, nil
}

func managerCapture(args []string, output, diagnostic io.Writer) (code int) {
	phase := "options"
	unknown := func() {
		_ = json.NewEncoder(diagnostic).Encode(map[string]any{
			"format": managerFormat, "status": "UNKNOWN", "phase": phase,
			"production_state_value_accepted": false,
		})
	}
	defer func() {
		if recover() != nil {
			unknown()
			code = 1
		}
	}()
	flags := flag.NewFlagSet("source-manager-frontier", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "existing physical owned control root with marker and ledger copy")
	stepText := flags.String("step", "", "fixed storage-only sequence step 0 through 6")
	inputSHA := flags.String("expect-input-sha256", "", "separately selected previous logical stream digest")
	outputSHA := flags.String("expect-output-sha256", "", "separately selected resulting logical stream digest")
	if err := flags.Parse(args); err != nil {
		unknown()
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 64
	}
	step, err := strconv.Atoi(*stepText)
	if err != nil || strconv.Itoa(step) != *stepText || step < 0 || step > 6 || flags.NArg() != 0 ||
		!managerDigest(*inputSHA) || !managerDigest(*outputSHA) || !managerRoot(*root) {
		unknown()
		return 64
	}
	beforeStages := [...]int{0, 0, 1, 2, 3, 2, 1}
	afterStages := [...]int{0, 1, 2, 3, 2, 1, 0}
	beforeStage, afterStage := beforeStages[step], afterStages[step]
	if (beforeStage == 0 && *inputSHA != managerBase) || (afterStage == 0 && *outputSHA != managerBase) {
		unknown()
		return 64
	}
	log15.Root().SetHandler(log15.DiscardHandler())
	ledger := filepath.Join(*root, "ledger")
	phase = "preflight-read-view"
	reader, err := db.NewReadOnlyLevelDBManager(ledger)
	if err != nil {
		unknown()
		return 1
	}
	before, readErr := managerFrontier(reader.Frontier(), beforeStage)
	closeErr := reader.Stop()
	if readErr != nil || closeErr != nil || before.SHA256 != *inputSHA {
		unknown()
		return 1
	}
	observed := before
	operation := "inspect"
	if step != 0 {
		phase = "storage-manager-mutation"
		writer := db.NewLevelDBManager(ledger)
		stopped := false
		defer func() {
			if !stopped {
				_ = writer.Stop()
			}
		}()
		// Recheck after acquiring the writable handle. No Chain or node is started.
		observed, err = managerFrontier(writer.Frontier(), beforeStage)
		if err != nil || observed != before {
			unknown()
			return 1
		}
		if step <= 3 {
			names := [...]string{"", "empty", "zero", "delete"}
			operation = names[step]
			patch := db.NewPatch()
			if step == 3 {
				patch.Delete(managerKey())
			} else if step == 1 {
				patch.Put(managerKey(), nil)
			} else {
				patch.Put(managerKey(), make([]byte, 32))
			}
			tx := &managerTransaction{commit: managerCommit{managerIdentifier(beforeStage), managerIdentifier(afterStage), operation}, patch: patch}
			err = writer.Add(tx)
		} else {
			operation = "pop"
			err = writer.Pop()
		}
		if err != nil {
			unknown()
			return 1
		}
		phase = "post-mutation-frontier"
		observed, err = managerFrontier(writer.Frontier(), afterStage)
		if err != nil || observed.SHA256 != *outputSHA {
			unknown()
			return 1
		}
		phase = "writer-Stop"
		stopped = true
		if writer.Stop() != nil || writer.Frontier() != nil {
			unknown()
			return 1
		}
	}
	phase = "fresh-read-only-reopen"
	reader, err = db.NewReadOnlyLevelDBManager(ledger)
	if err != nil {
		unknown()
		return 1
	}
	reopened, readErr := managerFrontier(reader.Frontier(), afterStage)
	closeErr = reader.Stop()
	if readErr != nil || closeErr != nil || reopened != observed || reopened.SHA256 != *outputSHA {
		unknown()
		return 1
	}
	phase = "receipt"
	if json.NewEncoder(output).Encode(map[string]any{
		"format": managerFormat, "status": "SOURCE_MANAGER_FRONTIER_CLOSED",
		"declared_node_revision": managerNode, "declared_node_tree": managerTree,
		"source_and_actual_exit_binding_requires_controller": true,
		"step": step, "operation": operation, "before_identifier": managerIdentifier(beforeStage), "after_identifier": managerIdentifier(afterStage),
		"before": before, "after": observed, "fresh_read_only_reopen_matched": true,
		"iterator_tombstones_omitted": map[string]uint64{"before": before.tombstones, "after": observed.tombstones},
		"iterators_released":          true, "manager_Stop_returned_nil": true,
		"runtime": map[string]string{"go": runtime.Version(), "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH},
		"scope": map[string]bool{"synthetic_storage_commits": true, "network_Momentum_validation_selected": false,
			"Chain_Init_selected": false, "Chain_Start_selected": false, "node_P2P_RPC_wallet_signing_broadcast_selected": false,
			"representative_R1_dataset": false, "accepted_header_binding": false, "production_state_value_accepted": false},
	}) != nil {
		unknown()
		return 1
	}
	return 0
}

func main() { os.Exit(managerCapture(os.Args[1:], os.Stdout, os.Stderr)) }
