// SPDX-License-Identifier: MIT

package proof_test

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
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

type candidateBatchEntryVector struct {
	Name   string
	Packed string `json:"packed_hex"`
	Fields struct {
		ProtocolVersion     uint16
		FirstInputSeq       uint64
		LastInputSeq        uint64
		PreStateRoot        chain.Hash
		PostStateRoot       chain.Hash
		InputRoot           chain.Hash
		ReceiptRoot         chain.Hash
		EventRoot           chain.Hash
		OutboxRoot          chain.Hash
		DaHash              chain.Hash
		DaMode              uint8
		ExecutorPillarHex   string
		SubmittedAtHeight   uint64
		FinalizeAtHeight    uint64
		AssetFlowSummaryHex string
		ProofDataHex        string
		State               uint8
	}
}

func candidateBatchEntryPinned(t *testing.T, path string, size int64, want string) []byte {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close recorded BatchEntry input: %v", err)
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		t.Fatal("recorded BatchEntry input length or type changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, size+1))
	digest := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) != size || hex.EncodeToString(digest[:]) != want {
		t.Fatal("recorded BatchEntry input digest changed")
	}
	return raw
}

func candidateBatchEntryVectors(t *testing.T) []candidateBatchEntryVector {
	t.Helper()
	raw := candidateBatchEntryPinned(t, "../testdata/conformance/batch-entry-abi.json", 20290,
		"e6d88da0ef13e19c28990359d5e0e80cdfc8838ac51cce3b7e807fdb617b81f0")
	var recorded struct {
		Format    string
		Source    json.RawMessage
		Harness   struct{ Path, SHA256 string }
		Execution struct {
			Test                 string
			Platform             string
			Go                   string
			CGO                  bool   `json:"cgo_enabled"`
			RecordSHA256         string `json:"record_sha256"`
			GateSHA256           string `json:"gate_sha256"`
			Exit                 int    `json:"actual_exit"`
			Complete             bool
			Cases                int    `json:"original_ABI_cases_passed"`
			IndependentEncodings int    `json:"independent_python_encodings_matched"`
			LoadedModules        int    `json:"loaded_modules_verified"`
			FullModuleGraph      string `json:"full_module_graph_go_mod_verify"`
		}
		Scope map[string]bool
		Cases []candidateBatchEntryVector
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&recorded); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatal("trailing recorded BatchEntry input")
	}
	var source struct {
		Repository, Revision, Tree string
		Files                      map[string]json.RawMessage
	}
	if err := json.Unmarshal(recorded.Source, &source); err != nil {
		t.Fatal(err)
	}
	wantScope := map[string]bool{
		"synthetic": true, "original_node_ABI_executed": true, "node_chain_started": false,
		"network_execution": false, "profile_agreed": false, "state_value_acceptance": false,
		"settlement_or_finality_established": false,
	}
	e := recorded.Execution
	if recorded.Format != "zenon-candidate-batch-entry-ABI-facts/v1" || len(recorded.Cases) != 7 ||
		source.Repository != "digitalSloth/go-zenon" || source.Revision != "938fca3b7787da86827a5eb63371509b36e14761" ||
		source.Tree != "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4" || len(source.Files) != 4 ||
		!reflect.DeepEqual(recorded.Scope, wantScope) || e.Test != "TestSPVBatchEntryABIEncoding" ||
		e.Platform != "darwin/arm64" || e.Go != "go1.25.14" || e.CGO || e.Exit != 0 || !e.Complete ||
		e.Cases != 7 || e.IndependentEncodings != 7 || e.LoadedModules != 21 || e.FullModuleGraph != "NOT_ESTABLISHED" ||
		e.RecordSHA256 != "6e2a600c4ef659f3b5b310e7b41f5224417f46b12e6e9ca46699f821792d53c8" ||
		e.GateSHA256 != "7d5296b8a9a6a03f67a72ea6fc92d10ef89da4b95fcef7d0ee75b052dd7ef99f" {
		t.Fatal("source, execution and untrusted encoding scope must remain explicit")
	}
	if recorded.Harness.Path != "tools/gen-state-root-vectors/batch-entry-abi_test.go.txt" ||
		recorded.Harness.SHA256 != "29117d4800aa54f2ac752f638208fa58613fd56f2ccd024154949e6100de7afe" {
		t.Fatal("original-node ABI capture harness identity changed")
	}
	candidateBatchEntryPinned(t, "../../"+recorded.Harness.Path, 4027, recorded.Harness.SHA256)
	return recorded.Cases
}

func candidateBatchEntryHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func candidateBatchEntryLimits() proof.CandidateBatchEntryLimits {
	return proof.CandidateBatchEntryLimits{
		MaxValueBytes: 4096, MaxExecutorPillarBytes: 256, MaxAssetFlowSummaryBytes: 1024,
		MaxProofDataBytes: 1024, MaxDynamicBytes: 2048, StringRule: proof.CandidateBatchEntryOpaqueString,
	}
}

func candidateBatchEntrySample(t *testing.T) []byte {
	t.Helper()
	return candidateBatchEntryHex(t, candidateBatchEntryVectors(t)[1].Packed)
}

func candidateBatchEntryRefusal(t *testing.T, raw []byte, limits proof.CandidateBatchEntryLimits, want error) {
	t.Helper()
	value, err := proof.DecodeCandidateBatchEntry(raw, limits)
	if !errors.Is(err, want) || !reflect.DeepEqual(value, proof.CandidateBatchEntry{}) {
		t.Fatalf("expected %v with no partial value; got %v", want, err)
	}
}

func candidateBatchEntrySetWord(raw []byte, index int, value uint64) {
	clear(raw[index*32 : (index+1)*32])
	binary.BigEndian.PutUint64(raw[index*32+24:(index+1)*32], value)
}

func TestCandidateBatchEntryRecordedNodeValues(t *testing.T) {
	for _, vector := range candidateBatchEntryVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			f := vector.Fields
			want := proof.CandidateBatchEntry{
				ProtocolVersion: f.ProtocolVersion, FirstInputSeq: f.FirstInputSeq, LastInputSeq: f.LastInputSeq,
				PreStateRoot: f.PreStateRoot, PostStateRoot: f.PostStateRoot, InputRoot: f.InputRoot,
				ReceiptRoot: f.ReceiptRoot, EventRoot: f.EventRoot, OutboxRoot: f.OutboxRoot, DaHash: f.DaHash,
				DaMode: f.DaMode, ExecutorPillar: string(candidateBatchEntryHex(t, f.ExecutorPillarHex)),
				SubmittedAtHeight: f.SubmittedAtHeight, FinalizeAtHeight: f.FinalizeAtHeight,
				State: f.State,
			}
			got, err := proof.DecodeCandidateBatchEntry(candidateBatchEntryHex(t, vector.Packed), candidateBatchEntryLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.AssetFlowSummary, candidateBatchEntryHex(t, f.AssetFlowSummaryHex)) ||
				!bytes.Equal(got.ProofData, candidateBatchEntryHex(t, f.ProofDataHex)) {
				t.Fatal("dynamic bytes differ from original node packing")
			}
			got.AssetFlowSummary, got.ProofData = nil, nil
			if !reflect.DeepEqual(got, want) {
				t.Fatal("one or more of the 17 typed fields differ from the node input")
			}
		})
	}
}

func TestCandidateBatchEntryRejectsNoncanonicalLayout(t *testing.T) {
	sample := candidateBatchEntrySample(t)
	changes := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"offset-into-head", func(b []byte) []byte { candidateBatchEntrySetWord(b, 11, 32); return b }},
		{"unaligned-offset", func(b []byte) []byte { candidateBatchEntrySetWord(b, 11, 545); return b }},
		{"leading-gap", func(b []byte) []byte { candidateBatchEntrySetWord(b, 11, 576); return b }},
		{"tail-alias", func(b []byte) []byte { copy(b[14*32:15*32], b[11*32:12*32]); return b }},
		{"reordered-tails", func(b []byte) []byte {
			copy(b[14*32:15*32], b[15*32:16*32])
			return b
		}},
		{"offset-over-uint64", func(b []byte) []byte { b[11*32] = 1; return b }},
		{"maximum-offset", func(b []byte) []byte { candidateBatchEntrySetWord(b, 15, ^uint64(0)); return b }},
		{"length-over-uint64", func(b []byte) []byte { b[544] = 1; return b }},
		{"trailing-zero-word", func(b []byte) []byte { return append(b, make([]byte, 32)...) }},
		{"trailing-byte", func(b []byte) []byte { return append(b, 1) }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			candidateBatchEntryRefusal(t, test.change(bytes.Clone(sample)), candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryEncoding)
		})
	}
	t.Run("every-truncated-prefix", func(t *testing.T) {
		for length := range sample {
			candidateBatchEntryRefusal(t, sample[:length], candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryEncoding)
		}
	})
	for _, index := range []int{11, 14, 15} {
		t.Run(fmt.Sprintf("padding-field-%d", index), func(t *testing.T) {
			changed := bytes.Clone(sample)
			offset := int(binary.BigEndian.Uint64(changed[index*32+24 : (index+1)*32]))
			length := int(binary.BigEndian.Uint64(changed[offset+24 : offset+32]))
			changed[offset+32+length] = 1
			candidateBatchEntryRefusal(t, changed, candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryEncoding)
		})
	}
	for _, field := range []struct{ index, width int }{{0, 2}, {1, 8}, {2, 8}, {10, 1}, {12, 8}, {13, 8}, {16, 1}} {
		t.Run(fmt.Sprintf("unsigned-width-field-%d", field.index), func(t *testing.T) {
			changed := bytes.Clone(sample)
			changed[field.index*32+31-field.width] = 1
			candidateBatchEntryRefusal(t, changed, candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryEncoding)
		})
	}
}

func TestCandidateBatchEntryExplicitBounds(t *testing.T) {
	raw := candidateBatchEntrySample(t)
	for _, field := range []struct {
		name string
		get  func(*proof.CandidateBatchEntryLimits) *int
	}{
		{"whole-value", func(l *proof.CandidateBatchEntryLimits) *int { return &l.MaxValueBytes }},
		{"pillar", func(l *proof.CandidateBatchEntryLimits) *int { return &l.MaxExecutorPillarBytes }},
		{"asset-flow", func(l *proof.CandidateBatchEntryLimits) *int { return &l.MaxAssetFlowSummaryBytes }},
		{"proof-data", func(l *proof.CandidateBatchEntryLimits) *int { return &l.MaxProofDataBytes }},
		{"cumulative", func(l *proof.CandidateBatchEntryLimits) *int { return &l.MaxDynamicBytes }},
	} {
		for _, bad := range []int{-1, 0, 4097} {
			t.Run(fmt.Sprintf("%s-%d", field.name, bad), func(t *testing.T) {
				limits := candidateBatchEntryLimits()
				*field.get(&limits) = bad
				candidateBatchEntryRefusal(t, raw, limits, proof.ErrCandidateBatchEntryBounds)
			})
		}
	}
	for _, mode := range []proof.CandidateBatchEntryStringRule{0, 3, 255} {
		limits := candidateBatchEntryLimits()
		limits.StringRule = mode
		candidateBatchEntryRefusal(t, raw, limits, proof.ErrCandidateBatchEntryBounds)
	}
	candidateBatchEntryRefusal(t, make([]byte, 4097), candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryBounds)
	limits := candidateBatchEntryLimits()
	limits.MaxDynamicBytes = 22 // 14-byte pillar plus two 4-byte payloads.
	if _, err := proof.DecodeCandidateBatchEntry(raw, limits); err != nil {
		t.Fatal("exact cumulative bound refused", err)
	}
	limits.MaxDynamicBytes--
	candidateBatchEntryRefusal(t, raw, limits, proof.ErrCandidateBatchEntryBounds)
	for _, change := range []func(*proof.CandidateBatchEntryLimits){
		func(l *proof.CandidateBatchEntryLimits) { l.MaxExecutorPillarBytes = 13 },
		func(l *proof.CandidateBatchEntryLimits) { l.MaxAssetFlowSummaryBytes = 3 },
		func(l *proof.CandidateBatchEntryLimits) { l.MaxProofDataBytes = 3 },
		func(l *proof.CandidateBatchEntryLimits) { l.MaxValueBytes = proof.CandidateBatchEntryMinBytes - 1 },
	} {
		limits := candidateBatchEntryLimits()
		change(&limits)
		candidateBatchEntryRefusal(t, raw, limits, proof.ErrCandidateBatchEntryBounds)
	}
	for _, index := range []int{11, 14, 15} {
		changed := bytes.Clone(raw)
		offset := int(binary.BigEndian.Uint64(changed[index*32+24 : (index+1)*32]))
		candidateBatchEntrySetWord(changed, offset/32, ^uint64(0))
		candidateBatchEntryRefusal(t, changed, candidateBatchEntryLimits(), proof.ErrCandidateBatchEntryBounds)
	}
}

func TestCandidateBatchEntryStringChoiceAndDetachedOutput(t *testing.T) {
	vectors := candidateBatchEntryVectors(t)
	invalidUTF8 := candidateBatchEntryHex(t, vectors[6].Packed)
	limits := candidateBatchEntryLimits()
	limits.StringRule = proof.CandidateBatchEntryUTF8String
	candidateBatchEntryRefusal(t, invalidUTF8, limits, proof.ErrCandidateBatchEntryEncoding)
	raw := candidateBatchEntrySample(t)
	decoded, err := proof.DecodeCandidateBatchEntry(raw, limits)
	if err != nil {
		t.Fatal(err)
	}
	savedPillar := decoded.ExecutorPillar
	savedAssets, savedProof := bytes.Clone(decoded.AssetFlowSummary), bytes.Clone(decoded.ProofData)
	clear(raw)
	if decoded.ExecutorPillar != savedPillar || !bytes.Equal(decoded.AssetFlowSummary, savedAssets) || !bytes.Equal(decoded.ProofData, savedProof) {
		t.Fatal("decoded dynamic values alias the input")
	}
	raw = candidateBatchEntrySample(t)
	other, err := proof.DecodeCandidateBatchEntry(raw, limits)
	if err != nil {
		t.Fatal(err)
	}
	other.AssetFlowSummary[0] ^= 1
	other.ProofData[0] ^= 1
	if !bytes.Equal(decoded.AssetFlowSummary, savedAssets) || !bytes.Equal(decoded.ProofData, savedProof) {
		t.Fatal("separate candidate outputs share mutable bytes")
	}
}
