// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

func experimentalBatchProfile() ExperimentalBatchEntryProfile {
	return ExperimentalBatchEntryProfile{Version: 1, Settlement: ExperimentalBatchEntrySettlementAddress(), DomainID: 1,
		RuntimeIdentity: chain.Hash{0x42, 0xab}, MaxProofBytes: proof.CandidateSMTMaxProofBytes, MaxSiblings: 256,
		Limits: ExperimentalBatchEntryLimits{MaxValueBytes: 4096, MaxExecutorPillarBytes: 256,
			MaxAssetFlowSummaryBytes: 1024, MaxProofDataBytes: 1024, MaxDynamicBytes: 2048,
			StringRule: proof.CandidateBatchEntryUTF8String},
		Source: "synthetic policy and recorded public signatures; not selected live runtime identity"}
}

func experimentalBatchInputs(t *testing.T) (ExperimentalV3State, ExperimentalBatchEntryProfile, ExperimentalBatchEntryContext, ExperimentalBatchEntryRequest) {
	t.Helper()
	f := experimentalV3Inputs(t)
	initial := experimentalV3New(t, f)
	result, state := initial.Extend(f.headers)
	if result.Outcome != OutcomeAccept {
		t.Fatal(result)
	}
	p := experimentalBatchProfile()
	c, err := ExperimentalBatchEntryContextFor(state, p)
	if err != nil {
		t.Fatal(err)
	}
	request := ExperimentalBatchEntryRequest{Context: c.Fingerprint, Height: 13, HeaderHash: f.headers[1].Header.HeaderHash,
		TipHeight: 14, TipHash: f.headers[2].Header.HeaderHash, BatchID: 1}
	return state, p, c, request
}

func experimentalBatchPacked(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/conformance/batch-entry-abi.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 20290 || hex.EncodeToString(digest[:]) != "e6d88da0ef13e19c28990359d5e0e80cdfc8838ac51cce3b7e807fdb617b81f0" {
		t.Fatal("recorded ABI corpus changed")
	}
	var data struct {
		Cases []struct {
			Name   string
			Packed string `json:"packed_hex"`
		}
	}
	if json.Unmarshal(raw, &data) != nil {
		t.Fatal("recorded ABI decode")
	}
	for _, row := range data.Cases {
		if row.Name == name {
			packed, err := hex.DecodeString(row.Packed)
			if err != nil {
				t.Fatal(err)
			}
			return packed
		}
	}
	t.Fatal("selected ABI case missing")
	return nil
}

// A mathematical single-leaf fixture only. It does not construct a signed
// header, replace an owned root, start a node or authorize a positive API query.
func experimentalBatchMathWitness(p ExperimentalBatchEntryProfile, batch uint64, value []byte) (chain.Hash, chain.Hash, []byte) {
	path := proof.CandidateSettlementBatchEntryPath(p.Settlement, p.DomainID, batch)
	leaf := chain.Hash(sha3.Sum256(append(append([]byte(nil), path[:]...), value...)))
	raw := make([]byte, 103+len(value))
	raw[0] = 1
	copy(raw[1:33], path[:])
	copy(raw[33:65], leaf[:])
	binary.BigEndian.PutUint32(raw[99:103], uint32(len(value)))
	copy(raw[103:], value)
	root := leaf
	for i := 0; i < 256; i++ {
		var pair [64]byte
		if path[31-i/8]&(1<<uint(i%8)) == 0 {
			copy(pair[:32], root[:])
		} else {
			copy(pair[32:], root[:])
		}
		root = chain.Hash(sha3.Sum256(pair[:]))
	}
	return root, path, raw
}

func TestExperimentalBatchEntryIndependentByteVectors(t *testing.T) {
	// Expected digests were calculated with Python's hashlib/struct over the
	// pinned public header and ABI fixtures, without importing or executing Go
	// or a node. The mathematical root does not occur in those signed headers.
	state, profile, context, request := experimentalBatchInputs(t)
	if hex.EncodeToString(context.Fingerprint[:]) != "7f1d56a0cc151b8b499cc6cddc614d7e5b95e0d7645681fdc4b1283d0af46391" {
		t.Fatal("typed context differs from the independent 302-byte preimage")
	}
	query, err := NewExperimentalBatchEntryQuery(state, profile, context.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := query.binding(request)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(binding.fingerprint[:]) != "bcf6c89ccd3b4766320f31c92afb528ba0e05468c0e6d272e99837414fea4f70" {
		t.Fatal("query differs from the independent 158-byte preimage")
	}
	value := experimentalBatchPacked(t, "typical")
	root, path, raw := experimentalBatchMathWitness(profile, request.BatchID, value)
	proofHash := sha3.Sum256(raw)
	if len(value) != 736 || len(raw) != 839 || path != binding.path || root == binding.root ||
		hex.EncodeToString(root[:]) != "055908c952e5d1813e7bb307b9e670a02ece7d6d73a431cf8e64a58bc1ef7993" ||
		hex.EncodeToString(proofHash[:]) != "f54e83870f77fd22469850047d5ed2350bc0461114152c29e273004b904bd19b" {
		t.Fatal("mathematical proof differs from the independent byte vector")
	}
}

func TestExperimentalBatchEntryProfileAndRequestStrictSchema(t *testing.T) {
	_, p, _, request := experimentalBatchInputs(t)
	for _, kind := range []string{"profile", "limits", "request"} {
		var raw []byte
		switch kind {
		case "profile":
			raw = experimentalV3JSON(t, p)
		case "limits":
			raw = experimentalV3JSON(t, p.Limits)
		case "request":
			raw = experimentalV3JSON(t, request)
		}
		for field := range experimentalV3Fields(t, raw) {
			for _, change := range []string{"missing", "null", "duplicate", "case-alias"} {
				t.Run(kind+"/"+field+"/"+change, func(t *testing.T) {
					fields := experimentalV3Fields(t, raw)
					switch change {
					case "missing":
						delete(fields, field)
					case "null":
						fields[field] = json.RawMessage("null")
					case "case-alias":
						fields[strings.ToUpper(field)] = fields[field]
						delete(fields, field)
					}
					bad := experimentalV3JSON(t, fields)
					if change == "duplicate" {
						bad = append(bad[:len(bad)-1], ',')
						bad = append(bad, experimentalV3JSON(t, field)...)
						bad = append(bad, ':')
						bad = append(bad, fields[field]...)
						bad = append(bad, '}')
					}
					switch kind {
					case "profile":
						before := p
						target := before
						if json.Unmarshal(bad, &target) == nil || target != before {
							t.Fatal("ambiguous profile changed a receiver")
						}
					case "limits":
						before := p.Limits
						target := before
						if json.Unmarshal(bad, &target) == nil || target != before {
							t.Fatal("ambiguous limits changed a receiver")
						}
					case "request":
						before := request
						target := before
						if json.Unmarshal(bad, &target) == nil || target != before {
							t.Fatal("ambiguous request changed a receiver")
						}
					}
				})
			}
		}
	}
	encoded := experimentalV3JSON(t, p)
	for _, field := range []string{"settlement", "runtime_identity"} {
		for _, kind := range []string{"uppercase", "prefix", "short"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				fields := experimentalV3Fields(t, encoded)
				var text string
				if json.Unmarshal(fields[field], &text) != nil {
					t.Fatal("fixture")
				}
				switch kind {
				case "uppercase":
					text = strings.ToUpper(text)
				case "prefix":
					text = "0x" + text
				case "short":
					text = text[:len(text)-1]
				}
				fields[field] = experimentalV3JSON(t, text)
				if _, err := DecodeExperimentalBatchEntryProfile(experimentalV3JSON(t, fields)); err == nil {
					t.Fatal("noncanonical identity accepted")
				}
			})
		}
	}
}

func TestExperimentalBatchEntryProfileBounds(t *testing.T) {
	for name, change := range map[string]func(*ExperimentalBatchEntryProfile){
		"version":         func(p *ExperimentalBatchEntryProfile) { p.Version = 2 },
		"contract":        func(p *ExperimentalBatchEntryProfile) { p.Settlement[0] ^= 1 },
		"runtime":         func(p *ExperimentalBatchEntryProfile) { p.RuntimeIdentity = chain.Hash{} },
		"proof-zero":      func(p *ExperimentalBatchEntryProfile) { p.MaxProofBytes = 0 },
		"proof-large":     func(p *ExperimentalBatchEntryProfile) { p.MaxProofBytes = proof.CandidateSMTMaxProofBytes + 1 },
		"siblings":        func(p *ExperimentalBatchEntryProfile) { p.MaxSiblings = 257 },
		"value-small":     func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxValueBytes = 639 },
		"value-large":     func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxValueBytes = 4097 },
		"executor-zero":   func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxExecutorPillarBytes = 0 },
		"asset-large":     func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxAssetFlowSummaryBytes = 4097 },
		"proof-data-zero": func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxProofDataBytes = 0 },
		"dynamic-zero":    func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxDynamicBytes = 0 },
		"string-rule":     func(p *ExperimentalBatchEntryProfile) { p.Limits.StringRule = 0 },
		"blank-source":    func(p *ExperimentalBatchEntryProfile) { p.Source = " " },
		"source-control":  func(p *ExperimentalBatchEntryProfile) { p.Source = "source\n" },
		"source-large":    func(p *ExperimentalBatchEntryProfile) { p.Source = strings.Repeat("x", 1025) },
		"source-utf8":     func(p *ExperimentalBatchEntryProfile) { p.Source = string([]byte{255}) },
	} {
		t.Run(name, func(t *testing.T) {
			p := experimentalBatchProfile()
			change(&p)
			if p.Validate() != ErrExperimentalBatchEntryProfile {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	p := experimentalBatchProfile()
	p.DomainID = 0
	p.MaxSiblings = 0
	if p.Validate() != nil {
		t.Fatal("explicit zero domain/sibling ceiling was treated as disabled")
	}
	for _, kind := range []string{"profile", "request"} {
		_, p, _, r := experimentalBatchInputs(t)
		raw := experimentalV3JSON(t, p)
		limit := MaxExperimentalBatchEntryProfileBytes
		if kind == "request" {
			raw = experimentalV3JSON(t, r)
			limit = 2048
		}
		padded := append(bytes.Repeat([]byte{' '}, limit-len(raw)), raw...)
		if kind == "profile" {
			if value, err := DecodeExperimentalBatchEntryProfile(padded); err != nil || value != p {
				t.Fatal("exact profile bound", err)
			}
			for _, bad := range [][]byte{append(padded, ' '), append(raw, []byte("{}")...), []byte("null"), []byte("[]")} {
				if value, err := DecodeExperimentalBatchEntryProfile(bad); err == nil || value != (ExperimentalBatchEntryProfile{}) {
					t.Fatal("invalid bounded profile accepted")
				}
			}
		} else {
			if value, err := DecodeExperimentalBatchEntryRequest(padded); err != nil || value != r {
				t.Fatal("exact request bound", err)
			}
			for _, bad := range [][]byte{append(padded, ' '), append(raw, []byte("{}")...), []byte("null"), []byte("[]")} {
				if value, err := DecodeExperimentalBatchEntryRequest(bad); err == nil || value != (ExperimentalBatchEntryRequest{}) {
					t.Fatal("invalid bounded request accepted")
				}
			}
		}
	}
}

func TestExperimentalBatchEntryContextPinsAndFrozenInputs(t *testing.T) {
	state, p, c, request := experimentalBatchInputs(t)
	if _, err := NewExperimentalBatchEntryQuery(state, p, chain.Hash{}); err != ErrExperimentalBatchEntryContext {
		t.Fatal("zero pin accepted")
	}
	if _, err := NewExperimentalBatchEntryQuery(state, p, chain.Hash{1}); err != ErrExperimentalBatchEntryContext {
		t.Fatal("wrong pin accepted")
	}
	q, err := NewExperimentalBatchEntryQuery(state, p, c.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	p.Source = "private-profile-marker"
	relabelled, err := ExperimentalBatchEntryContextFor(state, p)
	if err != nil || relabelled != c || bytes.Contains(experimentalV3JSON(t, c), []byte(p.Source)) {
		t.Fatal("metadata entered behavior identity", err)
	}
	p.RuntimeIdentity[0] ^= 1
	p.Limits.MaxValueBytes = 640
	c.Limits.MaxValueBytes = 640
	c.Fingerprint[0] ^= 1
	own, err := q.Context()
	if err != nil || own.Fingerprint != request.Context || own.Limits.MaxValueBytes != 4096 {
		t.Fatal("captured policy changed", err)
	}
	for _, change := range []func(*ExperimentalBatchEntryProfile){
		func(p *ExperimentalBatchEntryProfile) { p.DomainID++ },
		func(p *ExperimentalBatchEntryProfile) { p.RuntimeIdentity[0] ^= 1 },
		func(p *ExperimentalBatchEntryProfile) { p.MaxProofBytes-- },
		func(p *ExperimentalBatchEntryProfile) { p.MaxSiblings-- },
		func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxExecutorPillarBytes-- },
		func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxAssetFlowSummaryBytes-- },
		func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxProofDataBytes-- },
		func(p *ExperimentalBatchEntryProfile) { p.Limits.MaxDynamicBytes-- },
		func(p *ExperimentalBatchEntryProfile) { p.Limits.StringRule = proof.CandidateBatchEntryOpaqueString },
	} {
		changed := experimentalBatchProfile()
		change(&changed)
		context, err := ExperimentalBatchEntryContextFor(state, changed)
		if err != nil || context.Fingerprint == own.Fingerprint {
			t.Fatal("substantive policy omitted from pin", err)
		}
	}
	if _, err := json.Marshal(q); !errors.Is(err, ErrExperimentalBatchEntryOpaque) {
		t.Fatal("opaque query encoded", err)
	}
	before := q
	if json.Unmarshal([]byte("{}"), &q) == nil || q.data != before.data {
		t.Fatal("caller JSON replaced query")
	}
	var zero ExperimentalBatchEntryQuery
	if _, err := zero.Context(); err != ErrUninitializedState {
		t.Fatal(err)
	}
	f := experimentalV3Inputs(t)
	empty := experimentalV3New(t, f)
	context, err := ExperimentalBatchEntryContextFor(empty, experimentalBatchProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewExperimentalBatchEntryQuery(empty, experimentalBatchProfile(), context.Fingerprint); err != ErrExperimentalV3HeaderUnavailable {
		t.Fatal("empty state supplied typed authority", err)
	}
}

func requireExperimentalBatchNoResult(t *testing.T, result ExperimentalBatchEntryResult, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(result, ExperimentalBatchEntryResult{}) {
		t.Fatal("failed query returned partial consumer data", err)
	}
}
