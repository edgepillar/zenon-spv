// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

// These are mathematical fixture checks, not an accepted header/profile or an
// execution of the node/executor applier. The test oracle constructs full trees
// independently of the candidate decoder's bottom-up proof reconstruction.
type zenoVectorProof struct {
	Key, Serialized string
	Present         bool
	Value           *string
	Leaf            string   `json:"leaf_hash"`
	Bitmap          string   `json:"sibling_bitmap"`
	Siblings        []string `json:"siblings_nonzero_deepest_first"`
	Length          int      `json:"serialized_len"`
}

type zenoVectorOperation struct {
	Op, Key, Value string
	NewValue       string `json:"new_value"`
}

type zenoVectorStep struct {
	Key             string `json:"after_insert_key"`
	IncrementalRoot string `json:"incremental_root"`
	FullRoot        string `json:"full_recompute_root"`
	Equal           bool
}

type zenoDiffStep struct {
	Diff []struct {
		Key      string
		NewValue string `json:"new_value"`
	}
	State map[string]string `json:"resulting_state"`
	Root  string            `json:"incremental_root"`
}

type zenoVector struct {
	ID           string
	Initial      map[string]string `json:"initial_state"`
	Operations   []zenoVectorOperation
	State        map[string]string `json:"resulting_state"`
	Leaves       map[string]string `json:"expected_leaf_hashes"`
	Branches     map[string]string `json:"expected_branch_hashes"`
	Root         string            `json:"expected_root"`
	Inclusion    *zenoVectorProof  `json:"expected_inclusion_proof"`
	Absence      *zenoVectorProof  `json:"expected_non_inclusion_proof"`
	AbsentKey    string            `json:"absent_key"`
	Before       string            `json:"root_before"`
	After        string            `json:"root_after"`
	AbsentRoot   string            `json:"root_absent"`
	EmptyRoot    string            `json:"root_present_empty"`
	EmptyLeaf    string            `json:"leaf_hash_present_empty"`
	Distinct     bool              `json:"assert_distinct"`
	Steps        []zenoVectorStep
	AllEqual     bool           `json:"all_equal"`
	KeyOrder     []string       `json:"statediff_key_order"`
	PathResult   string         `json:"path_native_result"`
	HashedResult string         `json:"key_hashing_result"`
	AppliesTo    []string       `json:"applies_to"`
	DiffSteps    []zenoDiffStep `json:"diff_steps"`
}

func zenoVectors(t *testing.T) []zenoVector {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "conformance", "zeno-smt-v1-facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close Zeno facts: %v", err)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(f, 36220))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != 36219 || hex.EncodeToString(digest[:]) != "af407a0a0b6ffc83e67b346388a5d235508337f0c1e0d6d6e0716a0370dd97e9" {
		t.Fatal("selected normalized facts changed")
	}
	var file struct {
		Format string
		Source struct {
			Repository, Revision, Path, SHA256 string
			GitBlob                            string `json:"git_blob"`
			Bytes                              int
		}
		Scope struct {
			Math     bool `json:"mathematical_conformance"`
			Node     bool `json:"node_execution"`
			Header   bool `json:"accepted_header"`
			Profile  bool `json:"profile_agreed"`
			Accepted bool `json:"state_value_acceptance"`
		}
		Sentinels map[string]string `json:"sentinel_constants"`
		Vectors   []zenoVector
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if file.Format != "zenon-zeno-smt-conformance-facts/v1" ||
		file.Source.Repository != "Zeno-L2/zeno-docs" ||
		file.Source.Revision != "d74ba1fc4b01583af0daf33a2dedfc84ea2b9419" ||
		file.Source.Path != "artifacts/smt-v1-test-vectors.json" ||
		file.Source.GitBlob != "bfb42cb31b710fbb41f07d0d606b3d40dda99afa" ||
		file.Source.SHA256 != "d57aa52a683b2b768de16e6212058af9079125aca54feb2fdf007e9ba8c5568f" ||
		file.Source.Bytes != 41255 || !file.Scope.Math || file.Scope.Node ||
		file.Scope.Header || file.Scope.Profile || file.Scope.Accepted || len(file.Vectors) != 18 {
		t.Fatal("source identity or mathematical-only scope differs")
	}
	empty := sha3.Sum256(nil)
	want := map[string]string{
		"EMPTY_value_length_prefix_hex":         "ffffffff",
		"present_empty_value_length_prefix_hex": "00000000",
		"zero32_hex":                            strings.Repeat("0", 64),
		"sha3_256_empty_input_hex":              hex.EncodeToString(empty[:]),
	}
	if !reflect.DeepEqual(file.Sentinels, want) {
		t.Fatal("sentinel or SHA3/Keccak distinction differs")
	}
	return file.Vectors
}

type zenoOracleNode struct {
	hash        chain.Hash
	left, right *zenoOracleNode
}

type zenoOracleLeaf struct {
	path  chain.Hash
	value []byte
}

func zenoLeafHash(path chain.Hash, value []byte) chain.Hash {
	preimage := append(append([]byte(nil), path[:]...), value...)
	return chain.Hash(sha3.Sum256(preimage))
}

func zenoNodeHash(node *zenoOracleNode) chain.Hash {
	if node == nil {
		return chain.Hash{}
	}
	return node.hash
}

func zenoPathBit(path chain.Hash, depth int) byte {
	return path[depth/8] >> uint(7-depth%8) & 1
}

func zenoBuild(leaves []zenoOracleLeaf, depth int) *zenoOracleNode {
	if len(leaves) == 0 {
		return nil
	}
	if depth == 256 {
		return &zenoOracleNode{hash: zenoLeafHash(leaves[0].path, leaves[0].value)}
	}
	var sides [2][]zenoOracleLeaf
	for _, leaf := range leaves {
		bit := zenoPathBit(leaf.path, depth)
		sides[bit] = append(sides[bit], leaf)
	}
	left, right := zenoBuild(sides[0], depth+1), zenoBuild(sides[1], depth+1)
	lh, rh := zenoNodeHash(left), zenoNodeHash(right)
	var pair [64]byte
	copy(pair[:32], lh[:])
	copy(pair[32:], rh[:])
	return &zenoOracleNode{hash: chain.Hash(sha3.Sum256(pair[:])), left: left, right: right}
}

func zenoTree(t *testing.T, state map[string]string) *zenoOracleNode {
	t.Helper()
	if len(state) > 32 {
		t.Fatal("fixture oracle leaf bound exceeded")
	}
	leaves := make([]zenoOracleLeaf, 0, len(state))
	for key, value := range state {
		leaves = append(leaves, zenoOracleLeaf{candidateSMTHash(t, key), candidateSMTBytes(t, value)})
	}
	return zenoBuild(leaves, 0)
}

func zenoWantHash(t *testing.T, got chain.Hash, want string) {
	t.Helper()
	if want != "" && got != candidateSMTHash(t, want) {
		t.Fatalf("hash = %x, want %s", got, want)
	}
}

func zenoProof(t *testing.T, tree *zenoOracleNode, state map[string]string, path chain.Hash) []byte {
	t.Helper()
	var siblings [256]chain.Hash
	for depth, node := 0, tree; depth < 256; depth++ {
		if node == nil {
			break
		}
		if zenoPathBit(path, depth) == 0 {
			siblings[255-depth], node = zenoNodeHash(node.right), node.left
		} else {
			siblings[255-depth], node = zenoNodeHash(node.left), node.right
		}
	}
	raw := make([]byte, 99)
	copy(raw[1:33], path[:])
	var count uint16
	for index, sibling := range siblings {
		if sibling != (chain.Hash{}) {
			raw[65+index/8] |= 1 << uint(7-index%8)
			raw = append(raw, sibling[:]...)
			count++
		}
	}
	binary.BigEndian.PutUint16(raw[97:99], count)
	if encoded, present := state[hex.EncodeToString(path[:])]; present {
		value := candidateSMTBytes(t, encoded)
		raw[0] = 1
		leaf := zenoLeafHash(path, value)
		copy(raw[33:65], leaf[:])
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(value)))
		raw = append(raw, value...)
	}
	return raw
}

func zenoCheckNative(t *testing.T, root chain.Hash, path chain.Hash, state map[string]string, raw []byte) {
	t.Helper()
	encoded, present := state[hex.EncodeToString(path[:])]
	var result proof.CandidateSMTMatch
	var err error
	if present {
		result, err = proof.CheckCandidateSMTInclusion(root, path, candidateSMTBytes(t, encoded), raw, candidateSMTLimits())
	} else {
		result, err = proof.CheckCandidateSMTAbsence(root, path, raw, candidateSMTLimits())
	}
	if err != nil || result.Present != present || !result.Canonical ||
		!bytes.Equal(result.Value, candidateSMTBytes(t, encoded)) {
		t.Fatalf("native candidate differs from full-tree oracle: %+v, %v", result, err)
	}
}

func zenoCheckState(t *testing.T, state map[string]string, want string) chain.Hash {
	t.Helper()
	tree := zenoTree(t, state)
	root := zenoNodeHash(tree)
	zenoWantHash(t, root, want)
	for key := range state {
		path := candidateSMTHash(t, key)
		zenoCheckNative(t, root, path, state, zenoProof(t, tree, state, path))
	}
	// At most 32 fixture leaves: select an absent path without interpreting a
	// missing/excluded application witness as an account or balance absence.
	var absent chain.Hash
	for {
		if _, exists := state[hex.EncodeToString(absent[:])]; !exists {
			break
		}
		absent[0]++
	}
	zenoCheckNative(t, root, absent, state, zenoProof(t, tree, state, absent))
	return root
}

func zenoCopy(state map[string]string) map[string]string {
	result := make(map[string]string, len(state))
	for key, value := range state {
		result[key] = value
	}
	return result
}

func zenoApply(t *testing.T, state map[string]string, op zenoVectorOperation) {
	t.Helper()
	switch op.Op {
	case "insert", "update":
		state[op.Key] = op.Value
	case "delete":
		delete(state, op.Key)
	case "apply_statediff_entry":
		if op.NewValue == "EMPTY" {
			delete(state, op.Key)
		} else {
			state[op.Key] = op.NewValue
		}
	default:
		t.Fatalf("unknown fixture operation %q", op.Op)
	}
}

func zenoCheckBranches(t *testing.T, v zenoVector, tree *zenoOracleNode) {
	t.Helper()
	keys := make([]string, 0, len(v.State))
	for key := range v.State {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for label, expected := range v.Branches {
		if strings.HasPrefix(label, "leaf_hash") {
			key := keys[0]
			switch label {
			case "leaf_hash":
				if len(keys) != 1 {
					t.Fatal("ambiguous fixture leaf label")
				}
			case "leaf_hash_K_A":
				key = strings.Repeat("0", 64)
			case "leaf_hash_K_D":
				key = strings.Repeat("0", 63) + "1"
			default:
				t.Fatalf("unknown leaf label %q", label)
			}
			zenoWantHash(t, zenoLeafHash(candidateSMTHash(t, key), candidateSMTBytes(t, v.State[key])), expected)
			continue
		}
		depthText := strings.TrimPrefix(label, "node_at_depth_")
		if label == "divergence_node_depth_255" {
			depthText = "255"
		}
		depth, err := strconv.Atoi(depthText)
		if err != nil || depth < 0 || depth > 255 {
			t.Fatalf("unknown branch label %q", label)
		}
		path, node := candidateSMTHash(t, keys[0]), tree
		for d := 0; d < depth; d++ {
			if node == nil {
				t.Fatal("missing expected branch")
			}
			if zenoPathBit(path, d) == 0 {
				node = node.left
			} else {
				node = node.right
			}
		}
		zenoWantHash(t, zenoNodeHash(node), expected)
	}
}

func TestCandidateSMTZenoConformance(t *testing.T) {
	vectors := zenoVectors(t)
	byID := make(map[string]zenoVector, len(vectors))
	for i, v := range vectors {
		expected := fmt.Sprintf("SMT-%03d", i+1)
		if i >= 14 {
			expected = []string{"CV-PATH-1", "CV-PATH-2", "CV-APPLY-1", "CV-APPLY-2"}[i-14]
		}
		if v.ID != expected {
			t.Fatal("case inventory/order differs")
		}
		byID[v.ID] = v
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			zenoCheckVector(t, v, byID)
		})
	}
}

func zenoCheckVector(t *testing.T, v zenoVector, byID map[string]zenoVector) {
	t.Helper()
	if v.ID == "CV-PATH-2" {
		if len(v.AppliesTo) != 14 {
			t.Fatal("path-root API obligation omitted")
		}
		for i, id := range v.AppliesTo {
			if id != fmt.Sprintf("SMT-%03d", i+1) {
				t.Fatal("path-root case differs")
			}
			zenoCheckState(t, byID[id].State, byID[id].Root)
		}
		return
	}
	if v.ID == "CV-APPLY-2" {
		if len(v.DiffSteps) != 3 || !v.AllEqual {
			t.Fatal("batch/delete/present-empty projection omitted")
		}
		state := zenoCopy(v.Initial)
		for _, step := range v.DiffSteps {
			for _, entry := range step.Diff {
				zenoApply(t, state, zenoVectorOperation{Op: "apply_statediff_entry", Key: entry.Key, NewValue: entry.NewValue})
			}
			if !reflect.DeepEqual(state, step.State) {
				t.Fatal("diff projection state differs")
			}
			zenoCheckState(t, state, step.Root)
		}
		return
	}
	if v.Root == "" {
		t.Fatal("unhandled vector obligation")
	}
	root := zenoCheckState(t, v.State, v.Root)
	tree := zenoTree(t, v.State)
	for key, expected := range v.Leaves {
		value, exists := v.State[key]
		if !exists {
			t.Fatal("leaf expectation has no value")
		}
		zenoWantHash(t, zenoLeafHash(candidateSMTHash(t, key), candidateSMTBytes(t, value)), expected)
	}
	zenoCheckBranches(t, v, tree)
	if v.AbsentKey != "" && (v.Absence == nil || v.Absence.Key != v.AbsentKey) {
		t.Fatal("named absent path differs from its proof")
	}
	for _, p := range []*zenoVectorProof{v.Inclusion, v.Absence} {
		if p == nil {
			continue
		}
		value, present := v.State[p.Key]
		if p.Present != present || (p.Value != nil) != present || (present && *p.Value != value) {
			t.Fatal("proof presence/value differs from the selected state")
		}
		path := candidateSMTHash(t, p.Key)
		raw := candidateSMTBytes(t, p.Serialized)
		if !bytes.Equal(raw, zenoProof(t, tree, v.State, path)) {
			t.Fatal("serialized proof differs byte-for-byte")
		}
		if p.Length != 0 {
			if p.Length != len(raw) || !bytes.Equal(raw[33:65], candidateSMTBytes(t, p.Leaf)) ||
				!bytes.Equal(raw[65:97], candidateSMTBytes(t, p.Bitmap)) ||
				len(p.Siblings) != int(binary.BigEndian.Uint16(raw[97:99])) {
				t.Fatal("serialized proof metadata differs")
			}
			for i, sibling := range p.Siblings {
				if !bytes.Equal(raw[99+32*i:99+32*(i+1)], candidateSMTBytes(t, sibling)) {
					t.Fatal("bottom-up sibling order differs")
				}
			}
		} else if p.Leaf != "" || p.Bitmap != "" || len(p.Siblings) != 0 {
			t.Fatal("incomplete proof metadata")
		}
		zenoCheckNative(t, root, path, v.State, raw)
		if v.ID == "CV-PATH-1" {
			if v.PathResult != "accept" || v.HashedResult != "reject" {
				t.Fatal("path-native expectation changed")
			}
			double := chain.Hash(sha3.Sum256(path[:]))
			result, err := proof.CheckCandidateSMTInclusion(root, double, candidateSMTBytes(t, value), raw, candidateSMTLimits())
			requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTPath)
		}
	}
	if v.Operations != nil {
		state := zenoCopy(v.Initial)
		zenoWantHash(t, zenoNodeHash(zenoTree(t, state)), v.Before)
		for i, op := range v.Operations {
			zenoApply(t, state, op)
			if len(v.Steps) != 0 {
				if len(v.Steps) != len(v.Operations) || !v.AllEqual {
					t.Fatal("per-operation projection omitted")
				}
				step := v.Steps[i]
				if step.Key != op.Key || !step.Equal {
					t.Fatal("per-operation identity differs")
				}
				got := zenoCheckState(t, state, step.IncrementalRoot)
				zenoWantHash(t, got, step.FullRoot)
			}
		}
		if !reflect.DeepEqual(state, v.State) {
			t.Fatal("operation projection differs from resulting state")
		}
		zenoWantHash(t, root, v.After)
	}
	if len(v.KeyOrder) != 0 {
		keys := make([]string, len(v.Operations))
		for i, op := range v.Operations {
			keys[i] = op.Key
		}
		if !reflect.DeepEqual(keys, v.KeyOrder) || !sort.StringsAreSorted(keys) {
			t.Fatal("selected StateDiff key order differs")
		}
	}
	if v.Distinct {
		absent := zenoCopy(v.State)
		empty := 0
		for key, value := range v.State {
			if value == "" {
				delete(absent, key)
				empty++
				zenoWantHash(t, zenoLeafHash(candidateSMTHash(t, key), nil), v.EmptyLeaf)
			}
		}
		if empty != 1 {
			t.Fatal("ambiguous present-empty projection")
		}
		without := zenoCheckState(t, absent, v.AbsentRoot)
		zenoWantHash(t, root, v.EmptyRoot)
		if without == root {
			t.Fatal("present-empty collapsed into absence")
		}
	}
}
