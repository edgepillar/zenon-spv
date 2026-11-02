// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"golang.org/x/crypto/sha3"
)

type executorApplierRow struct {
	Case        string            `json:"case"`
	Step        int               `json:"step"`
	DiffEntries int               `json:"diff_entries"`
	Root        string            `json:"root"`
	State       map[string]string `json:"resulting_state"`
	Proofs      []struct {
		Path    string `json:"path"`
		Present bool   `json:"present"`
		Value   string `json:"value"`
		Raw     string `json:"proof"`
	} `json:"proofs"`
}

func executorApplierRows(t *testing.T) []executorApplierRow {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "conformance", "executor-statediff.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close executor facts: %v", err)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(f, 13695))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 13694 || hex.EncodeToString(sum[:]) != "1d25b73f0a6316a1d6c50972ab2df57b9de9eca359f1fdbb8740f06d2f5c6f49" {
		t.Fatal("selected original-executor facts changed")
	}
	var file struct {
		Format string
		Source struct {
			Executor struct{ Repository, Revision, Tree string }
			Node     struct{ Repository, Revision, Tree string }
		}
		Execution struct {
			Platform, Toolchain string
			PassEvents          int    `json:"actual_test_pass_events"`
			NewStates           int    `json:"new_applier_states"`
			Proofs              int    `json:"independent_python_exact_proofs"`
			FullGraph           string `json:"full_historical_module_graph"`
		}
		Scope struct {
			Synthetic          bool
			Executor           bool `json:"original_executor_execution"`
			ReplayExecutes     bool `json:"SPV_replay_executes_original_executor"`
			AcceptedHeader     bool `json:"accepted_header"`
			Profile            bool `json:"profile_agreed"`
			StateValue         bool `json:"state_value_acceptance"`
			Activation         bool `json:"network_activation"`
			ProductionWorkload bool `json:"production_workload"`
		}
		Rows []executorApplierRow
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Format != "zenon-executor-statediff-recording/v1" ||
		file.Source.Executor.Repository != "Zeno-L2/zeno-executor" ||
		file.Source.Executor.Revision != "caeaf764270b1489a53c860c6006026af208f924" ||
		file.Source.Executor.Tree != "e1ca785d0176d7d53c657d66ee19d9550efccf37" ||
		file.Source.Node.Repository != "digitalSloth/go-zenon" ||
		file.Source.Node.Revision != "938fca3b7787da86827a5eb63371509b36e14761" ||
		file.Source.Node.Tree != "f3b7947d2267ebdb806f18ff0c02bba5bffae9c4" ||
		file.Execution.Platform != "darwin/arm64" || file.Execution.Toolchain != "go1.25.14" ||
		file.Execution.PassEvents != 24 || file.Execution.NewStates != 4 || file.Execution.Proofs != 15 ||
		file.Execution.FullGraph != "NOT_ESTABLISHED" || !file.Scope.Synthetic || !file.Scope.Executor ||
		file.Scope.ReplayExecutes || file.Scope.AcceptedHeader || file.Scope.Profile || file.Scope.StateValue ||
		file.Scope.Activation || file.Scope.ProductionWorkload || len(file.Rows) != 4 {
		t.Fatal("selected executor identity or scope changed")
	}
	expectedCases := []string{"CV-APPLY-1", "CV-APPLY-2", "CV-APPLY-2", "CV-APPLY-2"}
	expectedSteps := []int{1, 1, 2, 3}
	expectedDiffs := []int{2, 1, 2, 2}
	total := 0
	for i, row := range file.Rows {
		if row.Case != expectedCases[i] || row.Step != expectedSteps[i] || row.DiffEntries != expectedDiffs[i] ||
			len(row.State) < 1 || len(row.State) > 3 || len(row.Proofs) != []int{3, 4, 4, 4}[i] {
			t.Fatal("recorded StateDiff coverage changed")
		}
		total += len(row.Proofs)
	}
	if total != 15 {
		t.Fatal("recorded executor proof coverage changed")
	}
	return file.Rows
}

// Hosted execution replays retained bytes; it does not execute the original
// executor, authenticate an L2 transition or establish an accepted header root.
func TestCandidateSMTExecutorApplier(t *testing.T) {
	rows := executorApplierRows(t)
	for i, row := range rows {
		t.Run(fmt.Sprintf("%s-step-%d", row.Case, row.Step), func(t *testing.T) {
			tree := zenoTree(t, row.State)
			root := candidateSMTHash(t, row.Root)
			if zenoNodeHash(tree) != root {
				t.Fatal("independent full-tree root differs from executor output")
			}
			other := candidateSMTHash(t, rows[(i+len(rows)-1)%len(rows)].Root)
			if other == root {
				t.Fatal("different StateDiff step unexpectedly has the same root")
			}
			seen := map[string]bool{}
			for _, record := range row.Proofs {
				t.Run("path-"+record.Path[:2], func(t *testing.T) {
					if seen[record.Path] {
						t.Fatal("duplicate recorded proof path")
					}
					seen[record.Path] = true
					path := candidateSMTHash(t, record.Path)
					raw := candidateSMTBytes(t, record.Raw)
					value := candidateSMTBytes(t, record.Value)
					encoded, present := row.State[record.Path]
					if present != record.Present || (present && encoded != record.Value) || (!present && record.Value != "") {
						t.Fatal("recorded presence or value differs from post-state")
					}
					if !bytes.Equal(raw, zenoProof(t, tree, row.State, path)) {
						t.Fatal("independent exact proof encoding differs")
					}
					check := func(expectedRoot, expectedPath chain.Hash, inclusion bool) (proof.CandidateSMTMatch, error) {
						if inclusion {
							return proof.CheckCandidateSMTInclusion(expectedRoot, expectedPath, value, raw, candidateSMTLimits())
						}
						return proof.CheckCandidateSMTAbsence(expectedRoot, expectedPath, raw, candidateSMTLimits())
					}
					match, err := check(root, path, present)
					if err != nil || !match.Canonical || match.Present != present || !bytes.Equal(match.Value, value) {
						t.Fatalf("executor proof differs: %+v, %v", match, err)
					}
					t.Run("different-state-root", func(t *testing.T) {
						result, err := check(other, path, present)
						requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTMismatch)
					})
					t.Run("double-hashed-path", func(t *testing.T) {
						result, err := check(root, chain.Hash(sha3.Sum256(path[:])), present)
						requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTPath)
					})
					t.Run("presence-flipped", func(t *testing.T) {
						result, err := check(root, path, !present)
						requireCandidateSMTError(t, result, err, proof.ErrCandidateSMTEncoding)
					})
				})
			}
		})
	}
}
