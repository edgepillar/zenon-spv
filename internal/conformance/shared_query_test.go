package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Concurrent calls share immutable evidence and one owned handle. Only detached
// results and inspection copies are mutated; callers must not mutate evidence
// while a query is reading it. Expected results come from the public low-level
// verifier over a detached node-derived window, before workers start.
func TestNodeConcurrentImmutableQueries(t *testing.T) {
	c, bundle := delayedInclusionBundle(t)
	opts, _ := delayedOptions(t, c)
	opts.Policy.MaxSegmentBlocks, opts.Policy.MaxFlatEvidenceMembers = 3, 2
	empty, err := verify.NewVerifiedState(c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, fresh := empty.Extend(bundle.Headers[:18])
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal(r)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := fresh.Save(path); err != nil {
		t.Fatal(err)
	}
	resumed, err := verify.LoadTrustedState(path, c.Chain.Anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, handle := range []struct {
		name      string
		state     verify.VerifiedState
		persisted bool
	}{{"fresh", fresh, false}, {"resumed", resumed, true}} {
		t.Run(handle.name, func(t *testing.T) {
			before := handle.state.Snapshot()
			contextBefore, err := handle.state.VerificationContext()
			if err != nil {
				t.Fatal(err)
			}
			type query struct {
				name  string
				input any
				run   func() []verify.Result
				want  []verify.Result
			}
			withTrust := func(row verify.Result) verify.Result {
				if row.Outcome == verify.OutcomeAccept {
					row = row.WithTrust(verify.TrustConfiguredAnchor)
					if handle.persisted {
						row = row.WithTrust(verify.TrustPersistedState)
					}
					row = row.WithTrust(verify.TrustExternalProducerSchedule)
				}
				return row
			}
			var queries []query
			valid := bundle.Commitments[0]
			bad := valid
			members := slices.Clone(valid.Flat.SortedHeaders)
			members[0].Hash[0] ^= 1
			bad.Flat = &proof.FlatContentEvidence{SortedHeaders: members}
			missing := valid
			missing.Flat = nil
			for _, variant := range []struct {
				name     string
				evidence proof.CommitmentEvidence
			}{{"valid", valid}, {"bad_content", bad}, {"missing", missing}} {
				evidence := variant.evidence
				want := withTrust(verify.VerifyCommitment(before, evidence, opts.Policy))
				queries = append(queries, query{"commitment/" + variant.name, evidence,
					func() []verify.Result { return []verify.Result{handle.state.VerifyCommitment(evidence)} }, []verify.Result{want}})
			}
			for _, segment := range bundle.Segments {
				kind := "user"
				if segment.Address.IsEmbeddedAddress() {
					kind = "embedded"
				}
				for _, variant := range []string{"valid", "bad_content", "missing"} {
					commitments := slices.Clone(bundle.Commitments)
					first := slices.IndexFunc(commitments, func(e proof.CommitmentEvidence) bool {
						return e.Target == segment.Blocks[0].AccountHeader()
					})
					if first < 0 {
						t.Fatal("node corpus lost the segment's first commitment")
					}
					switch variant {
					case "bad_content":
						members := slices.Clone(commitments[first].Flat.SortedHeaders)
						members[0].Hash[0] ^= 1
						commitments[first].Flat = &proof.FlatContentEvidence{SortedHeaders: members}
					case "missing":
						commitments[first].Flat = nil
					}
					want := verify.VerifySegment(before, segment, commitments, opts.Policy).Blocks
					for i := range want {
						want[i] = withTrust(want[i])
					}
					input := struct {
						Segment     proof.AccountSegment
						Commitments []proof.CommitmentEvidence
					}{segment, commitments}
					queries = append(queries, query{kind + "/" + variant, input,
						func() []verify.Result { return handle.state.VerifySegment(segment, commitments).Blocks }, want})
				}
			}
			outcomes := make(map[verify.Outcome]bool)
			inputs, expected := make([]any, len(queries)), make([][]verify.Result, len(queries))
			for i, q := range queries {
				inputs[i], expected[i] = q.input, q.want
				for _, row := range q.want {
					outcomes[row.Outcome] = true
					assertBoundedGuarantees(t, row)
				}
				if got := q.run(); !reflect.DeepEqual(got, q.want) {
					t.Fatalf("serial owned query differs from low-level oracle: %s", q.name)
				}
			}
			if len(queries) != 9 || !outcomes[verify.OutcomeAccept] || !outcomes[verify.OutcomeReject] || !outcomes[verify.OutcomeRefused] {
				t.Fatal("node query matrix must exercise commitments, both segment kinds and all three outcomes")
			}
			capture := func(value any) []byte {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			inputBefore, expectedBefore := capture(inputs), capture(expected)
			stateBefore := capture(before)
			const workers, rounds = 4, 8
			start := make(chan struct{})
			failures := make(chan error, workers)
			var ready, finished sync.WaitGroup
			ready.Add(workers)
			finished.Add(workers)
			for worker := range workers {
				go func() {
					defer finished.Done()
					ready.Done()
					<-start
					for round := range rounds {
						for i := range queries {
							q := queries[(i+worker+round)%len(queries)]
							got := q.run()
							if !reflect.DeepEqual(got, q.want) {
								failures <- fmt.Errorf("worker %d round %d: %s changed result fields", worker, round, q.name)
								return
							}
							for i := range got {
								mutateSharedQueryResult(&got[i])
							}
							copy := handle.state.Snapshot()
							copy.RetainedWindow[0].Version = 3
							copy.RetainedWindow[0].PublicKey[0] ^= 1
							copy.RetainedWindow[0].Signature[0] ^= 1
							copy.ProtocolProfile.Source = "caller inspection edit"
							trust := handle.state.TrustAssumptions()
							trust[0] = verify.TrustAssumption("caller inspection edit")
							if got := q.run(); !reflect.DeepEqual(got, q.want) {
								failures <- fmt.Errorf("worker %d round %d: %s changed after detached mutation", worker, round, q.name)
								return
							}
						}
					}
				}()
			}
			ready.Wait()
			close(start)
			finished.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			contextAfter, err := handle.state.VerificationContext()
			if err != nil || !reflect.DeepEqual(contextBefore, contextAfter) || !reflect.DeepEqual(before, handle.state.Snapshot()) {
				t.Fatal("concurrent queries or inspection mutations changed state or context", err)
			}
			if !bytes.Equal(capture(handle.state.Snapshot()), stateBefore) {
				t.Fatal("detached snapshot mutation reached shared state")
			}
			if !bytes.Equal(capture(inputs), inputBefore) || !bytes.Equal(capture(expected), expectedBefore) {
				t.Fatal("concurrent queries changed caller evidence or the independent serial oracle")
			}
		})
	}
}

func mutateSharedQueryResult(row *verify.Result) {
	row.Outcome, row.Reason, row.Message, row.FailedAt = verify.OutcomeReject, verify.ReasonInvalidHash, "caller edit", 42
	if len(row.Proven) > 0 {
		row.Proven[0] = verify.Guarantee("caller edit")
	}
	if len(row.NotProven) > 0 {
		row.NotProven[0] = verify.Guarantee("caller edit")
	}
	if len(row.TrustAssumptions) > 0 {
		row.TrustAssumptions[0] = verify.TrustAssumption("caller edit")
	}
}
