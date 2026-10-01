package conformance_test

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

type contentSample struct {
	Members int                   `json:"members"`
	Targets []chain.AccountHeader `json:"targets"`
	Headers []chain.Header        `json:"headers"`
}

type contentCorpus struct {
	FormatVersion int `json:"format_version"`
	Source        struct {
		Commit string `json:"commit"`
	} `json:"source"`
	Anchor        verify.GenesisTrustRoot `json:"anchor"`
	MemberPrefix  string                  `json:"member_prefix"`
	MemberAddress chain.Address           `json:"member_address"`
	Samples       []contentSample         `json:"samples"`
}

type flatWorkload struct {
	corpus   contentCorpus
	sample   contentSample
	opts     verify.VerifyOptions
	schedule *verify.ProducerSchedule
	state    verify.VerifiedState
	bundle   proof.HeaderBundle
	path     string
	bytes    int64
}

var flatWorkloads = []struct{ members, proofs int }{{1, 1}, {1000, 1}, {100000, 1}, {100000, 4}}

func flatWorkloadName(members, proofs int) string { return fmt.Sprintf("M%d_P%d", members, proofs) }

func newFlatWorkload(t testing.TB, members, proofs int) flatWorkload {
	t.Helper()
	w := flatWorkload{}
	raw, err := os.ReadFile("../testdata/conformance/content-scaling.json")
	if err != nil || json.Unmarshal(raw, &w.corpus) != nil {
		t.Fatal("cannot read compact content corpus")
	}
	c := w.corpus
	if c.FormatVersion != 1 || c.Source.Commit != "3a4131e63881058b6ce2ee81d3a41d0033fafc99" ||
		c.MemberPrefix != "synthetic flat content member:" || len(c.Samples) != 3 || c.Anchor.ChainID != 99 || c.Anchor.Height != 6000 {
		t.Fatal("unexpected content corpus or source pin")
	}
	for _, s := range c.Samples {
		if s.Members == members {
			w.sample = s
		}
	}
	if len(w.sample.Headers) != 7 || len(w.sample.Targets) != 3 || proofs < 1 || proofs > members {
		t.Fatal("incomplete content workload")
	}
	content := make([]chain.AccountHeader, members)
	for i := range content {
		input := binary.BigEndian.AppendUint64([]byte(c.MemberPrefix), uint64(i+1))
		content[i] = chain.AccountHeader{Address: c.MemberAddress, Height: uint64(i + 1), Hash: sha3.Sum256(input)}
	}
	for i, index := range []int{0, members / 2, members - 1} {
		if content[index] != w.sample.Targets[i] {
			t.Fatal("expanded target differs from node output")
		}
	}
	if chain.MomentumContentHash(content) != w.sample.Headers[0].ContentHash {
		t.Fatal("expanded content root differs from node output")
	}
	w.opts.Policy = verify.DefaultPolicy() // W=6, legacy K=W+1=7, fully populated.
	w.opts.Policy.ProtocolProfile = &verify.ProtocolProfile{Version: 1, Anchor: c.Anchor,
		V2FromHeight: 6001, ValidThrough: 6007, Source: "synthetic content scaling profile"}
	var entries []verify.ProducerEntry
	for _, h := range w.sample.Headers {
		entries = append(entries, verify.ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix, ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
	}
	w.schedule, err = verify.NewProducerSchedule(c.Anchor.ChainID,
		[]verify.ProducerCoverage{{FromHeight: 6001, ThroughHeight: 6007}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.opts.ProducerAuth = verify.ProducerAuthOptions{Mode: verify.ProducerAuthRequired, Authorizer: verify.NewScheduleAuthorizer(w.schedule)}
	w.state, err = verify.NewVerifiedState(c.Anchor, w.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, state := w.state.Extend(w.sample.Headers)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatal("node-derived content headers were not accepted", r)
	}
	w.state = state
	w.bundle = proof.HeaderBundle{Version: proof.WireVersion, ChainID: c.Anchor.ChainID, ClaimedGenesis: c.Anchor.HeaderHash}
	for i := range proofs {
		index := members - 1 // One proof searches for the final member.
		if proofs > 1 {
			index = i * (members - 1) / (proofs - 1)
		}
		w.bundle.Commitments = append(w.bundle.Commitments, proof.CommitmentEvidence{Height: 6001, Target: content[index],
			Flat: &proof.FlatContentEvidence{SortedHeaders: content}})
	}
	// Marshal repeats the complete list per target, as the current wire format
	// requires. In-memory sharing must not understate input size or budgets.
	raw, err = json.Marshal(w.bundle)
	if err != nil || int64(len(raw)) > w.opts.Policy.MaxBundleBytes {
		t.Fatal("content workload exceeds the default wire byte cap")
	}
	w.bytes = int64(len(raw))
	w.path = filepath.Join(t.TempDir(), "content-bundle.json")
	if err := os.WriteFile(w.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w flatWorkload) load() (proof.HeaderBundle, error) {
	p := w.opts.Policy
	return proof.LoadHeaderBundleWithLimits(w.path, p.MaxBundleBytes, proof.DecodeLimits{
		MaxHeaders: p.MaxHeaders, MaxCommitments: p.MaxCommitments,
		MaxFlatEvidenceMembers: p.MaxFlatEvidenceMembers, MaxTotalFlatEvidenceMembers: p.MaxTotalFlatEvidenceMembers,
		MaxSegments: p.MaxSegments, MaxSegmentBlocks: p.MaxSegmentBlocks, MaxTotalSegmentBlocks: p.MaxTotalSegmentBlocks,
		MaxStateValueProofs: p.MaxStateValueProofs, MaxStateProofNodes: p.MaxStateProofNodes, MaxStateProofBytes: p.MaxStateProofBytes,
	})
}

func (w flatWorkload) check(t testing.TB, bundle proof.HeaderBundle) {
	t.Helper()
	if len(bundle.Commitments) != len(w.bundle.Commitments) || verify.PreflightCommitmentBounds(bundle.Commitments, w.opts.Policy).Outcome != verify.OutcomeAccept {
		t.Fatal("flat workload lost its targets or exceeded budgets")
	}
	for i, evidence := range bundle.Commitments {
		r := w.state.VerifyCommitment(evidence)
		if evidence.Target != w.bundle.Commitments[i].Target || r.Outcome != verify.OutcomeAccept ||
			!slices.Equal(r.Proven, []verify.Guarantee{verify.GuaranteeContentInclusion}) ||
			!slices.Contains(r.TrustAssumptions, verify.TrustExternalProducerSchedule) {
			t.Fatal("flat workload changed target, inclusion or trust boundaries", r)
		}
	}
}

func TestNodeContentScaling(t *testing.T) {
	for _, grid := range flatWorkloads {
		t.Run(flatWorkloadName(grid.members, grid.proofs), func(t *testing.T) {
			w := newFlatWorkload(t, grid.members, grid.proofs)
			bundle, err := w.load()
			if err != nil {
				t.Fatal(err)
			}
			w.check(t, bundle)
			for _, target := range w.sample.Targets {
				evidence := w.bundle.Commitments[0]
				evidence.Target = target
				if w.state.VerifyCommitment(evidence).Outcome != verify.OutcomeAccept {
					t.Fatal("node target was not found")
				}
			}
			evidence := bundle.Commitments[0]
			evidence.Target.Hash[0] ^= 1
			if r := w.state.VerifyCommitment(evidence); r.Outcome != verify.OutcomeReject || len(r.Proven) != 0 {
				t.Fatal("absent target acquired inclusion")
			}
			evidence = bundle.Commitments[0]
			evidence.Flat.SortedHeaders[grid.members/2].Hash[0] ^= 1
			if r := w.state.VerifyCommitment(evidence); r.Outcome != verify.OutcomeReject || r.Reason != verify.ReasonInvalidContent || len(r.Proven) != 0 {
				t.Fatal("mutated content acquired inclusion")
			}
			if grid.members > 1 {
				w.opts.Policy.MaxFlatEvidenceMembers = grid.members - 1
				var countErr *proof.BundleCountLimitError
				if _, err := w.load(); !errors.As(err, &countErr) || countErr.Field != "commitments.flat.sorted_headers" {
					t.Fatal("per-proof decode limit did not stop the workload", err)
				}
				w.opts.Policy.MaxFlatEvidenceMembers = verify.DefaultMaxFlatEvidenceMembers
			}
			if grid.proofs > 1 {
				w.opts.Policy.MaxTotalFlatEvidenceMembers = grid.members*grid.proofs - 1
				r := verify.PreflightCommitmentBounds(w.bundle.Commitments, w.opts.Policy)
				if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedEvidence || len(r.Proven) != 0 {
					t.Fatal("shared lists bypassed aggregate preflight")
				}
				var countErr *proof.BundleCountLimitError
				if _, err := w.load(); !errors.As(err, &countErr) {
					t.Fatal("repeated wire lists bypassed aggregate decode budget")
				}
			}
		})
	}
}

// Setup, expansion and state creation are outside timing. Verify measures an
// already-decoded batch; LoadAndVerify includes bounded warm file reads and
// JSON decoding. Both include result checks. Neither measures peak RSS.
func BenchmarkFlatContent(b *testing.B) {
	for _, grid := range flatWorkloads {
		b.Run(flatWorkloadName(grid.members, grid.proofs), func(b *testing.B) {
			w := newFlatWorkload(b, grid.members, grid.proofs)
			for _, operation := range []string{"Verify", "LoadAndVerify"} {
				b.Run(operation, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						bundle := w.bundle
						if operation == "LoadAndVerify" {
							var err error
							bundle, err = w.load()
							if err != nil {
								b.Fatal(err)
							}
						}
						w.check(b, bundle)
					}
					b.ReportMetric(float64(grid.members), "members/proof")
					b.ReportMetric(float64(grid.proofs), "proofs/op")
					b.ReportMetric(float64(w.bytes), "input-B")
				})
			}
		})
	}
}
