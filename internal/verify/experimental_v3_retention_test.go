// SPDX-License-Identifier: MIT

package verify

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func experimentalV3RetentionInputs(t testing.TB, retain, batch uint32) experimentalV3Fixture {
	t.Helper()
	f := experimentalV3Inputs(t)
	f.policy.RetainHeaders, f.policy.MaxBatchHeaders = retain, batch
	c, err := ExperimentalV3ContextFor(f.profile, f.policy, f.schedule)
	if err != nil {
		t.Fatal(err)
	}
	f.pin = c.Fingerprint
	return f
}

func TestExperimentalV3RetainedSuffixOwnership(t *testing.T) {
	for _, retain := range []uint32{2, 3, MaxRetainHeaders} {
		for _, partition := range [][]int{{3}, {1, 2}, {2, 1}, {1, 1, 1}} {
			t.Run(fmt.Sprint(retain, "-", partition), func(t *testing.T) {
				f := experimentalV3RetentionInputs(t, retain, 3)
				// Read the unchanged public capture independently for the oracle.
				oracle := experimentalV3Inputs(t)
				state := experimentalV3New(t, f)
				type previous struct {
					state ExperimentalV3State
					count int
				}
				states := []previous{{state, 0}}
				count := 0
				for _, size := range partition {
					r, next := state.Extend(f.headers[count : count+size])
					if r.Outcome != OutcomeAccept {
						t.Fatal("public signed extension failed", r)
					}
					count += size
					state = next
					states = append(states, previous{next, count})
				}
				for i := range f.headers {
					f.headers[i].Header.PublicKey[0] ^= 1
					f.headers[i].Header.Signature[0] ^= 1
					f.headers[i].StateRoot[0] ^= 1
				}
				for _, old := range states {
					context, err := old.state.Context()
					if err != nil || context.Fingerprint != f.pin {
						t.Fatal("extension replaced the selected context", err)
					}
					for i, want := range oracle.headers {
						got, ok := old.state.HeaderAtHeight(want.Header.Height)
						present := i < old.count && old.count-i <= int(retain)
						if ok != present || ok && !reflect.DeepEqual(got, want) {
							t.Fatal("retained public bytes or earlier handle changed", i, old.count)
						}
						if ok {
							got.Header.PublicKey[0] ^= 1
							got.Header.Signature[0] ^= 1
							again, _ := old.state.HeaderAtHeight(want.Header.Height)
							if !reflect.DeepEqual(again, want) {
								t.Fatal("exported bytes alias retained ownership")
							}
						}
					}
				}
				var unavailable error
				if retain == 2 {
					unavailable = ErrExperimentalV3HeaderUnavailable
				}
				if _, err := state.RootAt(12, oracle.headers[0].Header.HeaderHash, f.pin); err != unavailable {
					t.Fatal("retention changed root availability", err)
				}
				if root, err := state.RootAt(13, oracle.headers[1].Header.HeaderHash, f.pin); err != nil || root != oracle.headers[1].StateRoot {
					t.Fatal("retained root/depth changed", err)
				}
			})
		}
	}
}

func TestExperimentalV3EvictedInputStillValidated(t *testing.T) {
	for _, name := range []string{"root", "signature", "version", "producer", "schedule_gap"} {
		t.Run(name, func(t *testing.T) {
			f := experimentalV3Inputs(t)
			outcome, reason := OutcomeReject, ReasonInvalidHash
			switch name {
			case "root":
				f.headers[0].StateRoot[0] ^= 1
			case "signature":
				f.headers[0].Header.Signature[0] ^= 1
				reason = ReasonInvalidSignature
			case "version":
				f.headers[0].Header.Version = 2
				outcome, reason = OutcomeRefused, ReasonUnsupportedHeaderVersion
			case "producer":
				entries := append([]ProducerEntry(nil), f.schedule.Entries...)
				entries[0].ProducingAddr[0] ^= 1
				var err error
				f.schedule, err = NewProducerSchedule(100, f.schedule.Coverage, entries, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				reason = ReasonUnauthorizedProducer
			case "schedule_gap":
				var err error
				f.schedule, err = NewProducerSchedule(100, []ProducerCoverage{{FromHeight: 13, ThroughHeight: 14}}, f.schedule.Entries[1:], nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				outcome, reason = OutcomeRefused, ReasonProducerSetUnknown
			}
			c, err := ExperimentalV3ContextFor(f.profile, f.policy, f.schedule)
			if err != nil {
				t.Fatal(err)
			}
			f.pin = c.Fingerprint
			state := experimentalV3New(t, f)
			r, next := state.Extend(f.headers)
			if r.Outcome != outcome || r.Reason != reason || next.data != state.data || !next.Empty() || len(r.Proven) != 0 {
				t.Fatal("an eventually evicted input escaped validation or published progress", r)
			}
		})
	}
}

// Repeat existing public signatures to construct a bounded invalid batch,
// not another chain/capture. The first repeated height fails at index three.
func experimentalV3RejectedBatch(t testing.TB, early bool) (ExperimentalV3State, []chain.CandidateV3Header, Outcome, ReasonCode) {
	t.Helper()
	f := experimentalV3RetentionInputs(t, 2, MaxRetainHeaders)
	batch := make([]chain.CandidateV3Header, MaxRetainHeaders)
	for i := range batch {
		batch[i] = f.headers[i%len(f.headers)]
	}
	outcome, reason := OutcomeReject, ReasonHeightNonMonotonic
	if early {
		batch[0].Header.Version = 2
		outcome, reason = OutcomeRefused, ReasonUnsupportedHeaderVersion
	}
	return experimentalV3New(t, f), batch, outcome, reason
}

func TestExperimentalV3RejectedBatchAllocation(t *testing.T) {
	for _, early := range []bool{true, false} {
		t.Run(fmt.Sprint("early_", early), func(t *testing.T) {
			state, batch, outcome, reason := experimentalV3RejectedBatch(t, early)
			state.Extend(batch)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			const attempts = 4
			for i := 0; i < attempts; i++ {
				r, next := state.Extend(batch)
				if r.Outcome != outcome || r.Reason != reason || next.data != state.data {
					t.Fatal("invalid batch changed its refusal or owned state", r)
				}
			}
			runtime.ReadMemStats(&after)
			// A generous cumulative allocation bound, not a peak-RSS claim.
			// This catches a 4096-header throwaway slice before any accepted state.
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > attempts*(64<<10) {
				t.Fatalf("rejected batch allocated %d bytes across %d attempts", allocated, attempts)
			}
		})
	}
}

func BenchmarkExperimentalV3RetainedCopies(b *testing.B) {
	for _, name := range []string{"public_retained_tail", "invalid_first_4096", "invalid_after_public_prefix_4096"} {
		b.Run(name, func(b *testing.B) {
			f := experimentalV3Inputs(b)
			state, batch, outcome, reason := experimentalV3New(b, f), f.headers, OutcomeAccept, ReasonOK
			if name != "public_retained_tail" {
				state, batch, outcome, reason = experimentalV3RejectedBatch(b, name == "invalid_first_4096")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, next := state.Extend(batch)
				if r.Outcome != outcome || r.Reason != reason || outcome != OutcomeAccept && next.data != state.data {
					b.Fatal("unexpected measured extension outcome", r)
				}
			}
		})
	}
}
