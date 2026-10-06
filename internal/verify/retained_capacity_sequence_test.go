package verify

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// The same independent fixture-index model now checks composed operations on
// full windows, including the largest explicit capacity. Signing constructs
// synthetic envelopes; it does not supply the list or query oracle.
type capacitySequence struct {
	t       *testing.T
	fixture sequenceFixture
	model   sequenceModel
	state   VerifiedState
	path    string
	targets []int
	old     []capacityPredecessor
	covered map[ReasonCode]bool
	steps   int
}

type capacityPredecessor struct {
	state VerifiedState
	model sequenceModel
}

func (s *capacitySequence) remember() {
	s.old = append(s.old, capacityPredecessor{s.state, s.model.resized(s.model.w, s.model.k)})
	if len(s.old) > 3 {
		s.old = s.old[1:]
	}
}

func (s *capacitySequence) check() {
	s.t.Helper()
	s.steps++
	sequenceCheckState(s.t, s.fixture, s.model, s.state)
	// Keep independently selected delayed targets, not just the current tail.
	for _, index := range s.targets {
		sequenceCheckQuery(s.t, s.fixture, s.model, s.state, index, 0)
	}
	for _, old := range s.old {
		sequenceCheckState(s.t, s.fixture, old.model, old.state)
	}
}

func (s *capacitySequence) extend(count int, fault string) {
	s.t.Helper()
	batch := make([]chain.Header, count)
	for i := range batch {
		batch[i] = sequenceCopyHeader(s.fixture.headers[s.model.next+i])
	}
	switch fault {
	case "signature":
		batch[count-1].Signature[0] ^= 1
	case "hash":
		batch[count-1].HeaderHash[0] ^= 1
	}
	want, reason, at := OutcomeAccept, ReasonOK, -1
	for i, h := range batch {
		switch {
		case s.fixture.profile != nil && h.Height > s.fixture.profile.ValidThrough:
			want, reason, at = OutcomeRefused, ReasonProtocolProfileCoverage, i
		case fault == "signature" && i == count-1:
			want, reason, at = OutcomeReject, ReasonInvalidSignature, i
		case fault == "hash" && i == count-1:
			want, reason, at = OutcomeReject, ReasonInvalidHash, i
		case s.fixture.schedule != 0 && h.Height > s.fixture.schedule:
			want, reason = OutcomeRefused, ReasonProducerSetUnknown
		}
		if want != OutcomeAccept {
			break
		}
	}
	before := s.state.Snapshot()
	r, next := s.state.Extend(batch)
	if r.Outcome != want || r.Reason != reason || r.FailedAt != at {
		s.t.Fatalf("step=%d count=%d fault=%s: got %s, want %v/%v at %d", s.steps, count, fault, r, want, reason, at)
	}
	s.covered[reason] = true
	if want == OutcomeAccept {
		s.remember()
		m := s.model.resized(s.model.w, s.model.k)
		for range count {
			m.indices = append(m.indices, m.next)
			m.next++
		}
		s.state, s.model = next, m.resized(m.w, m.k)
	} else if next != s.state || !reflect.DeepEqual(before, next.Snapshot()) || len(r.Proven) != 0 {
		s.t.Fatal("failed full-window batch published a prefix or evidence")
	}
	for i := range batch {
		batch[i].PublicKey[0] ^= 1
		batch[i].Signature[0] ^= 1
	}
	s.check()
}

func (s *capacitySequence) resume(w uint64, k int) {
	s.t.Helper()
	raw := sequenceSavedBytes(s.t, s.state, s.path)
	context, err := s.state.VerificationContext()
	if err != nil {
		s.t.Fatal(err)
	}
	m := s.model.resized(w, k)
	loaded, err := LoadTrustedState(s.path, s.fixture.anchor, s.fixture.options(s.t, m))
	if err != nil {
		s.t.Fatal(err)
	}
	changed := w != s.model.w || k != s.model.k
	if (loaded.RequireContextFingerprint(*context.Fingerprint) != nil) != changed {
		s.t.Fatal("resume did not preserve or invalidate the previous policy pin")
	}
	s.remember()
	m.resumed = len(m.indices) != 0
	s.state, s.model = loaded, m
	s.unchangedFile(raw)
	s.check()
}

func (s *capacitySequence) unchangedFile(raw []byte) {
	s.t.Helper()
	after, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(raw, after) {
		s.t.Fatal("read-only resume changed the saved bytes")
	}
}

func (s *capacitySequence) refuseShrink() {
	s.t.Helper()
	raw := sequenceSavedBytes(s.t, s.state, s.path)
	m := s.model.resized(6, 8)
	opts := s.fixture.options(s.t, m)
	first, last := s.fixture.headers[m.indices[0]], s.fixture.headers[m.next-1]
	opts.ProducerAuth = ProducerAuthOptions{Mode: ProducerAuthRequired,
		Authorizer: s.fixture.authorizer(s.t, first.Height, last.Height)}
	_, err := LoadTrustedState(s.path, s.fixture.anchor, opts)
	var auth *StateAuthorizationError
	if !errors.As(err, &auth) || auth.Result.Outcome != OutcomeRefused || auth.Result.Reason != ReasonProducerSetUnknown {
		s.t.Fatal("tail-only schedule hid an unauthorized full-window prefix", err)
	}
	s.unchangedFile(raw)
	s.check()
}

func (s *capacitySequence) refuseSelections() {
	s.t.Helper()
	raw := sequenceSavedBytes(s.t, s.state, s.path)
	for _, k := range []int{0, int(s.model.w), MaxRetainHeaders + 1} {
		opts := s.fixture.options(s.t, s.model)
		opts.Policy.RetainHeaders = k
		_, err := LoadTrustedState(s.path, s.fixture.anchor, opts)
		if err == nil || k != 0 && !errors.Is(err, ErrInvalidRetentionPolicy) {
			s.t.Fatal("invalid or omitted retention resumed the full state", err)
		}
		s.unchangedFile(raw)
		s.check()
	}
}

func TestRetainedCapacitySequenceModel(t *testing.T) {
	for _, k := range []int{16, 256, MaxRetainHeaders} {
		for mode, name := range []string{"v1", "v1_v2_profile", "v1_v2_schedule"} {
			fixture := newSequenceFixtureSize(mode, 2*k+32)
			if fixture.profile != nil {
				fixture.profile.ValidThrough = fixture.anchor.Height + uint64(2*k+16)
			}
			if mode == 2 {
				fixture.schedule = fixture.anchor.Height + uint64(2*k+12)
			}
			for _, w := range []uint64{6, uint64(k - 1)} {
				t.Run(fmt.Sprintf("K%d/%s/W%d", k, name, w), func(t *testing.T) {
					m := sequenceModel{w: w, k: k}
					state, err := NewVerifiedState(fixture.anchor, fixture.options(t, m))
					if err != nil {
						t.Fatal(err)
					}
					s := capacitySequence{t: t, fixture: fixture, model: m, state: state,
						path: filepath.Join(t.TempDir(), "state.json"), targets: []int{0, k / 2, k - 1},
						covered: make(map[ReasonCode]bool)}
					s.check()
					s.extend(k, "") // Fill exactly K, including W=K-1 startup.
					s.resume(w, k)
					s.extend(3, "signature")
					s.extend(3, "hash")
					s.extend(1, "") // Evict the original oldest delayed target.
					s.refuseShrink()
					s.refuseSelections()
					s.resume(6, 8)
					s.resume(6, k) // Growth must not restore the evicted history.
					s.resume(6, k)
					s.extend(k-8, "") // Refill the enlarged window from its retained tail.
					s.extend(9, "")
					s.resume(uint64(k-1), k) // Only the oldest height meets W=K-1.
					s.extend(11, "")         // Required schedule expires inside this batch.
					s.extend(15, "")         // Profile expiry also refuses the whole valid prefix.
					s.resume(6, 16)
					s.resume(6, 16)
					for _, reason := range []ReasonCode{ReasonOK, ReasonInvalidSignature, ReasonInvalidHash} {
						if !s.covered[reason] {
							t.Fatal("fixed capacity sequence missed extension reason", reason)
						}
					}
					if mode == 1 && !s.covered[ReasonProtocolProfileCoverage] || mode == 2 && !s.covered[ReasonProducerSetUnknown] {
						t.Fatal("fixed capacity sequence missed its finite trust-input boundary")
					}
					if s.steps != 20 {
						t.Fatal("fixed capacity operation count changed", s.steps)
					}
				})
			}
		}
	}
}
