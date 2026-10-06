package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// This oracle keeps fixture indices, not HeaderState or verifier results. Its
// list updates and query decisions never call Append, capacityForPolicy,
// VerifyHeaders, VerifyCommitment, or any production validation helper.
// The signed synthetic fixtures test local semantics, not executed history.
type sequenceFixture struct {
	anchor   GenesisTrustRoot
	headers  []chain.Header
	members  []chain.AccountHeader
	profile  *ProtocolProfile
	schedule uint64
}

type sequenceModel struct {
	indices []int
	next    int
	w       uint64
	k       int // Zero selects the documented legacy W+1 capacity.
	resumed bool
}

func (m sequenceModel) capacity() int {
	if m.k == 0 {
		return int(m.w) + 1
	}
	return m.k
}

func (m sequenceModel) resized(w uint64, k int) sequenceModel {
	m.w, m.k = w, k
	m.indices = slices.Clone(m.indices)
	if len(m.indices) > m.capacity() {
		m.indices = m.indices[len(m.indices)-m.capacity():]
	}
	return m
}

func newSequenceFixture(mode int) sequenceFixture {
	return newSequenceFixtureSize(mode, 256)
}

func newSequenceFixtureSize(mode, count int) sequenceFixture {
	f := sequenceFixture{anchor: GenesisTrustRoot{ChainID: 3, Height: 100, HeaderHash: chain.Hash{1}}}
	if mode != 0 {
		f.profile = &ProtocolProfile{Version: 1, Anchor: f.anchor, ValidThrough: 140,
			V2FromHeight: 112, Source: "synthetic sequence fixture"}
	}
	if mode == 2 {
		f.profile.ValidThrough, f.schedule = 180, 138
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	previous := f.anchor.HeaderHash
	for i := 0; i < count; i++ {
		height := f.anchor.Height + uint64(i) + 1
		member := chain.AccountHeader{Address: chain.Address{2}, Height: height}
		binary.BigEndian.PutUint64(member.Hash[:8], height)
		h := chain.Header{Version: 1, ChainIdentifier: f.anchor.ChainID, Height: height,
			PreviousHash: previous, TimestampUnix: 1700000000 + height*10,
			ContentHash: chain.MomentumContentHash([]chain.AccountHeader{member}), PublicKey: key.Public().(ed25519.PublicKey)}
		if f.profile != nil && height >= f.profile.V2FromHeight {
			h.Version, h.NextFusionPrice, h.NextWorkPrice = 2, 1000, 1000
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(key, h.HeaderHash[:])
		f.headers, f.members = append(f.headers, h), append(f.members, member)
		previous = h.HeaderHash
	}
	return f
}

func (f sequenceFixture) authorizer(t *testing.T, from, through uint64) ProducerAuthorizer {
	t.Helper()
	var entries []ProducerEntry
	for _, h := range f.headers {
		if h.Height >= from && h.Height <= through {
			entries = append(entries, ProducerEntry{Height: h.Height, TimestampUnix: h.TimestampUnix,
				ProducingAddr: chain.PubKeyToAddress(h.PublicKey)})
		}
	}
	schedule, err := NewProducerSchedule(f.anchor.ChainID, []ProducerCoverage{{from, through}}, entries, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewScheduleAuthorizer(schedule)
}

func (f sequenceFixture) options(t *testing.T, m sequenceModel) VerifyOptions {
	t.Helper()
	p := DefaultPolicy()
	p.W, p.RetainHeaders = m.w, m.k
	if f.profile != nil {
		profile := *f.profile
		p.ProtocolProfile = &profile
	}
	opts := VerifyOptions{Policy: p}
	if f.schedule != 0 {
		opts.ProducerAuth = ProducerAuthOptions{Mode: ProducerAuthRequired,
			Authorizer: f.authorizer(t, f.anchor.Height+1, f.schedule)}
	}
	return opts
}

func sequenceCopyHeader(h chain.Header) chain.Header {
	h.PublicKey, h.Signature = bytes.Clone(h.PublicKey), bytes.Clone(h.Signature)
	return h
}

func sequenceCheckQuery(t *testing.T, f sequenceFixture, m sequenceModel, state VerifiedState, index, fault int) {
	t.Helper()
	height := f.anchor.Height + uint64(index+1)
	member := chain.AccountHeader{Address: chain.Address{2}, Height: height}
	binary.BigEndian.PutUint64(member.Hash[:8], height)
	e := proof.CommitmentEvidence{Height: height, Target: member,
		Flat: &proof.FlatContentEvidence{SortedHeaders: []chain.AccountHeader{member}}}
	switch fault {
	case 1:
		e.Flat = nil
	case 2:
		e.Flat.SortedHeaders[0].Hash[31] ^= 1
	case 3:
		e.Target.Hash[31] ^= 1
	}
	outcome, reason := OutcomeAccept, ReasonOK
	switch {
	case !slices.Contains(m.indices, index):
		outcome, reason = OutcomeRefused, ReasonHeightOutOfWindow
	case uint64(m.next-index-1) < m.w:
		outcome, reason = OutcomeRefused, ReasonInsufficientFinality
	case fault == 1:
		outcome, reason = OutcomeRefused, ReasonMissingProof
	case fault == 2:
		outcome, reason = OutcomeReject, ReasonInvalidContent
	case fault == 3:
		outcome, reason = OutcomeReject, ReasonNotMember
	}
	r := state.VerifyCommitment(e)
	if r.Outcome != outcome || r.Reason != reason || r.FailedAt != -1 {
		t.Fatalf("query index=%d fault=%d: got %s, want %v/%v", index, fault, r, outcome, reason)
	}
	if outcome != OutcomeAccept {
		if len(r.Proven) != 0 || len(r.TrustAssumptions) != 0 {
			t.Fatal("unsuccessful query promoted evidence or trust")
		}
		return
	}
	if !reflect.DeepEqual(r.Proven, []Guarantee{GuaranteeContentInclusion}) {
		t.Fatal("query promoted an unrelated guarantee")
	}
	wantTrust := []TrustAssumption{TrustRetainedWindowDepth, TrustConfiguredAnchor}
	if f.profile != nil {
		wantTrust = append(wantTrust, TrustExternalProtocolProfile)
	}
	if f.schedule != 0 {
		wantTrust = append(wantTrust, TrustExternalProducerSchedule)
	}
	if m.resumed {
		wantTrust = append(wantTrust, TrustPersistedState)
	}
	gotTrust := slices.Clone(r.TrustAssumptions)
	slices.Sort(gotTrust)
	slices.Sort(wantTrust)
	if !slices.Equal(gotTrust, wantTrust) {
		t.Fatal("query lost or invented a captured trust assumption")
	}
}

func sequenceCheckState(t *testing.T, f sequenceFixture, m sequenceModel, state VerifiedState) {
	t.Helper()
	snapshot := state.Snapshot()
	if snapshot.Genesis != f.anchor || snapshot.Capacity != m.capacity() || snapshot.RetainHeaders != m.k ||
		!reflect.DeepEqual(snapshot.ProtocolProfile, f.profile) || len(snapshot.RetainedWindow) != len(m.indices) {
		t.Fatal("retained state differs from independent list model")
	}
	for i, index := range m.indices {
		if !reflect.DeepEqual(snapshot.RetainedWindow[i], f.headers[index]) {
			t.Fatal("retained ordering or signed envelope differs from model")
		}
	}
	tip, hasTip := state.Tip()
	if hasTip != (len(m.indices) != 0) || state.Empty() != (len(m.indices) == 0) ||
		hasTip && !reflect.DeepEqual(tip, f.headers[m.next-1]) {
		t.Fatal("tip advanced on an unsuccessful operation")
	}
	summary, err := state.RetainedSummary()
	if err != nil || summary.Count != len(m.indices) || summary.Capacity != m.capacity() {
		t.Fatal("retained summary differs from model")
	}
	if len(m.indices) == 0 {
		if summary.Oldest != nil || summary.Tip != nil || summary.DepthEligible != nil {
			t.Fatal("empty state invented a retained range")
		}
	} else {
		first, last := f.headers[m.indices[0]], f.headers[m.next-1]
		if summary.Oldest == nil || *summary.Oldest != (chain.HashHeight{Hash: first.HeaderHash, Height: first.Height}) ||
			summary.Tip == nil || *summary.Tip != (chain.HashHeight{Hash: last.HeaderHash, Height: last.Height}) {
			t.Fatal("retained summary identities differ from model")
		}
		var eligible *RetainedDepthRange
		if uint64(len(m.indices)) > m.w {
			eligible = &RetainedDepthRange{FromHeight: first.Height, ThroughHeight: last.Height - m.w}
		}
		if !reflect.DeepEqual(summary.DepthEligible, eligible) {
			t.Fatal("depth-eligible range differs from model")
		}
	}
	context, err := state.VerificationContext()
	if err != nil || context.Policy.W != m.w || context.Policy.RetainHeaders != int64(m.k) || context.Fingerprint == nil ||
		state.RequireContextFingerprint(*context.Fingerprint) != nil {
		t.Fatal("captured policy or configuration pin differs from model")
	}
	indices := []int{-1, m.next - 1, m.next, m.next - int(m.w) - 1, m.next - int(m.w)}
	if len(m.indices) != 0 {
		indices = append(indices, m.indices[0]-1, m.indices[0])
	}
	for _, index := range indices {
		h, ok := state.HeaderAtHeight(f.anchor.Height + uint64(index+1))
		if ok != slices.Contains(m.indices, index) || ok && !reflect.DeepEqual(h, f.headers[index]) {
			t.Fatal("retained lookup differs from model")
		}
		for fault := 0; fault < 4; fault++ {
			sequenceCheckQuery(t, f, m, state, index, fault)
		}
	}
}

func sequenceSavedBytes(t *testing.T, state VerifiedState, path string) []byte {
	t.Helper()
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runRetainedSequence(t *testing.T, f sequenceFixture, initial sequenceModel, operations []byte) map[ReasonCode]bool {
	t.Helper()
	covered := make(map[ReasonCode]bool)
	m := initial
	opts := f.options(t, m)
	state, err := NewVerifiedState(f.anchor, opts)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	type predecessor struct {
		state VerifiedState
		model sequenceModel
	}
	var old []predecessor
	sequenceCheckState(t, f, m, state)
	for step, operation := range operations {
		kind, value := operation>>4, int(operation&15)
		before := state.Snapshot()
		if kind <= 4 || kind >= 14 {
			count := min(1+value%7, len(f.headers)-m.next)
			if kind == 4 {
				count = 0
			}
			batch := make([]chain.Header, count)
			for i := range batch {
				batch[i] = sequenceCopyHeader(f.headers[m.next+i])
			}
			faultAt := count - 1 // Includes a valid prefix when count > 1.
			if count != 0 {
				switch kind {
				case 1:
					batch[faultAt].Signature[0] ^= 1
				case 2:
					batch[faultAt].HeaderHash[0] ^= 1
				case 3:
					batch[faultAt].Version = 3
				}
			}
			want, reason, at := OutcomeAccept, ReasonOK, -1
			if count == 0 {
				want, reason = OutcomeRefused, ReasonMissingEvidence
			}
			for i, h := range batch {
				switch {
				case kind == 3 && i == faultAt:
					want, reason, at = OutcomeRefused, ReasonUnsupportedHeaderVersion, i
				case f.profile != nil && h.Height > f.profile.ValidThrough:
					want, reason, at = OutcomeRefused, ReasonProtocolProfileCoverage, i
				case kind == 1 && i == faultAt:
					want, reason, at = OutcomeReject, ReasonInvalidSignature, i
				case kind == 2 && i == faultAt:
					want, reason, at = OutcomeReject, ReasonInvalidHash, i
				case f.schedule != 0 && h.Height > f.schedule:
					want, reason = OutcomeRefused, ReasonProducerSetUnknown
				}
				if want != OutcomeAccept {
					break
				}
			}
			if want == OutcomeAccept && uint64(min(len(m.indices)+count, m.capacity())) < m.w {
				want, reason = OutcomeRefused, ReasonWindowNotMet
			}
			r, next := state.Extend(batch)
			if r.Outcome != want || r.Reason != reason || r.FailedAt != at {
				t.Fatalf("step=%d operation=%02x extension: got %s, want %v/%v at %d", step, operation, r, want, reason, at)
			}
			covered[reason] = true
			if want == OutcomeAccept {
				old = append(old, predecessor{state, m.resized(m.w, m.k)})
				if len(old) > 4 {
					old = old[1:]
				}
				m = m.resized(m.w, m.k)
				for i := 0; i < count; i++ {
					m.indices = append(m.indices, m.next)
					m.next++
				}
				m = m.resized(m.w, m.k)
				state = next
			} else if next != state || !reflect.DeepEqual(before, next.Snapshot()) || len(r.Proven) != 0 {
				t.Fatal("unsuccessful batch published a prefix or evidence")
			}
			for i := range batch {
				batch[i].PublicKey[0] ^= 1
				batch[i].Signature[0] ^= 1
			}
		} else {
			switch kind {
			case 5, 6, 7, 8, 9:
				raw := sequenceSavedBytes(t, state, path)
				candidate := m.resized(m.w, m.k)
				switch kind {
				case 6:
					candidate = m.resized(m.w, int(m.w)+1+value%9)
					if value == 15 {
						candidate = m.resized(m.w, 0)
					}
				case 7:
					w := []uint64{1, 2, 6}[value%3]
					candidate = m.resized(w, int(w)+1+value%9)
				}
				selected := f.options(t, candidate)
				if kind == 8 {
					if selected.Policy.ProtocolProfile == nil {
						selected.Policy.ProtocolProfile = &ProtocolProfile{Version: 1, Anchor: f.anchor,
							ValidThrough: 500, Source: "incompatible synthetic profile"}
					} else {
						selected.Policy.ProtocolProfile.ValidThrough++
					}
				}
				partialSchedule := kind == 9 && len(m.indices) > int(m.w)+1
				if partialSchedule {
					candidate = m.resized(m.w, int(m.w)+1)
					selected = f.options(t, candidate)
					from := f.headers[candidate.indices[0]].Height
					through := f.headers[candidate.next-1].Height
					selected.ProducerAuth = ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: f.authorizer(t, from, through)}
				}
				context, _ := state.VerificationContext()
				loaded, loadErr := LoadTrustedState(path, f.anchor, selected)
				switch {
				case kind == 6 && candidate.k == 0 && m.k != 0:
					if loadErr == nil {
						t.Fatal("omitted retention silently resumed explicit-K state")
					}
				case kind == 8:
					if !errors.Is(loadErr, ErrProtocolProfileMismatch) {
						t.Fatal("profile replacement bypassed the captured profile")
					}
				case partialSchedule:
					var auth *StateAuthorizationError
					if !errors.As(loadErr, &auth) || auth.Result.Outcome != OutcomeRefused || auth.Result.Reason != ReasonProducerSetUnknown {
						t.Fatal("shrink hid an unauthorized saved prefix")
					}
				default:
					if loadErr != nil {
						t.Fatal(loadErr)
					}
					changed := candidate.w != m.w || candidate.k != m.k
					if (loaded.RequireContextFingerprint(*context.Fingerprint) != nil) != changed {
						t.Fatal("old context pin did not track explicit policy changes")
					}
					candidate.resumed = len(candidate.indices) != 0
					state, m, opts = loaded, candidate, selected
				}
				after, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(raw, after) {
					t.Fatal("read-only resume modified the saved file")
				}
			case 10:
				view := state.Snapshot()
				view.Genesis.HeaderHash[0] ^= 1
				if view.ProtocolProfile != nil {
					view.ProtocolProfile.ValidThrough = 0
				}
				for i := range view.RetainedWindow {
					view.RetainedWindow[i].PublicKey[0] ^= 1
					view.RetainedWindow[i].Signature[0] ^= 1
				}
			case 11:
				sequenceCheckQuery(t, f, m, state, value, value%4)
			case 12:
				if err := state.Save(filepath.Join(filepath.Dir(path), "absent", "state.json")); err == nil {
					t.Fatal("save to an absent parent succeeded")
				}
			case 13:
				badPath := filepath.Join(filepath.Dir(path), "malformed.json")
				bad := []byte(`{"version":3}`)
				if os.WriteFile(badPath, bad, 0o600) != nil {
					t.Fatal("cannot prepare malformed saved input")
				}
				if _, err := LoadTrustedState(badPath, f.anchor, opts); err == nil {
					t.Fatal("malformed saved state resumed")
				}
				after, err := os.ReadFile(badPath)
				if err != nil || !bytes.Equal(after, bad) {
					t.Fatal("failed load rewrote malformed input")
				}
			}
		}
		sequenceCheckState(t, f, m, state)
		for _, predecessor := range old {
			sequenceCheckState(t, f, predecessor.model, predecessor.state)
		}
	}
	return covered
}

func TestRetainedStateSequenceModel(t *testing.T) {
	for mode, name := range []string{"v1", "v1_v2_profile", "v1_v2_schedule"} {
		fixture := newSequenceFixture(mode)
		for _, w := range []uint64{1, 2, 6} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/W%d/explicit%t", name, w, explicit), func(t *testing.T) {
					m := sequenceModel{w: w}
					if explicit {
						m.k = int(w) + 9
					}
					for _, seed := range []uint32{1, 0x5eed} {
						operations := []byte{0x00, 0x06, 0x16, 0x26, 0x36, 0x40, 0x50,
							0x06, 0x06, 0x06, 0x90, 0x60, 0x68, 0x6f, 0x70, 0x72, 0x80, 0xa0, 0xb0, 0xc0, 0xd0}
						operations = append(operations, bytes.Repeat([]byte{0x06}, 10)...)
						for i := 0; i < 32; i++ {
							seed = seed*1664525 + 1013904223
							operations = append(operations, byte(seed>>24))
						}
						covered := runRetainedSequence(t, fixture, m, operations)
						required := []ReasonCode{ReasonOK, ReasonInvalidSignature, ReasonInvalidHash,
							ReasonUnsupportedHeaderVersion, ReasonMissingEvidence}
						if w > 1 {
							required = append(required, ReasonWindowNotMet)
						}
						switch mode {
						case 1:
							required = append(required, ReasonProtocolProfileCoverage)
						case 2:
							required = append(required, ReasonProducerSetUnknown)
						}
						for _, reason := range required {
							if !covered[reason] {
								t.Fatalf("fixed sequence did not exercise extension reason %v", reason)
							}
						}
					}
				})
			}
		}
	}
}

func FuzzRetainedStateSequence(f *testing.F) {
	fixtures := []sequenceFixture{newSequenceFixture(0), newSequenceFixture(1), newSequenceFixture(2)}
	f.Add([]byte{0, 0, 0x06, 0x16, 0x50, 0x60, 0x6f, 0x90, 0xa0})
	f.Add([]byte{1, 2, 0x00, 0x06, 0x26, 0x70, 0x80, 0x50, 0xc0, 0xd0})
	f.Add(append([]byte{2, 1}, bytes.Repeat([]byte{0x06}, 10)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 2 || len(raw) > 98 {
			return
		}
		m := sequenceModel{w: []uint64{1, 2, 6}[int(raw[1])%3]}
		if raw[1]&4 != 0 {
			m.k = int(m.w) + 9
		}
		runRetainedSequence(t, fixtures[int(raw[0])%3], m, raw[2:])
	})
}
