package verify

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Exact prior helper body from b4ef6d48aa9cabe8a6353cd8e42418ba072ad854,
// with only its name changed. This reference never calls the new copier.
func ownedHeaderCopyReference(h chain.Header) chain.Header {
	h.PublicKey = bytes.Clone(h.PublicKey)
	h.Signature = bytes.Clone(h.Signature)
	return h
}

func ownedHeaderCopyFixture(key, signature []byte) chain.Header {
	return chain.Header{
		Version: 2, ChainIdentifier: 99, HeaderHash: chain.Hash{1, 2},
		PreviousHash: chain.Hash{3, 4}, Height: 123, TimestampUnix: 1700000123,
		DataHash: chain.Hash{5, 6}, ContentHash: chain.Hash{7, 8}, ChangesHash: chain.Hash{9, 10},
		PublicKey: key, Signature: signature, NextFusionPrice: 456, NextWorkPrice: 789,
	}
}

func TestOwnedHeaderEnvelopeCopyReference(t *testing.T) {
	shapes := []struct {
		name string
		data []byte
	}{{"nil", nil}, {"empty", []byte{}}, {"spare_capacity", make([]byte, 3, 96)}}
	for _, n := range []int{1, 31, 32, 33, 63, 64, 65, 256} {
		shapes = append(shapes, struct {
			name string
			data []byte
		}{fmt.Sprintf("bytes%d", n), bytes.Repeat([]byte{byte(n)}, n)})
	}
	for _, key := range shapes {
		for _, signature := range shapes {
			t.Run(key.name+"/"+signature.name, func(t *testing.T) {
				h := ownedHeaderCopyFixture(key.data, signature.data)
				want := ownedHeaderCopyReference(h)
				got := cloneStateHeader(h)
				if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(h, want) {
					t.Fatal("envelope bytes, fields or nil/empty shape differ from the prior copier")
				}
				if cap(got.PublicKey) != len(got.PublicKey) || cap(got.Signature) != len(got.Signature) {
					t.Fatal("an envelope field can extend beyond its owned range")
				}
			})
		}
	}
}

func TestOwnedHeaderEnvelopeCopyIndependence(t *testing.T) {
	for _, layout := range []string{"disjoint", "identical", "overlapping"} {
		t.Run(layout, func(t *testing.T) {
			input := make([]byte, 96)
			for i := range input {
				input[i] = byte(i)
			}
			key, signature := input[:32], input[32:]
			switch layout {
			case "identical":
				signature = key
			case "overlapping":
				signature = input[16:80]
			}
			h := ownedHeaderCopyFixture(key, signature)
			before := ownedHeaderCopyReference(h)
			first, second := cloneStateHeader(h), cloneStateHeader(h)
			signatureBefore := bytes.Clone(first.Signature)
			first.PublicKey[0] ^= 1
			if !bytes.Equal(first.Signature, signatureBefore) || !reflect.DeepEqual(h, before) || !reflect.DeepEqual(second, before) {
				t.Fatal("key mutation reached the signature, input or a separate copy")
			}
			grownKey := append(first.PublicKey, bytes.Repeat([]byte{0xa5}, 64)...)
			grownKey[len(key)] ^= 1
			if !bytes.Equal(first.Signature, signatureBefore) {
				t.Fatal("key append reached the signature")
			}
			keyBefore := bytes.Clone(first.PublicKey)
			first.Signature[0] ^= 1
			grownSignature := append(first.Signature, bytes.Repeat([]byte{0x5a}, 64)...)
			grownSignature[len(signature)] ^= 1
			if !bytes.Equal(first.PublicKey, keyBefore) || !reflect.DeepEqual(h, before) || !reflect.DeepEqual(second, before) {
				t.Fatal("signature mutation or append reached another owned field")
			}
			firstBefore := ownedHeaderCopyReference(first)
			key[0] ^= 2
			signature[0] ^= 4
			if !reflect.DeepEqual(first, firstBefore) || !reflect.DeepEqual(second, before) {
				t.Fatal("input mutation reached an existing copy")
			}
		})
	}
}

func TestOwnedHeaderEnvelopeSnapshotIndependence(t *testing.T) {
	state, _, evidence, _ := verifiedStateFixture(t)
	before := state.Snapshot()
	contextBefore, err := state.VerificationContext()
	if err != nil {
		t.Fatal(err)
	}
	view, separate := state.Snapshot(), state.Snapshot()
	view.RetainedWindow[0].PublicKey[0] ^= 1
	view.RetainedWindow[0].Signature[0] ^= 1
	view.RetainedWindow[0].PublicKey = append(view.RetainedWindow[0].PublicKey, 1)
	if !reflect.DeepEqual(view.RetainedWindow[1:], before.RetainedWindow[1:]) ||
		!reflect.DeepEqual(separate, before) || !reflect.DeepEqual(state.Snapshot(), before) {
		t.Fatal("snapshot mutation reached another header, view or the immutable handle")
	}
	contextAfter, err := state.VerificationContext()
	if err != nil || !reflect.DeepEqual(contextAfter, contextBefore) ||
		state.VerifyCommitment(evidence).Outcome != OutcomeAccept {
		t.Fatal("detached-view mutation changed context pins or accepted inclusion")
	}
}

var ownedHeaderCopySink chain.Header
var ownedHeaderSnapshotSink HeaderState

func ownedHeaderSnapshotReference(s HeaderState) HeaderState {
	s.ProtocolProfile = cloneProtocolProfile(s.ProtocolProfile)
	window := make([]chain.Header, len(s.RetainedWindow))
	for i, h := range s.RetainedWindow {
		window[i] = ownedHeaderCopyReference(h)
	}
	s.RetainedWindow = window
	return s
}

// Structural copy inputs, not signed or accepted history. Validation is outside
// these allocation measurements; the unchanged sequence tests cover that path.
func ownedHeaderSnapshotFixture(k int) HeaderState {
	s := HeaderState{Capacity: k, RetainedWindow: make([]chain.Header, k)}
	for i := range s.RetainedWindow {
		s.RetainedWindow[i] = ownedHeaderCopyFixture(bytes.Repeat([]byte{byte(i)}, 32), bytes.Repeat([]byte{byte(i + 1)}, 64))
	}
	return s
}

func TestOwnedHeaderEnvelopeAllocationBound(t *testing.T) {
	h := ownedHeaderCopyFixture(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64))
	reference := testing.AllocsPerRun(20, func() { ownedHeaderCopySink = ownedHeaderCopyReference(h) })
	actual := testing.AllocsPerRun(20, func() { ownedHeaderCopySink = cloneStateHeader(h) })
	if actual > 1 || reference < actual+1 {
		t.Fatal("a complete envelope did not remove one allocation", reference, actual)
	}
	for _, k := range []int{7, 256, MaxRetainHeaders} {
		t.Run(fmt.Sprintf("K%d", k), func(t *testing.T) {
			s := ownedHeaderSnapshotFixture(k)
			reference := testing.AllocsPerRun(3, func() { ownedHeaderSnapshotSink = ownedHeaderSnapshotReference(s) })
			actual := testing.AllocsPerRun(3, func() { ownedHeaderSnapshotSink = cloneHeaderState(s) })
			if actual > float64(k+1) || reference < actual+float64(k) || !reflect.DeepEqual(ownedHeaderSnapshotSink, s) {
				t.Fatal("snapshot allocation count, complete bytes or fields changed", reference, actual)
			}
		})
	}
}

func FuzzOwnedHeaderEnvelopeCopy(f *testing.F) {
	for _, seed := range [][]byte{{}, {0, 0}, {1, 1, 2, 3}, bytes.Repeat([]byte{0x42}, 96)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1024 {
			return
		}
		middle := len(raw) / 2
		h := ownedHeaderCopyFixture(raw[:middle], raw[middle:])
		if len(raw) != 0 && raw[0]&1 != 0 {
			h.Signature = raw // Deliberate input overlap.
		}
		before := ownedHeaderCopyReference(h)
		got := cloneStateHeader(h)
		if !reflect.DeepEqual(got, before) || cap(got.PublicKey) != len(got.PublicKey) || cap(got.Signature) != len(got.Signature) {
			t.Fatal("copier changed fields, bytes, shape or capacity isolation")
		}
		if len(got.PublicKey) != 0 {
			got.PublicKey[0] ^= 1
		}
		if len(got.Signature) != 0 {
			got.Signature[0] ^= 1
		}
		if !reflect.DeepEqual(h, before) {
			t.Fatal("copy mutation reached its source")
		}
	})
}

func BenchmarkOwnedHeaderEnvelopeCopy(b *testing.B) {
	h := ownedHeaderCopyFixture(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 64))
	for _, implementation := range []struct {
		name string
		copy func(chain.Header) chain.Header
	}{{"reference", ownedHeaderCopyReference}, {"owned", cloneStateHeader}} {
		b.Run(implementation.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ownedHeaderCopySink = implementation.copy(h)
			}
		})
	}
}

func BenchmarkOwnedHeaderEnvelopeSnapshot(b *testing.B) {
	for _, k := range []int{7, 256, MaxRetainHeaders} {
		s := ownedHeaderSnapshotFixture(k)
		b.Run(fmt.Sprintf("K%d", k), func(b *testing.B) {
			for _, implementation := range []struct {
				name string
				copy func(HeaderState) HeaderState
			}{{"reference", ownedHeaderSnapshotReference}, {"owned", cloneHeaderState}} {
				b.Run(implementation.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						ownedHeaderSnapshotSink = implementation.copy(s)
					}
				})
			}
		})
	}
}
