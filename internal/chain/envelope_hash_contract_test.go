package chain_test

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Fixed offsets keep these byte oracles independent of production append
// helpers, HashHeight.Bytes and accountAmountBytes. Pinned node vectors provide
// separate expected digests. These low-level oracles do not authorize inputs.
func referenceHeaderEnvelope(h chain.Header) []byte {
	size := 160
	if h.Version == 2 {
		size = 176
	}
	raw := make([]byte, size)
	binary.BigEndian.PutUint64(raw[0:8], h.Version)
	binary.BigEndian.PutUint64(raw[8:16], h.ChainIdentifier)
	copy(raw[16:48], h.PreviousHash[:])
	binary.BigEndian.PutUint64(raw[48:56], h.Height)
	binary.BigEndian.PutUint64(raw[56:64], h.TimestampUnix)
	copy(raw[64:96], h.DataHash[:])
	copy(raw[96:128], h.ContentHash[:])
	copy(raw[128:160], h.ChangesHash[:])
	if h.Version == 2 {
		binary.BigEndian.PutUint64(raw[160:168], h.NextFusionPrice)
		binary.BigEndian.PutUint64(raw[168:176], h.NextWorkPrice)
	}
	return raw
}

func referenceAccountEnvelope(b chain.AccountBlock) []byte {
	amount := new(big.Int)
	if b.Amount != nil {
		amount.Abs(b.Amount)
	}
	width := max(32, (amount.BitLen()+7)/8)
	raw := make([]byte, 306+width-32)
	binary.BigEndian.PutUint64(raw[0:8], b.Version)
	binary.BigEndian.PutUint64(raw[8:16], b.ChainIdentifier)
	binary.BigEndian.PutUint64(raw[16:24], b.BlockType)
	copy(raw[24:56], b.PreviousHash[:])
	binary.BigEndian.PutUint64(raw[56:64], b.Height)
	copy(raw[64:96], b.MomentumAcknowledged.Hash[:])
	binary.BigEndian.PutUint64(raw[96:104], b.MomentumAcknowledged.Height)
	copy(raw[104:124], b.Address[:])
	copy(raw[124:144], b.ToAddress[:])
	amount.FillBytes(raw[144 : 144+width])
	p := 144 + width
	copy(raw[p:p+10], b.TokenStandard[:])
	copy(raw[p+10:p+42], b.FromBlockHash[:])
	copy(raw[p+42:p+74], b.DescendantBlocksHash[:])
	copy(raw[p+74:p+106], b.DataHash[:])
	binary.BigEndian.PutUint64(raw[p+106:p+114], b.FusedPlasma)
	binary.BigEndian.PutUint64(raw[p+114:p+122], b.Difficulty)
	copy(raw[p+122:p+130], b.Nonce[:])
	return raw
}

func envelopeBoundaryInputs() (chain.Header, chain.AccountBlock) {
	var hashes [7]chain.Hash
	for i := range hashes {
		for j := range hashes[i] {
			hashes[i][j] = byte(i*37 + j*11)
		}
	}
	h := chain.Header{Version: 2, ChainIdentifier: math.MaxUint64, PreviousHash: hashes[0],
		Height: 1<<53 + 1, TimestampUnix: 1<<63 + 1, DataHash: hashes[1],
		ContentHash: hashes[2], ChangesHash: hashes[3], NextFusionPrice: math.MaxUint64,
		NextWorkPrice: 1<<32 + 1, HeaderHash: hashes[6], PublicKey: []byte{1, 2}, Signature: []byte{3, 4}}
	b := chain.AccountBlock{Version: math.MaxUint64, ChainIdentifier: 1<<53 + 1,
		BlockType: 1<<63 + 1, PreviousHash: hashes[0], Height: math.MaxUint64,
		MomentumAcknowledged: chain.HashHeight{Hash: hashes[1], Height: 1<<63 + 1},
		FromBlockHash:        hashes[2], DescendantBlocksHash: hashes[3], DataHash: hashes[4],
		FusedPlasma: math.MaxUint64, Difficulty: 1<<32 + 1, BlockHash: hashes[6],
		PublicKey: []byte{5, 6}, Signature: []byte{7, 8}}
	for i := range b.Address {
		b.Address[i], b.ToAddress[i] = byte(i*13+1), byte(i*17+2)
	}
	for i := range b.TokenStandard {
		b.TokenStandard[i] = byte(i*19 + 3)
	}
	for i := range b.Nonce {
		b.Nonce[i] = byte(i*23 + 4)
	}
	return h, b
}

func checkHeaderEnvelope(t testing.TB, h chain.Header) {
	t.Helper()
	before := h
	before.PublicKey, before.Signature = slices.Clone(h.PublicKey), slices.Clone(h.Signature)
	if h.ComputeHash() != chain.Hash(sha3.Sum256(referenceHeaderEnvelope(h))) {
		t.Fatal("momentum hash differs from the independent byte oracle")
	}
	if !reflect.DeepEqual(h, before) {
		t.Fatal("momentum hashing modified caller-owned input")
	}
}

func checkAccountEnvelope(t testing.TB, b chain.AccountBlock) {
	t.Helper()
	before := b
	before.PublicKey, before.Signature = slices.Clone(b.PublicKey), slices.Clone(b.Signature)
	var amountValue *big.Int
	var amountWords []big.Word
	if b.Amount != nil {
		amountValue = new(big.Int).Set(b.Amount)
		amountWords = slices.Clone(b.Amount.Bits())
	}
	if b.ComputeHash() != chain.Hash(sha3.Sum256(referenceAccountEnvelope(b))) {
		t.Fatal("account hash differs from the independent byte oracle")
	}
	// A cloned zero may have a different empty backing slice. Compare the
	// numeric value and words separately while retaining the original pointer.
	if !reflect.DeepEqual(b, before) || b.Amount != before.Amount ||
		(b.Amount != nil && (b.Amount.Cmp(amountValue) != 0 || !slices.Equal(b.Amount.Bits(), amountWords))) {
		t.Fatal("account hashing modified caller-owned input")
	}
}

func TestSignedEnvelopeHashSerializationContract(t *testing.T) {
	h, block := envelopeBoundaryInputs()
	for _, version := range []uint64{0, 1, 2, 3, math.MaxUint64} {
		t.Run(fmt.Sprintf("header_version_%d", version), func(t *testing.T) {
			candidate := h
			candidate.Version = version
			checkHeaderEnvelope(t, candidate)
		})
	}
	max255 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	bit257 := new(big.Int).Lsh(big.NewInt(1), 256)
	for _, tc := range []struct {
		name   string
		amount *big.Int
	}{
		{"nil", nil}, {"zero", new(big.Int)}, {"zero bytes", new(big.Int).SetBytes([]byte{0})},
		{"one", big.NewInt(1)}, {"max255", max255}, {"max256", max256},
		{"negative", big.NewInt(-1)}, {"bit257", bit257},
		{"negative257", new(big.Int).Neg(bit257)}, {"wide4097", new(big.Int).Lsh(big.NewInt(1), 4096)},
	} {
		t.Run("account_amount_"+tc.name, func(t *testing.T) {
			candidate := block
			candidate.Amount = tc.amount
			checkAccountEnvelope(t, candidate)
		})
	}
	t.Run("unsigned fields are excluded", func(t *testing.T) {
		for _, version := range []uint64{1, 2} {
			candidate := h
			candidate.Version = version
			want := candidate.ComputeHash()
			candidate.HeaderHash, candidate.PublicKey, candidate.Signature = chain.Hash{}, nil, nil
			if candidate.ComputeHash() != want {
				t.Fatal("unsigned momentum fields changed the hash")
			}
		}
		candidate := block
		candidate.Amount = max255
		want := candidate.ComputeHash()
		candidate.BlockHash, candidate.PublicKey, candidate.Signature = chain.Hash{}, nil, nil
		if candidate.ComputeHash() != want {
			t.Fatal("unsigned account fields changed the hash")
		}
	})
	t.Run("shared immutable input", func(t *testing.T) {
		block.Amount = max255
		wantHeader := chain.Hash(sha3.Sum256(referenceHeaderEnvelope(h)))
		wantAccount := chain.Hash(sha3.Sum256(referenceAccountEnvelope(block)))
		beforeAmount := slices.Clone(block.Amount.Bytes())
		beforeHeader, beforeBlock := h, block
		beforeHeader.PublicKey, beforeHeader.Signature = slices.Clone(h.PublicKey), slices.Clone(h.Signature)
		beforeBlock.PublicKey, beforeBlock.Signature = slices.Clone(block.PublicKey), slices.Clone(block.Signature)
		beforeBlock.Amount = new(big.Int).Set(block.Amount)
		var readers sync.WaitGroup
		for range 8 {
			readers.Go(func() {
				for range 32 {
					if h.ComputeHash() != wantHeader || block.ComputeHash() != wantAccount {
						t.Error("concurrent immutable reads changed the hash")
					}
				}
			})
		}
		readers.Wait()
		checkHeaderEnvelope(t, h)
		checkAccountEnvelope(t, block)
		if !bytes.Equal(block.Amount.Bytes(), beforeAmount) || !reflect.DeepEqual(h, beforeHeader) || !reflect.DeepEqual(block, beforeBlock) {
			t.Fatal("concurrent reads modified shared input")
		}
	})
}

func FuzzSignedEnvelopeHashSerialization(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{255}, 512))
	f.Add(bytes.Repeat([]byte{2}, 306))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2048 {
			return
		}
		var fixed [306]byte
		copy(fixed[:], raw)
		h := chain.Header{Version: binary.BigEndian.Uint64(fixed[0:8]),
			ChainIdentifier: binary.BigEndian.Uint64(fixed[8:16]), Height: binary.BigEndian.Uint64(fixed[48:56]),
			TimestampUnix: binary.BigEndian.Uint64(fixed[56:64]), NextFusionPrice: binary.BigEndian.Uint64(fixed[160:168]),
			NextWorkPrice: binary.BigEndian.Uint64(fixed[168:176])}
		copy(h.PreviousHash[:], fixed[16:48])
		copy(h.DataHash[:], fixed[64:96])
		copy(h.ContentHash[:], fixed[96:128])
		copy(h.ChangesHash[:], fixed[128:160])
		checkHeaderEnvelope(t, h)
		// Always exercise the v2 suffix even when arbitrary version bytes are not 2.
		h.Version = 2
		checkHeaderEnvelope(t, h)
		b := chain.AccountBlock{Version: binary.BigEndian.Uint64(fixed[0:8]),
			ChainIdentifier: binary.BigEndian.Uint64(fixed[8:16]), BlockType: binary.BigEndian.Uint64(fixed[16:24]),
			Height: binary.BigEndian.Uint64(fixed[56:64]), Amount: new(big.Int).SetBytes(raw),
			FusedPlasma: binary.BigEndian.Uint64(fixed[282:290]), Difficulty: binary.BigEndian.Uint64(fixed[290:298])}
		copy(b.PreviousHash[:], fixed[24:56])
		copy(b.MomentumAcknowledged.Hash[:], fixed[64:96])
		b.MomentumAcknowledged.Height = binary.BigEndian.Uint64(fixed[96:104])
		copy(b.Address[:], fixed[104:124])
		copy(b.ToAddress[:], fixed[124:144])
		copy(b.TokenStandard[:], fixed[176:186])
		copy(b.FromBlockHash[:], fixed[186:218])
		copy(b.DescendantBlocksHash[:], fixed[218:250])
		copy(b.DataHash[:], fixed[250:282])
		copy(b.Nonce[:], fixed[298:306])
		checkAccountEnvelope(t, b)
		b.Amount.Neg(b.Amount)
		checkAccountEnvelope(t, b)
	})
}
