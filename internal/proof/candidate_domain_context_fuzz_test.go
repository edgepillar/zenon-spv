// SPDX-License-Identifier: MIT

package proof_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/0x3639/zenon-spv/internal/proof"
)

// This independent encoder also checks every accepted fuzz result against the
// same canonical word/tail representation as the original-node byte corpus.
func candidateDomainReencode(value proof.CandidateDomainRecord) []byte {
	head := make([]byte, 12*32)
	for _, field := range []struct {
		index int
		value uint8
	}{
		{0, value.DomainClass}, {1, value.RuntimeKind}, {3, value.InputSource},
		{4, value.ExecProfile}, {5, value.ForeignProfile}, {8, value.MinExecutors},
		{9, value.ProposerPolicy}, {10, value.FinalityModel}, {11, value.Status},
	} {
		head[field.index*32+31] = field.value
	}
	copy(head[64:96], value.StfSpecHash[:])
	var tails []byte
	for i, field := range [][]byte{value.ProfileConfig, value.ChainBinding} {
		binary.BigEndian.PutUint64(head[(6+i)*32+24:], uint64(len(head)+len(tails)))
		word := make([]byte, 32)
		binary.BigEndian.PutUint64(word[24:], uint64(len(field)))
		tails = append(tails, word...)
		tails = append(tails, field...)
		tails = append(tails, make([]byte, (-len(field))&31)...)
	}
	return append(head, tails...)
}

func FuzzCandidateDomainContextDecode(f *testing.F) {
	facts := candidateDomainVectors(f)
	for _, v := range facts.Records {
		f.Add(candidateDomainHex(f, v.Packed))
	}
	for _, v := range facts.Configs {
		f.Add(candidateDomainHex(f, v.Packed))
	}
	f.Add([]byte{})
	f.Add(make([]byte, 4097))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := proof.DecodeCandidateDomainRecord(raw, candidateDomainLimits())
		if err != nil {
			if (!errors.Is(err, proof.ErrCandidateDomainBounds) && !errors.Is(err, proof.ErrCandidateDomainEncoding)) || !reflect.DeepEqual(got, proof.CandidateDomainRecord{}) {
				t.Fatal("record error returned partial data or an unknown category")
			}
		} else if !bytes.Equal(candidateDomainReencode(got), raw) {
			t.Fatal("accepted record differs from independent canonical encoding")
		}
		config, configErr := proof.DecodeCandidateDomainConfig(raw)
		if configErr != nil {
			if !errors.Is(configErr, proof.ErrCandidateDomainEncoding) || config != (proof.CandidateDomainConfig{}) {
				t.Fatal("config error returned partial data or an unknown category")
			}
		} else {
			encoded := make([]byte, 64)
			binary.BigEndian.PutUint64(encoded[24:], config.WithdrawalDelay)
			binary.BigEndian.PutUint64(encoded[56:], config.RuntimeUpgradeDelay)
			if !bytes.Equal(encoded, raw) {
				t.Fatal("accepted config differs from independent canonical encoding")
			}
		}
	})
}
