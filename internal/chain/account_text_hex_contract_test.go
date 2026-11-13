package chain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Exact codec bodies from 4a1d03e06c848edebcf611e964e84967d85679d1,
// retained independently of the buffer implementation and expected nibble bytes.
func nonceTextReferenceMarshal(n Nonce) ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

func nonceTextReferenceUnmarshal(n *Nonce, text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*NonceSize {
		return errors.New("chain.Nonce: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(n[:], b)
	return nil
}

func tokenTextReferenceMarshal(token TokenStandard) ([]byte, error) {
	return []byte(hex.EncodeToString(token[:])), nil
}

func tokenTextReferenceUnmarshal(token *TokenStandard, text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*TokenStandardSize {
		return errors.New("chain.TokenStandard: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(token[:], b)
	return nil
}

func TestAccountTextHexContract(t *testing.T) {
	var nonce Nonce
	var token TokenStandard
	for i := range nonce {
		nonce[i] = byte(7*i + 13)
	}
	for i := range token {
		token[i] = byte(11*i + 17)
	}
	values, encoded, lengths := 0, 0, 0
	t.Run("Nonce", func(t *testing.T) {
		v, e, l := chainTextControls(t, nonce, Nonce.MarshalText, nonceTextReferenceMarshal,
			(*Nonce).UnmarshalText, nonceTextReferenceUnmarshal)
		values, encoded, lengths = values+v, encoded+e, lengths+l
	})
	t.Run("TokenStandard", func(t *testing.T) {
		v, e, l := chainTextControls(t, token, TokenStandard.MarshalText, tokenTextReferenceMarshal,
			(*TokenStandard).UnmarshalText, tokenTextReferenceUnmarshal)
		values, encoded, lengths = values+v, encoded+e, lengths+l
	})
	if values != 4608 || encoded != 18432 || lengths != 100 {
		t.Fatal("finite account text coverage changed")
	}
	t.Logf("account-text-hex-controls {\"schema_version\":1,\"types\":2,\"value_position_cases\":%d,\"encoded_byte_cases\":%d,\"length_cases\":%d,\"failure_atomicity\":true,\"input_preservation\":true,\"json_checked\":true}",
		values, encoded, lengths)
}

func FuzzAccountTextHexContract(f *testing.F) {
	for _, text := range [][]byte{nil, []byte("0x"), bytes.Repeat([]byte{'a'}, 16),
		bytes.Repeat([]byte{'F'}, 20), append([]byte("0x"), bytes.Repeat([]byte{'b'}, 16)...),
		append(bytes.Repeat([]byte{'0'}, 19), 255)} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if len(text) > 256 {
			return
		}
		checkChainTextDecode(t, Nonce{1, 2, 3}, text, (*Nonce).UnmarshalText, nonceTextReferenceUnmarshal)
		checkChainTextDecode(t, TokenStandard{4, 5, 6}, text, (*TokenStandard).UnmarshalText, tokenTextReferenceUnmarshal)
	})
}

func BenchmarkAccountTextHex(b *testing.B) {
	b.Run("Nonce", func(b *testing.B) {
		benchmarkChainTextHex(b, Nonce{1, 2, 3}, Nonce.MarshalText, nonceTextReferenceMarshal,
			(*Nonce).UnmarshalText, nonceTextReferenceUnmarshal)
	})
	b.Run("TokenStandard", func(b *testing.B) {
		benchmarkChainTextHex(b, TokenStandard{4, 5, 6}, TokenStandard.MarshalText, tokenTextReferenceMarshal,
			(*TokenStandard).UnmarshalText, tokenTextReferenceUnmarshal)
	})
}
