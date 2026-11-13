// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// These are local candidate-decoding budgets, not agreed network limits.
const (
	MaxCandidateV3MomentumJSONBytes      = 256 * 1024
	MaxCandidateV3MomentumDataBytes      = 16 * 1024
	MaxCandidateV3MomentumContentMembers = 1024
)

// ErrCandidateV3Momentum classifies an unusable raw candidate envelope. Errors
// deliberately omit remote values, field names and addresses.
var ErrCandidateV3Momentum = errors.New("invalid candidate v3 RPC momentum")

// CandidateV3Momentum is untrusted encoding data. Producer is locally derived
// from the public key and compared with the wire claim. Neither this comparison
// nor a consistent hash authenticates a signature, producer schedule, network,
// activation, retained context or state value. No production RPC path uses it.
type CandidateV3Momentum struct {
	Header   chain.CandidateV3Header
	Content  []chain.AccountHeader
	Producer chain.Address
}

// DecodeCandidateV3Momentum projects one complete selected-node result object,
// not a JSON-RPC wrapper. It requires every exact field once and derives data
// and content hashes from raw bytes. Content order is preserved: the selected
// node's low-level MomentumContent.Hash hashes the received sequence. Sorting
// here would change the signed preimage. A failure returns no partial result.
//
// Signatures must have the correct width and encoding but are not verified.
// Genesis/v1/v2 and unknown versions are outside this candidate-only format.
func DecodeCandidateV3Momentum(raw []byte) (CandidateV3Momentum, error) {
	if len(raw) > MaxCandidateV3MomentumJSONBytes {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	var next CandidateV3Momentum
	h := &next.Header.Header
	var data, publicKey, signature, content json.RawMessage
	var producer string
	fields := map[string]any{
		"version": &h.Version, "chainIdentifier": &h.ChainIdentifier,
		"hash": &h.HeaderHash, "previousHash": &h.PreviousHash,
		"height": &h.Height, "timestamp": &h.TimestampUnix,
		"data": &data, "content": &content, "changesHash": &h.ChangesHash,
		"publicKey": &publicKey, "signature": &signature,
		"nextFusionPrice": &h.NextFusionPrice, "nextWorkPrice": &h.NextWorkPrice,
		"stateRoot": &next.Header.StateRoot, "producer": &producer,
	}
	if err := decodeCandidateRPCObject(raw, fields); err != nil || h.Version != chain.CandidateMomentumVersion3 {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	decodedData, err := decodeCandidateRPCBytes(data, 0, MaxCandidateV3MomentumDataBytes)
	if err != nil {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	h.DataHash = chain.Hash(sha3.Sum256(decodedData))
	if h.PublicKey, err = decodeCandidateRPCBytes(publicKey, ed25519.PublicKeySize, ed25519.PublicKeySize); err != nil {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	if h.Signature, err = decodeCandidateRPCBytes(signature, ed25519.SignatureSize, ed25519.SignatureSize); err != nil {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	if next.Content, err = decodeCandidateRPCContent(content); err != nil {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	digest := sha3.New256()
	for _, member := range next.Content {
		if _, err := digest.Write(member.Bytes()); err != nil {
			return CandidateV3Momentum{}, ErrCandidateV3Momentum
		}
	}
	copy(h.ContentHash[:], digest.Sum(nil))
	next.Producer, err = decodeCandidateRPCAddress(producer)
	if err != nil || next.Producer != chain.PubKeyToAddress(h.PublicKey) {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	computed, err := next.Header.ComputeHash()
	if err != nil || computed != h.HeaderHash {
		return CandidateV3Momentum{}, ErrCandidateV3Momentum
	}
	return next, nil
}

func decodeCandidateRPCObject(raw []byte, fields map[string]any) error {
	return decodeCandidateRPCObjectNullable(raw, fields)
}

// Only explicitly named schema fields may be null. Existing v3 envelopes
// continue to require every member to be non-null.
func decodeCandidateRPCObjectNullable(raw []byte, fields map[string]any, nullable ...string) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if start, err := d.Token(); err != nil || start != json.Delim('{') {
		return ErrCandidateV3Momentum
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return ErrCandidateV3Momentum
		}
		key, ok := token.(string)
		target, known := fields[key]
		if !ok || !known || seen[key] {
			return ErrCandidateV3Momentum
		}
		seen[key] = true
		allowNull := false
		for _, name := range nullable {
			allowNull = allowNull || name == key
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !allowNull) {
			return ErrCandidateV3Momentum
		}
		if hash, ok := target.(*chain.Hash); ok {
			decoded, err := decodeCandidateRPCHash(value)
			if err != nil {
				return ErrCandidateV3Momentum
			}
			*hash = decoded
		} else if err := json.Unmarshal(value, target); err != nil {
			return ErrCandidateV3Momentum
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != len(fields) {
		return ErrCandidateV3Momentum
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return ErrCandidateV3Momentum
	}
	return nil
}

// A valid hash has 64 ASCII digits. JSON may spell each digit with a six-byte
// Unicode escape, so this bound preserves escaped values while refusing large
// tokens before json.Unmarshal allocates their decoded string. Keep decoding
// the original bytes: trimming non-JSON Unicode whitespace must not admit it.
func decodeCandidateRPCHash(raw []byte) (chain.Hash, error) {
	const digits = 2 * chain.HashSize
	if len(bytes.TrimSpace(raw)) > 2+6*digits {
		return chain.Hash{}, ErrCandidateV3Momentum
	}
	var text string
	if json.Unmarshal(raw, &text) != nil || len(text) != digits {
		return chain.Hash{}, ErrCandidateV3Momentum
	}
	for i := range text {
		if c := text[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return chain.Hash{}, ErrCandidateV3Momentum
		}
	}
	var decoded chain.Hash
	if _, err := hex.Decode(decoded[:], []byte(text)); err != nil {
		return chain.Hash{}, ErrCandidateV3Momentum
	}
	return decoded, nil
}

func decodeCandidateRPCBytes(raw []byte, minimum, maximum int) ([]byte, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil || len(text) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, ErrCandidateV3Momentum
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != text {
		return nil, ErrCandidateV3Momentum
	}
	return decoded, nil
}

func decodeCandidateRPCAddress(text string) (chain.Address, error) {
	if len(text) != 40 || text != strings.ToLower(text) {
		return chain.Address{}, ErrCandidateV3Momentum
	}
	decoded, err := DecodeZenonAddress(text)
	if err != nil {
		return chain.Address{}, ErrCandidateV3Momentum
	}
	return chain.Address(decoded), nil
}

func decodeCandidateRPCContent(raw []byte) ([]chain.AccountHeader, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if start, err := d.Token(); err != nil || start != json.Delim('[') {
		return nil, ErrCandidateV3Momentum
	}
	members := make([]chain.AccountHeader, 0)
	for d.More() {
		if len(members) >= MaxCandidateV3MomentumContentMembers {
			return nil, ErrCandidateV3Momentum
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, ErrCandidateV3Momentum
		}
		var member chain.AccountHeader
		var address string
		if err := decodeCandidateRPCObject(value, map[string]any{"address": &address, "height": &member.Height, "hash": &member.Hash}); err != nil {
			return nil, err
		}
		var err error
		if member.Address, err = decodeCandidateRPCAddress(address); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	if end, err := d.Token(); err != nil || end != json.Delim(']') {
		return nil, ErrCandidateV3Momentum
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, ErrCandidateV3Momentum
	}
	return members, nil
}
