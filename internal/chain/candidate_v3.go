// SPDX-License-Identifier: MIT

package chain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

// CandidateMomentumVersion3 identifies the selected research layout. It does
// not add version 3 to ValidateHeaderVersion or activate a protocol profile.
const CandidateMomentumVersion3 uint64 = 3

// CandidateV3HeaderPreimageSize includes the raw state root after both prices.
const CandidateV3HeaderPreimageSize = 208

// MaxCandidateV3HeaderJSONBytes bounds this projected research representation.
// It is a local codec limit, not an agreed network or state-proof byte budget.
const MaxCandidateV3HeaderJSONBytes = 8 * 1024

// ErrCandidateV3Header classifies format failures without a verifier outcome.
var ErrCandidateV3Header = errors.New("invalid candidate v3 projected header")

// CandidateV3Header is untrusted encoding data, separate from the supported
// v1/v2 Header model and from an owned, accepted verification state. Its hash
// format follows the selected node candidate; decoding or hashing does not
// authenticate a signature, producer, activation, history or state value.
//
// Typed hashing permits unsigned research vectors. JSON additionally requires
// the complete projected envelope, signature widths and a self-consistent hash.
type CandidateV3Header struct {
	Header    Header
	StateRoot Hash
}

// Preimage reconstructs exactly version 3. Unknown versions are refused even
// though the selected node's low-level helper uses a >= 3 layout branch.
// HeaderHash, PublicKey and Signature are outside the signed hash preimage.
func (c CandidateV3Header) Preimage() ([CandidateV3HeaderPreimageSize]byte, error) {
	var preimage [CandidateV3HeaderPreimageSize]byte
	h := c.Header
	if h.Version != CandidateMomentumVersion3 {
		return preimage, fmt.Errorf("%w: version must be exactly 3", ErrCandidateV3Header)
	}
	buf := preimage[:0]
	buf = appendUint64(buf, h.Version)
	buf = appendUint64(buf, h.ChainIdentifier)
	buf = append(buf, h.PreviousHash[:]...)
	buf = appendUint64(buf, h.Height)
	buf = appendUint64(buf, h.TimestampUnix)
	buf = append(buf, h.DataHash[:]...)
	buf = append(buf, h.ContentHash[:]...)
	buf = append(buf, h.ChangesHash[:]...)
	buf = appendUint64(buf, h.NextFusionPrice)
	buf = appendUint64(buf, h.NextWorkPrice)
	buf = append(buf, c.StateRoot[:]...)
	return preimage, nil
}

// ComputeHash performs the candidate's SHA3-256 encoding calculation only.
// The returned digest supplies no verification result or trusted expected root.
func (c CandidateV3Header) ComputeHash() (Hash, error) {
	preimage, err := c.Preimage()
	if err != nil {
		return Hash{}, err
	}
	return Hash(sha3.Sum256(preimage[:])), nil
}

type candidateV3JSONHeader Header

type candidateV3JSON struct {
	candidateV3JSONHeader
	StateRoot Hash `json:"stateRoot"`
}

// DecodeCandidateV3Header bounds the complete document, including whitespace,
// before JSON scanning. A failure returns no partial value. A successful decode
// still returns unauthenticated candidate encoding data.
func DecodeCandidateV3Header(raw []byte) (CandidateV3Header, error) {
	if len(raw) > MaxCandidateV3HeaderJSONBytes {
		return CandidateV3Header{}, fmt.Errorf("%w: JSON byte limit", ErrCandidateV3Header)
	}
	var value CandidateV3Header
	if err := json.Unmarshal(raw, &value); err != nil {
		if errors.Is(err, ErrCandidateV3Header) {
			return CandidateV3Header{}, err
		}
		return CandidateV3Header{}, fmt.Errorf("%w: malformed JSON", ErrCandidateV3Header)
	}
	return value, nil
}

// MarshalJSON emits the flat, complete projected header. Width and hash checks
// establish encoding consistency; they do not validate the signature bytes.
func (c CandidateV3Header) MarshalJSON() ([]byte, error) {
	if err := c.validateWire(); err != nil {
		return nil, err
	}
	return json.Marshal(candidateV3JSON{
		candidateV3JSONHeader: candidateV3JSONHeader(c.Header), StateRoot: c.StateRoot,
	})
}

// UnmarshalJSON accepts each exact projected field once, rejects null and
// trailing input, and publishes the new value only after all checks succeed.
// Hashes require 64 hexadecimal characters; byte fields require the emitted
// padded Base64 form. No existing v1/v2 decoder or persisted schema is changed.
// Use DecodeCandidateV3Header for a whole-document byte limit: encoding/json
// supplies only the object value to this method.
func (c *CandidateV3Header) UnmarshalJSON(raw []byte) error {
	if c == nil || len(raw) > MaxCandidateV3HeaderJSONBytes {
		return fmt.Errorf("%w: nil receiver or JSON byte limit", ErrCandidateV3Header)
	}
	var next CandidateV3Header
	h := &next.Header
	fields := map[string]any{
		"version": &h.Version, "chainIdentifier": &h.ChainIdentifier,
		"hash": &h.HeaderHash, "previousHash": &h.PreviousHash, "height": &h.Height,
		"timestamp": &h.TimestampUnix, "dataHash": &h.DataHash, "contentHash": &h.ContentHash,
		"changesHash": &h.ChangesHash, "publicKey": &h.PublicKey, "signature": &h.Signature,
		"nextFusionPrice": &h.NextFusionPrice, "nextWorkPrice": &h.NextWorkPrice,
		"stateRoot": &next.StateRoot,
	}
	if err := decodeCandidateV3Object(raw, fields); err != nil {
		return fmt.Errorf("%w: %v", ErrCandidateV3Header, err)
	}
	if err := next.validateWire(); err != nil {
		return err
	}
	*c = next
	return nil
}

func (c CandidateV3Header) validateWire() error {
	computed, err := c.ComputeHash()
	if err != nil {
		return err
	}
	if len(c.Header.PublicKey) != ed25519.PublicKeySize || len(c.Header.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: public key or signature width", ErrCandidateV3Header)
	}
	if computed != c.Header.HeaderHash {
		return fmt.Errorf("%w: projected hash mismatch", ErrCandidateV3Header)
	}
	return nil
}

func decodeCandidateV3Object(raw []byte, fields map[string]any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("expected one JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return errors.New("malformed JSON object")
		}
		key, ok := token.(string)
		target, known := fields[key]
		if !ok || !known || seen[key] {
			return errors.New("unknown or duplicate field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return errors.New("malformed JSON field")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s must be non-null", key)
		}
		if err := decodeCandidateV3Field(value, key, target); err != nil {
			// Only known schema names are echoed, never input values or unknown keys.
			return fmt.Errorf("invalid %s", key)
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return errors.New("malformed JSON object")
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if len(seen) != len(fields) {
		return errors.New("missing required field")
	}
	return nil
}

func decodeCandidateV3Field(raw []byte, name string, target any) error {
	switch out := target.(type) {
	case *Hash:
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		if len(text) != 2*HashSize {
			return errors.New("hash width")
		}
		return out.UnmarshalText([]byte(text))
	case *[]byte:
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		width := ed25519.PublicKeySize
		if name == "signature" {
			width = ed25519.SignatureSize
		}
		if len(text) != base64.StdEncoding.EncodedLen(width) {
			return errors.New("encoded byte width")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(decoded) != width || base64.StdEncoding.EncodeToString(decoded) != text {
			return errors.New("byte encoding")
		}
		*out = decoded
		return nil
	default:
		return json.Unmarshal(raw, target)
	}
}
