package fetch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// These transport guardrails bound decoded nested entries, independently of
// MaxResponseBytes and the requested block count. They are not consensus limits.
// The per-list cap matches the default verifier's flat-content member ceiling.
const (
	MaxEvidenceListMembers     = 100_000
	MaxResponseEvidenceMembers = 1_000_000
)

// ErrResponseTooComplex marks a response whose nested evidence exceeds a
// decoding guardrail. It is unusable for quorum and returns no partial evidence.
var ErrResponseTooComplex = errors.New("rpc response exceeds decoded entry limit")

// One decoder belongs to one response or complete paginated range, never to the
// reusable Client. A failed decode can consume this budget; all rows are discarded.
type rpcEvidenceDecoder struct {
	maxMembers int
	remaining  int
}

func newRPCEvidenceDecoder() *rpcEvidenceDecoder {
	return &rpcEvidenceDecoder{maxMembers: MaxEvidenceListMembers, remaining: MaxResponseEvidenceMembers}
}

func (d *rpcEvidenceDecoder) momentum(target *rpcMomentum) any {
	return &rpcMomentumDecoder{target: target, evidence: d}
}

func (d *rpcEvidenceDecoder) account(target *rpcAccountBlock) any {
	return &rpcAccountDecoder{target: target, evidence: d}
}

type rpcMomentumDecoder struct {
	target   *rpcMomentum
	evidence *rpcEvidenceDecoder
}

func (d *rpcMomentumDecoder) UnmarshalJSON(raw []byte) error {
	type momentumWire rpcMomentum
	var decoded momentumWire
	wire := struct {
		*momentumWire
		Content rpcEvidenceMembers[rpcAccountHdr] `json:"content"`
	}{&decoded, rpcEvidenceMembers[rpcAccountHdr]{decoder: d.evidence, field: "content"}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	decoded.Content = wire.Content.rows
	*d.target = rpcMomentum(decoded)
	return nil
}

type rpcAccountDecoder struct {
	target   *rpcAccountBlock
	evidence *rpcEvidenceDecoder
}

func (d *rpcAccountDecoder) UnmarshalJSON(raw []byte) error {
	type accountWire rpcAccountBlock
	var decoded accountWire
	wire := struct {
		*accountWire
		DescendantBlocks rpcEvidenceMembers[rpcDescendant] `json:"descendantBlocks"`
	}{&decoded, rpcEvidenceMembers[rpcDescendant]{decoder: d.evidence, field: "descendantBlocks"}}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	decoded.DescendantBlocks = wire.DescendantBlocks.rows
	*d.target = rpcAccountBlock(decoded)
	return nil
}

type rpcEvidenceMembers[T any] struct {
	decoder *rpcEvidenceDecoder
	field   string // Fixed by the caller, never copied from a remote field name.
	rows    []T
	seen    bool
}

func (members *rpcEvidenceMembers[T]) UnmarshalJSON(raw []byte) error {
	if members.seen {
		return fmt.Errorf("%w: duplicate %s list", ErrInvalidRPCResponse, members.field)
	}
	members.seen = true
	// The enclosing json.Unmarshal has already validated the whole JSON value.
	// Count its top-level array members before allocating any entry structs.
	// Using a decoder per entry would add allocations even for tiny null rows.
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		members.rows = nil
		return nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return fmt.Errorf("%w: %s must be an array or null", ErrInvalidRPCResponse, members.field)
	}
	count, depth := 0, 0
	quoted, next := false, true
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if quoted {
			switch c {
			case '\\':
				i++ // Escaped quotes and backslashes cannot end a JSON string.
			case '"':
				quoted = false
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if next {
			if count >= members.decoder.maxMembers || count >= members.decoder.remaining {
				return fmt.Errorf("%w: %s", ErrResponseTooComplex, members.field)
			}
			count++
			next = false
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			next = depth == 0
		}
	}
	var rows []T
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	members.decoder.remaining -= count
	members.rows = rows
	return nil
}
