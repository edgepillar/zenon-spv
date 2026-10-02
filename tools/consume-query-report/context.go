package main

import (
	"encoding/binary"
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// This is a diagnostic schema, not a deserializable verifier state. Encode its
// settings independently according to docs/verification-context.md. Matching a
// digest does not authenticate any trust input, executable or report channel.
type settings struct {
	Version           uint32 `json:"schema_version"`
	Fingerprint       string `json:"fingerprint"`
	FingerprintStatus string `json:"fingerprint_status"`
	Anchor            struct {
		ChainID uint64 `json:"chain_id"`
		Height  uint64 `json:"height"`
		Hash    string `json:"header_hash"`
	} `json:"anchor"`
	Policy struct {
		W                uint64 `json:"w"`
		RetainHeaders    *int64 `json:"retain_headers,omitempty"`
		BundleBytes      int64  `json:"max_bundle_bytes"`
		Headers          int64  `json:"max_headers"`
		Commitments      int64  `json:"max_commitments"`
		FlatMembers      int64  `json:"max_flat_evidence_members"`
		TotalFlatMembers int64  `json:"max_total_flat_evidence_members"`
		Segments         int64  `json:"max_segments"`
		SegmentBlocks    int64  `json:"max_segment_blocks"`
		TotalBlocks      int64  `json:"max_total_segment_blocks"`
		StateProofs      int64  `json:"max_state_value_proofs"`
		StateNodes       int64  `json:"max_state_proof_nodes"`
		StateBytes       int64  `json:"max_state_proof_bytes"`
	} `json:"policy"`
	Profile *struct {
		Version      uint32 `json:"version"`
		ValidThrough uint64 `json:"valid_through"`
		V2FromHeight uint64 `json:"v2_from_height"`
	} `json:"protocol_profile"`
	Producer struct {
		Mode         string  `json:"mode"`
		Source       string  `json:"source"`
		Kind         string  `json:"kind"`
		ScheduleHash *string `json:"schedule_hash"`
	} `json:"producer"`
	Checkpoints []struct {
		Height uint64 `json:"height"`
		Hash   string `json:"header_hash"`
	} `json:"checkpoints"`
}

func resourceLimits(c settings) []int64 {
	p := c.Policy
	return []int64{p.BundleBytes, p.Headers, p.Commitments, p.FlatMembers, p.TotalFlatMembers,
		p.Segments, p.SegmentBlocks, p.TotalBlocks, p.StateProofs, p.StateNodes, p.StateBytes}
}

func validContext(c settings) bool {
	if c.Version != 1 && c.Version != 2 || c.FingerprintStatus != "available" || !hexString(c.Fingerprint, 64) ||
		c.Anchor.Height == 0 || !hexString(c.Anchor.Hash, 64) || !nonzeroHex(c.Anchor.Hash) || c.Policy.W == 0 {
		return false
	}
	if c.Version == 1 && c.Policy.RetainHeaders != nil || c.Version == 2 && (c.Policy.RetainHeaders == nil || *c.Policy.RetainHeaders <= 0) {
		return false
	}
	for _, limit := range resourceLimits(c) {
		if limit < 0 {
			return false
		}
	}
	if c.Profile != nil && (c.Profile.Version != 1 || c.Profile.ValidThrough < c.Anchor.Height) {
		return false
	}
	p := c.Producer
	if p.Mode == "Disabled" {
		if p.Source != "None" || p.Kind != "disabled" || p.ScheduleHash != nil {
			return false
		}
	} else if p.Mode != "Required" || p.Kind != "schedule" ||
		(p.Source != "OperatorAttested" && p.Source != "LocallyDerivedFromChain") ||
		p.ScheduleHash == nil || !hexString(*p.ScheduleHash, 64) || !nonzeroHex(*p.ScheduleHash) {
		return false
	}
	var previous uint64
	for _, cp := range c.Checkpoints {
		if cp.Height <= previous || !hexString(cp.Hash, 64) || !nonzeroHex(cp.Hash) {
			return false
		}
		previous = cp.Height
	}
	return settingsFingerprint(c) == c.Fingerprint
}

// Only called for validated hash strings. The order and full-width encoding
// are intentionally independent of the verifier's private implementation.
func settingsFingerprint(c settings) string {
	domain := "zenon-spv/verification-context/v1\x00"
	if c.Version == 2 {
		domain = "zenon-spv/verification-context/v2\x00"
	}
	raw := []byte(domain)
	u64 := func(v uint64) { raw = binary.BigEndian.AppendUint64(raw, v) }
	text := func(v string) { u64(uint64(len(v))); raw = append(raw, v...) }
	hash := func(v string) { b, _ := hex.DecodeString(v); raw = append(raw, b...) }
	u64(uint64(c.Version))
	u64(c.Anchor.ChainID)
	u64(c.Anchor.Height)
	hash(c.Anchor.Hash)
	u64(c.Policy.W)
	if c.Version == 2 {
		u64(uint64(*c.Policy.RetainHeaders))
	}
	for _, limit := range resourceLimits(c) {
		u64(uint64(limit))
	}
	if c.Profile == nil {
		u64(0)
	} else {
		u64(1)
		u64(uint64(c.Profile.Version))
		u64(c.Profile.ValidThrough)
		u64(c.Profile.V2FromHeight)
	}
	text(c.Producer.Mode)
	text(c.Producer.Source)
	text(c.Producer.Kind)
	if c.Producer.ScheduleHash == nil {
		u64(0)
	} else {
		u64(1)
		hash(*c.Producer.ScheduleHash)
	}
	u64(uint64(len(c.Checkpoints)))
	for _, cp := range c.Checkpoints {
		u64(cp.Height)
		hash(cp.Hash)
	}
	digest := sha3.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
