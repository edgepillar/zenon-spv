// SPDX-License-Identifier: MIT

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

const (
	ExperimentalV3NodeRevision                   = "938fca3b7787da86827a5eb63371509b36e14761"
	ExperimentalV3ReferenceGasNodeRevision       = "2835c436b197fece5c76adf4ba8dc1decca2e3ea"
	ExperimentalV3Layout                         = "zenon-experimental-momentum-v3-sha3-208"
	MaxExperimentalV3ProfileBytes                = 16 * 1024
	MaxExperimentalV3ScheduleEntries             = 4096
	MaxExperimentalV3StateBytes            int64 = 8 * 1024 * 1024
)

var (
	ErrExperimentalV3Profile  = errors.New("invalid experimental v3 profile")
	ErrExperimentalV3Policy   = errors.New("invalid experimental v3 resource policy")
	ErrExperimentalV3Schedule = errors.New("invalid experimental v3 producer schedule")
)

// ExperimentalV3Profile is an explicitly configured, non-mainnet assertion.
// Genesis identifies the network separately from a possibly later anchor.
// FirstV3Height is an incoming-header height, not a spork enforcement height.
// Source is provenance metadata; neither it nor the selected source revision
// authenticates network identity, activation or the configured trust inputs.
// This schema does not extend the production ProtocolProfile.
type ExperimentalV3Profile struct {
	Version       uint32           `json:"version"`
	Genesis       GenesisTrustRoot `json:"genesis"`
	Anchor        GenesisTrustRoot `json:"anchor"`
	FirstV3Height uint64           `json:"first_v3_height"`
	ValidThrough  uint64           `json:"valid_through"`
	NodeRevision  string           `json:"node_revision"`
	Source        string           `json:"source"`
}

func (p ExperimentalV3Profile) Validate() error {
	if p.Version != 1 || p.Genesis.Validate() != nil || p.Genesis.Height != 1 ||
		p.Genesis.ChainID == MainnetChainID || p.Anchor.Validate() != nil ||
		p.Anchor.ChainID != p.Genesis.ChainID || p.FirstV3Height < 2 ||
		p.Anchor.Height < p.FirstV3Height-1 || p.ValidThrough <= p.Anchor.Height ||
		(p.NodeRevision != ExperimentalV3NodeRevision && p.NodeRevision != ExperimentalV3ReferenceGasNodeRevision) || len(p.Source) > 1024 ||
		strings.TrimSpace(p.Source) == "" || !utf8.ValidString(p.Source) {
		return ErrExperimentalV3Profile
	}
	if p.Anchor.Height == 1 && p.Anchor != p.Genesis {
		return ErrExperimentalV3Profile
	}
	for _, r := range p.Source {
		if unicode.IsControl(r) {
			return ErrExperimentalV3Profile
		}
	}
	return nil
}

func (p *ExperimentalV3Profile) UnmarshalJSON(raw []byte) error {
	if p == nil || len(raw) > MaxExperimentalV3ProfileBytes || !utf8.Valid(raw) {
		return ErrExperimentalV3Profile
	}
	var next ExperimentalV3Profile
	var genesis, anchor json.RawMessage
	if err := decodeRequiredObject(raw, map[string]any{
		"version": &next.Version, "genesis": &genesis, "anchor": &anchor,
		"first_v3_height": &next.FirstV3Height, "valid_through": &next.ValidThrough,
		"node_revision": &next.NodeRevision, "source": &next.Source,
	}); err != nil {
		return ErrExperimentalV3Profile
	}
	var err error
	if next.Genesis, err = decodeExperimentalV3Anchor(genesis); err != nil {
		return err
	}
	if next.Anchor, err = decodeExperimentalV3Anchor(anchor); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	*p = next
	return nil
}

// DecodeExperimentalV3Profile applies the whole-document bound, including
// whitespace. A successful decode is a configuration value, not a state handle.
func DecodeExperimentalV3Profile(raw []byte) (ExperimentalV3Profile, error) {
	if len(raw) > MaxExperimentalV3ProfileBytes {
		return ExperimentalV3Profile{}, ErrExperimentalV3Profile
	}
	var p ExperimentalV3Profile
	if json.Unmarshal(raw, &p) != nil {
		return ExperimentalV3Profile{}, ErrExperimentalV3Profile
	}
	return p, nil
}

func decodeExperimentalV3Anchor(raw []byte) (GenesisTrustRoot, error) {
	var out GenesisTrustRoot
	var text string
	if err := decodeRequiredObject(raw, map[string]any{"chain_id": &out.ChainID, "height": &out.Height, "header_hash": &text}); err != nil {
		return GenesisTrustRoot{}, ErrExperimentalV3Profile
	}
	if len(text) != 64 {
		return GenesisTrustRoot{}, ErrExperimentalV3Profile
	}
	if _, err := hex.Decode(out.HeaderHash[:], []byte(text)); err != nil || hex.EncodeToString(out.HeaderHash[:]) != text {
		return GenesisTrustRoot{}, ErrExperimentalV3Profile
	}
	return out, nil
}

// ExperimentalV3Policy has no disabled or implicit limits. W is retained depth,
// not consensus finality; K bounds available history independently of W.
type ExperimentalV3Policy struct {
	W               uint64 `json:"w"`
	RetainHeaders   uint32 `json:"retain_headers"`
	MaxBatchHeaders uint32 `json:"max_batch_headers"`
}

func (p ExperimentalV3Policy) Validate() error {
	if p.W == 0 || p.W >= uint64(p.RetainHeaders) || p.RetainHeaders > MaxRetainHeaders ||
		p.MaxBatchHeaders == 0 || p.MaxBatchHeaders > MaxRetainHeaders {
		return ErrExperimentalV3Policy
	}
	return nil
}

func (p *ExperimentalV3Policy) UnmarshalJSON(raw []byte) error {
	var next ExperimentalV3Policy
	if p == nil || len(raw) > 1024 {
		return ErrExperimentalV3Policy
	}
	if err := decodeRequiredObject(raw, map[string]any{"w": &next.W, "retain_headers": &next.RetainHeaders, "max_batch_headers": &next.MaxBatchHeaders}); err != nil {
		return ErrExperimentalV3Policy
	}
	if err := next.Validate(); err != nil {
		return err
	}
	*p = next
	return nil
}

// ExperimentalV3Context contains detached substantive settings only. Source and
// schedule peer labels are excluded. Matching fingerprints do not authenticate
// settings, history, a local file or the verifier executable.
type ExperimentalV3Context struct {
	Version        uint32               `json:"version"`
	Layout         string               `json:"layout"`
	Genesis        GenesisTrustRoot     `json:"genesis"`
	Anchor         GenesisTrustRoot     `json:"anchor"`
	FirstV3Height  uint64               `json:"first_v3_height"`
	ValidThrough   uint64               `json:"valid_through"`
	NodeRevision   string               `json:"node_revision"`
	Policy         ExperimentalV3Policy `json:"policy"`
	ScheduleHash   chain.Hash           `json:"schedule_hash"`
	MaxHeaderBytes int                  `json:"max_header_bytes"`
	MaxStateBytes  int64                `json:"max_state_bytes"`
	Fingerprint    chain.Hash           `json:"fingerprint"`
}

// ExperimentalV3Configuration holds validated settings and a private, read-only
// copy of the producer schedule. It contains no accepted headers.
type ExperimentalV3Configuration struct {
	profile  ExperimentalV3Profile
	policy   ExperimentalV3Policy
	schedule *ProducerSchedule
	context  ExperimentalV3Context
}

// ExperimentalV3ContextFor validates and snapshots the selected configuration.
// It returns diagnostic data. Only header verification can populate owned state.
func ExperimentalV3ContextFor(profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule) (ExperimentalV3Context, error) {
	c, err := PrepareExperimentalV3Configuration(profile, policy, schedule)
	if err != nil {
		return ExperimentalV3Context{}, err
	}
	return c.Context(), nil
}

// PrepareExperimentalV3Configuration validates and captures one configuration
// for diagnostic context, empty state construction and read-only checkpoint use.
func PrepareExperimentalV3Configuration(profile ExperimentalV3Profile, policy ExperimentalV3Policy, schedule *ProducerSchedule) (ExperimentalV3Configuration, error) {
	if err := profile.Validate(); err != nil {
		return ExperimentalV3Configuration{}, err
	}
	if err := policy.Validate(); err != nil {
		return ExperimentalV3Configuration{}, err
	}
	if schedule == nil || schedule.ChainID != profile.Genesis.ChainID ||
		len(schedule.Entries) == 0 || len(schedule.Entries) > MaxExperimentalV3ScheduleEntries || len(schedule.Coverage) > MaxExperimentalV3ScheduleEntries {
		return ExperimentalV3Configuration{}, ErrExperimentalV3Schedule
	}
	frozen := &ProducerSchedule{ChainID: schedule.ChainID, ScheduleHash: schedule.ScheduleHash,
		Coverage: append([]ProducerCoverage(nil), schedule.Coverage...), Entries: append([]ProducerEntry(nil), schedule.Entries...)}
	if frozen.Validate() != nil {
		return ExperimentalV3Configuration{}, ErrExperimentalV3Schedule
	}
	c := ExperimentalV3Context{Version: 1, Layout: ExperimentalV3Layout, Genesis: profile.Genesis, Anchor: profile.Anchor,
		FirstV3Height: profile.FirstV3Height, ValidThrough: profile.ValidThrough, NodeRevision: profile.NodeRevision,
		Policy: policy, ScheduleHash: frozen.ScheduleHash, MaxHeaderBytes: chain.MaxCandidateV3HeaderJSONBytes, MaxStateBytes: MaxExperimentalV3StateBytes}
	var b bytes.Buffer
	b.WriteString("ZENON-EXPERIMENTAL-V3-CONTEXT\x00\x01")
	appendWord := func(v uint64) { var word [8]byte; binary.BigEndian.PutUint64(word[:], v); b.Write(word[:]) }
	for _, a := range []GenesisTrustRoot{c.Genesis, c.Anchor} {
		appendWord(a.ChainID)
		appendWord(a.Height)
		b.Write(a.HeaderHash[:])
	}
	for _, v := range []uint64{uint64(c.Version), c.FirstV3Height, c.ValidThrough, c.Policy.W, uint64(c.Policy.RetainHeaders), uint64(c.Policy.MaxBatchHeaders), uint64(c.MaxHeaderBytes), uint64(c.MaxStateBytes)} {
		appendWord(v)
	}
	node, _ := hex.DecodeString(c.NodeRevision)
	b.Write(node)
	b.Write(c.ScheduleHash[:])
	c.Fingerprint = chain.Hash(sha3.Sum256(b.Bytes()))
	return ExperimentalV3Configuration{profile: profile, policy: policy, schedule: frozen, context: c}, nil
}

// Context returns detached diagnostic data for the prepared settings.
func (c ExperimentalV3Configuration) Context() ExperimentalV3Context { return c.context }
