package main

import "slices"

const inclusion = "CONTENT_INCLUSION"

var guarantees = []string{"HEADER_CHAIN_INTEGRITY", "SIGNATURE_AUTHENTICITY", inclusion, "PRODUCER_AUTHORIZATION"}
var allGuarantees = append(slices.Clone(guarantees), "CANONICALITY", "STATE_TRANSITION", "STATE_VALUE_INCLUSION")
var trustNames = []string{
	"TRUST_CONFIGURED_ANCHOR", "TRUST_PERSISTED_STATE", "TRUST_EXTERNAL_PROTOCOL_PROFILE",
	"TRUST_CHECKPOINT_ANCHOR", "TRUST_RPC_QUORUM", "TRUST_EXTERNAL_PRODUCER_SCHEDULE", "TRUST_RETAINED_WINDOW_DEPTH",
}

type hashHeight struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
}

type accountHeader struct {
	Address string `json:"address"`
	Height  uint64 `json:"height"`
	Hash    string `json:"hash"`
}

type reference struct {
	Scope          string        `json:"scope"`
	Index          uint64        `json:"index"`
	BlockIndex     *uint64       `json:"block_index,omitempty"`
	MomentumHeight *uint64       `json:"momentum_height,omitempty"`
	Account        accountHeader `json:"account_header"`
}

type expectations struct {
	Version      uint32      `json:"schema_version"`
	Command      string      `json:"command"`
	Context      string      `json:"context_fingerprint"`
	Tip          hashHeight  `json:"verification_tip"`
	Targets      []reference `json:"targets"`
	Required     []string    `json:"required_guarantees"`
	AllowedTrust []string    `json:"allowed_trust_assumptions"`
}

type queryReport struct {
	Version  uint32 `json:"schema_version"`
	Command  string `json:"command"`
	Mode     string `json:"mode"`
	ExitCode int64  `json:"exit_code"`
	Outcome  string `json:"outcome"`
	Error    *struct {
		Stage    string `json:"stage"`
		Category string `json:"category"`
	} `json:"error"`
	Persistence string     `json:"persistence"`
	Context     settings   `json:"verification_context"`
	Tip         hashHeight `json:"verification_tip"`
	StateTrust  []string   `json:"state_trust"`
	Results     []row      `json:"results"`
	Caveats     []string   `json:"caveats"`
}

type row struct {
	Reference reference `json:"reference"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason"`
	FailedAt  int64     `json:"failed_at"`
	Proven    []string  `json:"proven"`
	NotProven []string  `json:"not_proven"`
	Trust     []string  `json:"trust_assumptions"`
}

type position struct {
	scope string
	index uint64
	block uint64
}

func referencePosition(r reference) position {
	p := position{scope: r.Scope, index: r.Index}
	if r.BlockIndex != nil {
		p.block = *r.BlockIndex
	}
	return p
}

func validReference(r reference, command string) bool {
	if !hexString(r.Account.Address, 40) || !hexString(r.Account.Hash, 64) {
		return false
	}
	switch command {
	case "verify-commitment":
		return r.Scope == "commitment" && r.MomentumHeight != nil && r.BlockIndex == nil
	case "verify-segment":
		return r.Scope == "segment" && r.BlockIndex != nil && *r.BlockIndex <= 1<<63-1 && r.MomentumHeight == nil
	}
	return false
}

func validExpectations(e expectations) bool {
	if e.Version != 1 || !hexString(e.Context, 64) || !validTip(e.Tip) || len(e.Targets) == 0 || len(e.Targets) > maxTargets ||
		!validSet(e.Required, guarantees) || !slices.Contains(e.Required, inclusion) || !validSet(e.AllowedTrust, trustNames) {
		return false
	}
	seen := make(map[position]bool)
	for _, r := range e.Targets {
		key := referencePosition(r)
		if !validReference(r, e.Command) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func validReport(r queryReport) bool {
	if r.Version != 1 || !validContext(r.Context) || !validTip(r.Tip) || len(r.Results) == 0 || len(r.Results) > maxTargets || !validSet(r.StateTrust, trustNames) {
		return false
	}
	seen := make(map[position]bool)
	for _, item := range r.Results {
		key := referencePosition(item.Reference)
		if !validReference(item.Reference, r.Command) || seen[key] || !validSet(item.Proven, guarantees) ||
			!validSet(item.NotProven, allGuarantees) || !validSet(item.Trust, trustNames) {
			return false
		}
		for _, proven := range item.Proven {
			if slices.Contains(item.NotProven, proven) {
				return false
			}
		}
		seen[key] = true
	}
	return true
}

func matchReport(r queryReport, e expectations) string {
	if r.Command != e.Command || r.Mode != "retained_only" || r.Persistence != "read_only" || r.ExitCode != 0 ||
		r.Error != nil || r.Outcome != "ACCEPT" || r.Context.Fingerprint != e.Context || r.Tip != e.Tip {
		return "report_mismatch"
	}
	if !allowedTrust(r.StateTrust, e.AllowedTrust) {
		return "trust_mismatch"
	}
	if len(r.Results) != len(e.Targets) {
		return "target_mismatch"
	}
	expected := make(map[position]reference, len(e.Targets))
	for _, target := range e.Targets {
		expected[referencePosition(target)] = target
	}
	for _, item := range r.Results {
		ref := item.Reference
		target, ok := expected[referencePosition(ref)]
		if !ok || !sameReference(ref, target) {
			return "target_mismatch"
		}
		failedAt := int64(-1)
		if ref.BlockIndex != nil {
			failedAt = int64(*ref.BlockIndex)
		}
		if item.Outcome != "ACCEPT" || item.Reason != "ReasonOK" || item.FailedAt != failedAt {
			return "report_mismatch"
		}
		for _, required := range e.Required {
			if !slices.Contains(item.Proven, required) {
				return "guarantee_mismatch"
			}
		}
		if !allowedTrust(item.Trust, e.AllowedTrust) {
			return "trust_mismatch"
		}
	}
	return ""
}

func sameReference(a, b reference) bool {
	return a.Scope == b.Scope && a.Index == b.Index && a.Account == b.Account &&
		sameOptional(a.BlockIndex, b.BlockIndex) && sameOptional(a.MomentumHeight, b.MomentumHeight)
}

func sameOptional(a, b *uint64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func validTip(t hashHeight) bool { return t.Height > 0 && hexString(t.Hash, 64) && nonzeroHex(t.Hash) }

func validSet(values, known []string) bool {
	seen := make(map[string]bool)
	for _, v := range values {
		if seen[v] || !slices.Contains(known, v) {
			return false
		}
		seen[v] = true
	}
	return true
}

func allowedTrust(values, allowed []string) bool {
	if !slices.Contains(values, "TRUST_CONFIGURED_ANCHOR") || !slices.Contains(values, "TRUST_PERSISTED_STATE") {
		return false
	}
	for _, v := range values {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}

func hexString(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		digit := c >= '0' && c <= '9'
		lowerHex := c >= 'a' && c <= 'f'
		if !digit && !lowerHex {
			return false
		}
	}
	return true
}

func nonzeroHex(value string) bool {
	for _, c := range value {
		if c != '0' {
			return true
		}
	}
	return false
}
