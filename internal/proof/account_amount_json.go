package proof

import (
	"encoding/json"
	"math/big"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// DefaultMaxAccountAmountBytes bounds CLI parsing before arbitrary-precision
// conversion. Valid node amounts need at most 77 decimal digits; the generous
// token cap also retains invalid-magnitude node conformance vectors. This is a
// parser resource guard, not an amount-validity rule or a total memory limit.
const DefaultMaxAccountAmountBytes = 4 << 10

func (e *evidenceDecoder) accountBlock(d *json.Decoder, block *chain.AccountBlock) error {
	if e.limits.MaxAccountAmountBytes == 0 {
		return d.Decode(block)
	}
	type plain chain.AccountBlock
	wire := struct {
		*plain
		Amount accountAmountJSON `json:"amount"`
	}{plain: (*plain)(block), Amount: accountAmountJSON{
		target: &block.Amount, limit: e.limits.MaxAccountAmountBytes,
	}}
	return d.Decode(&wire)
}

type accountAmountJSON struct {
	target **big.Int
	limit  int
}

func (amount *accountAmountJSON) UnmarshalJSON(raw []byte) error {
	// The enclosing JSON decoder scans the value before this callback. Check
	// every known amount occurrence, including one later replaced by null or
	// another amount, before invoking the legacy big.Int decoder.
	if len(raw) > amount.limit {
		return &BundleByteLimitError{Field: "segments.blocks.amount", Limit: amount.limit}
	}
	return json.Unmarshal(raw, amount.target)
}
