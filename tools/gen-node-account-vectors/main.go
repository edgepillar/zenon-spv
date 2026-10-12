// Command gen-node-account-vectors records the actual exported node transaction
// method against existing signed fixtures and opaque recording context stubs.
// It creates no keys or signatures, opens no database, and imports no SPV code.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/verifier"
)

const (
	nodeModule  = "github.com/zenon-network/go-zenon"
	nodeVersion = "v0.0.8-alphanet.0.20261009223306-c64ed6279ff1"
	nodeCommit  = "c64ed6279ff1d07335dab0ac36156dec8b5b71e9"
	nodeSum     = "h1:3Vyk+6hw2dcWJLg15JEq7ITFOkaYvrVyI+W8Qb3Jlr4="
	segmentsPin = "1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048"
	amountsPin  = "55e6d89f2ad3a25f7f7a6232fe99a5a572e2937d844fc9a3828d9e4cdad4a6aa"
)

type vector struct {
	Name string          `json:"name"`
	RPC  json.RawMessage `json:"rpc"`
}

type projection struct {
	Version              uint64           `json:"version"`
	ChainIdentifier      uint64           `json:"chainIdentifier"`
	BlockType            uint64           `json:"blockType"`
	Hash                 types.Hash       `json:"hash"`
	PreviousHash         types.Hash       `json:"previousHash"`
	Height               uint64           `json:"height"`
	MomentumAcknowledged types.HashHeight `json:"momentumAcknowledged"`
	Address              string           `json:"address"`
	ToAddress            string           `json:"toAddress"`
	Amount               *big.Int         `json:"amount"`
	TokenStandard        string           `json:"tokenStandard"`
	FromBlockHash        types.Hash       `json:"fromBlockHash"`
	DescendantBlocksHash types.Hash       `json:"descendantBlocksHash"`
	DataHash             types.Hash       `json:"dataHash"`
	FusedPlasma          uint64           `json:"fusedPlasma"`
	Difficulty           uint64           `json:"difficulty"`
	Nonce                string           `json:"nonce"`
	PublicKey            []byte           `json:"publicKey"`
	Signature            []byte           `json:"signature"`
}

type call struct {
	Method     string            `json:"method"`
	Address    string            `json:"address,omitempty"`
	Identifier *types.HashHeight `json:"identifier,omitempty"`
}

// Unexpected chain/store/consensus methods have no implementation. They panic
// and fail generation rather than silently fabricating an authenticated state.
type opaqueAccount struct{ store.Account }
type opaqueMomentum struct{ store.Momentum }
type recordingChain struct {
	chain.Chain
	calls *[]call
}

func (c recordingChain) GetAccountStore(address types.Address, identifier types.HashHeight) store.Account {
	*c.calls = append(*c.calls, call{Method: "GetAccountStore", Address: address.String(), Identifier: &identifier})
	return opaqueAccount{}
}
func (c recordingChain) GetMomentumStore(identifier types.HashHeight) store.Momentum {
	*c.calls = append(*c.calls, call{Method: "GetMomentumStore", Identifier: &identifier})
	return opaqueMomentum{}
}
func (c recordingChain) GetFrontierMomentumStore() store.Momentum {
	*c.calls = append(*c.calls, call{Method: "GetFrontierMomentumStore"})
	return opaqueMomentum{}
}

type observation struct {
	Name           string          `json:"name"`
	Baseline       string          `json:"baseline"`
	Block          json.RawMessage `json:"account_block"`
	Projection     *projection     `json:"block"`
	ComputedHash   *types.Hash     `json:"computed_hash"`
	AmountIsNil    bool            `json:"amount_is_nil"`
	RecomputedHash bool            `json:"recomputed_claimed_hash"`
	Result         string          `json:"node_transaction_result"`
	Error          string          `json:"node_error"`
	Calls          []call          `json:"context_calls"`
}

func readSelected(path, pin string, into any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return fmt.Errorf("selected fixture is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if len(raw) > 128<<10 || hex.EncodeToString(digest[:]) != pin {
		return fmt.Errorf("selected fixture bytes differ")
	}
	return json.Unmarshal(raw, into)
}

func checkNodePin() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("missing node build information")
	}
	for _, dep := range info.Deps {
		if dep.Path == nodeModule {
			if dep.Version != nodeVersion || dep.Sum != nodeSum || dep.Replace != nil {
				return fmt.Errorf("node module pin differs")
			}
			return nil
		}
	}
	return fmt.Errorf("node dependency missing")
}

func invoke(tx *nom.AccountBlockTransaction, calls *[]call) (err error, panicValue any) {
	defer func() { panicValue = recover() }()
	err = verifier.NewAccountBlockVerifier(recordingChain{calls: calls}, nil).AccountBlockTransaction(tx)
	return
}

func record(name, baseline string, b *nom.AccountBlock, recomputed, nilTransaction bool) (observation, error) {
	r := observation{Name: name, Baseline: baseline, RecomputedHash: recomputed, Calls: make([]call, 0)}
	var tx *nom.AccountBlockTransaction
	if !nilTransaction {
		tx = &nom.AccountBlockTransaction{Block: b}
	}
	if b != nil {
		r.AmountIsNil = b.Amount == nil
		hash := b.ComputeHash()
		r.ComputedHash = &hash
		r.Projection = &projection{b.Version, b.ChainIdentifier, b.BlockType, b.Hash, b.PreviousHash,
			b.Height, b.MomentumAcknowledged, hex.EncodeToString(b.Address[:]), hex.EncodeToString(b.ToAddress[:]),
			b.Amount, hex.EncodeToString(b.TokenStandard[:]), b.FromBlockHash, b.DescendantBlocksHash(), types.NewHash(b.Data),
			b.FusedPlasma, b.Difficulty, hex.EncodeToString(b.Nonce.Data[:]), b.PublicKey, b.Signature}
		var err error
		r.Block, err = json.Marshal(b)
		if err != nil {
			return r, err
		}
	}
	err, panicValue := invoke(tx, &r.Calls)
	if b != nil {
		after, e := json.Marshal(b)
		if e != nil || !bytes.Equal(after, r.Block) {
			return r, fmt.Errorf("node method changed selected input")
		}
	}
	if panicValue != nil {
		_, isRuntimeError := panicValue.(runtime.Error)
		if b != nil || len(r.Calls) != 0 || !isRuntimeError ||
			!strings.Contains(fmt.Sprint(panicValue), "nil pointer dereference") {
			return r, fmt.Errorf("unexpected node method panic")
		}
		r.Result, r.Error = "PANIC", "nil_pointer"
		return r, nil
	}
	if b == nil {
		return r, fmt.Errorf("selected nil method call did not panic")
	}
	r.Result = "REJECT"
	switch {
	case err == nil:
		r.Result = "MATCH"
	case errors.Is(err, verifier.ErrABTypeInvalidExternal):
		r.Error = "external_batched_type"
	case errors.Is(err, verifier.ErrABMHeightMissing):
		r.Error = "height_missing"
	case errors.Is(err, verifier.ErrABPrevHashMustBeZero):
		r.Error = "previous_must_be_zero"
	case errors.Is(err, verifier.ErrABPrevHashMissing):
		r.Error = "previous_missing"
	case errors.Is(err, verifier.ErrABMAMustNotBeZero):
		r.Error = "ack_missing"
	case errors.Is(err, verifier.ErrABHashMissing):
		r.Error = "hash_missing"
	case errors.Is(err, verifier.ErrABHashInvalid):
		r.Error = "hash_mismatch"
	case errors.Is(err, verifier.ErrABSignatureMissing):
		r.Error = "signature_missing"
	case errors.Is(err, verifier.ErrABPublicKeyMissing):
		r.Error = "public_key_missing"
	case errors.Is(err, verifier.ErrABSignatureInvalid):
		r.Error = "signature_invalid"
	case errors.Is(err, verifier.ErrABPublicKeyMustBeZero):
		r.Error = "public_key_must_be_zero"
	case errors.Is(err, verifier.ErrABSignatureMustBeZero):
		r.Error = "signature_must_be_zero"
	case errors.Is(err, verifier.ErrABDescendantMustBeZero):
		r.Error = "descendants_must_be_zero"
	default:
		return r, fmt.Errorf("unselected node method error")
	}
	return r, nil
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: gen-node-account-vectors SEGMENTS_FIXTURE AMOUNTS_FIXTURE")
	}
	if err := checkNodePin(); err != nil {
		return err
	}
	var segments struct {
		Segments []struct {
			Vectors []vector `json:"vectors"`
		} `json:"segments"`
	}
	var amounts struct {
		Vectors []vector `json:"vectors"`
	}
	if err := readSelected(os.Args[1], segmentsPin, &segments); err != nil {
		return err
	}
	if err := readSelected(os.Args[2], amountsPin, &amounts); err != nil {
		return err
	}
	var originals []vector
	for _, s := range segments.Segments {
		originals = append(originals, s.Vectors...)
	}
	if len(originals) != 4 || len(amounts.Vectors) != 7 {
		return fmt.Errorf("incomplete selected fixtures")
	}
	originals = append(originals, amounts.Vectors...)
	baselines := make(map[string]json.RawMessage)
	observations := make([]observation, 0, 58)
	appendRecord := func(name, baseline string, edit func(*nom.AccountBlock), recomputed bool) error {
		var b nom.AccountBlock
		if err := json.Unmarshal(baselines[baseline], &b); err != nil {
			return err
		}
		if edit != nil {
			edit(&b)
		}
		if recomputed {
			b.Hash = b.ComputeHash()
		}
		r, err := record(name, baseline, &b, recomputed, false)
		if err == nil {
			observations = append(observations, r)
		}
		return err
	}
	for _, v := range originals {
		if _, exists := baselines[v.Name]; exists {
			return fmt.Errorf("repeated selected baseline")
		}
		baselines[v.Name] = v.RPC
		if err := appendRecord("baseline/"+v.Name, v.Name, nil, false); err != nil {
			return err
		}
	}
	mutations := []struct {
		name string
		edit func(*nom.AccountBlock)
	}{
		{"hash-zero", func(b *nom.AccountBlock) { b.Hash = types.ZeroHash }},
		{"hash-bit", func(b *nom.AccountBlock) { b.Hash[0] ^= 1 }},
		{"data-bit", func(b *nom.AccountBlock) { b.Data = append(b.Data, 255) }},
		{"chain", func(b *nom.AccountBlock) { b.ChainIdentifier++ }},
		{"height-zero", func(b *nom.AccountBlock) { b.Height = 0 }},
		{"height-two-with-zero-parent", func(b *nom.AccountBlock) { b.Height = 2 }},
		{"previous-nonzero-at-one", func(b *nom.AccountBlock) { b.PreviousHash[0] ^= 1 }},
		{"ack-zero", func(b *nom.AccountBlock) { b.MomentumAcknowledged = types.HashHeight{} }},
		{"signature-empty", func(b *nom.AccountBlock) { b.Signature = []byte{} }},
		{"public-key-empty", func(b *nom.AccountBlock) { b.PublicKey = []byte{} }},
		{"both-empty", func(b *nom.AccountBlock) { b.Signature = []byte{}; b.PublicKey = []byte{} }},
		{"public-key-short31", func(b *nom.AccountBlock) { b.PublicKey = b.PublicKey[:31] }},
		{"public-key-long33", func(b *nom.AccountBlock) { b.PublicKey = append(b.PublicKey, 0) }},
		{"signature-short63", func(b *nom.AccountBlock) { b.Signature = b.Signature[:63] }},
		{"signature-long65", func(b *nom.AccountBlock) { b.Signature = append(b.Signature, 0) }},
		{"signature-bit", func(b *nom.AccountBlock) { b.Signature[0] ^= 1 }},
		{"public-key-bit", func(b *nom.AccountBlock) { b.PublicKey[0] ^= 1 }},
		{"changes-hash-bit", func(b *nom.AccountBlock) { b.ChangesHash[0] ^= 1 }},
		{"base-plasma-one", func(b *nom.AccountBlock) { b.BasePlasma = 1 }},
		{"used-plasma-one", func(b *nom.AccountBlock) { b.TotalPlasma = 1 }},
		{"amount-negative", func(b *nom.AccountBlock) { b.Amount.Neg(b.Amount) }},
		{"amount-nil", func(b *nom.AccountBlock) { b.Amount = nil }},
		{"token-bit", func(b *nom.AccountBlock) { b.TokenStandard[0] ^= 1 }},
		{"nonce-bit", func(b *nom.AccountBlock) { b.Nonce.Data[0] ^= 1 }},
		{"difficulty-one", func(b *nom.AccountBlock) { b.Difficulty = 1 }},
		{"fused-plasma-one", func(b *nom.AccountBlock) { b.FusedPlasma = 1 }},
		{"to-address-bit", func(b *nom.AccountBlock) { b.ToAddress[0] ^= 1 }},
		{"from-hash-bit", func(b *nom.AccountBlock) { b.FromBlockHash[0] ^= 1 }},
		{"ack-height", func(b *nom.AccountBlock) { b.MomentumAcknowledged.Height++ }},
	}
	for _, m := range mutations {
		if err := appendRecord("user-type-2/"+m.name, "user-type-2", m.edit, false); err != nil {
			return err
		}
	}
	if err := appendRecord("user-type-3/amount-nil", "user-type-3", func(b *nom.AccountBlock) { b.Amount = nil }, false); err != nil {
		return err
	}
	var user nom.AccountBlock
	if err := json.Unmarshal(baselines["user-type-2"], &user); err != nil {
		return err
	}
	embedded := []struct {
		name string
		edit func(*nom.AccountBlock)
	}{
		{"version-zero", func(b *nom.AccountBlock) { b.Version = 0 }},
		{"version-two", func(b *nom.AccountBlock) { b.Version = 2 }},
		{"type-zero", func(b *nom.AccountBlock) { b.BlockType = 0 }},
		{"type-six", func(b *nom.AccountBlock) { b.BlockType = 6 }},
		{"chain-zero", func(b *nom.AccountBlock) { b.ChainIdentifier = 0 }},
		{"chain-different", func(b *nom.AccountBlock) { b.ChainIdentifier++ }},
		{"receive-amount-one", func(b *nom.AccountBlock) { b.Amount.SetInt64(1) }},
		{"receive-token-nonzero", func(b *nom.AccountBlock) { b.TokenStandard = user.TokenStandard }},
		{"receive-to-nonzero", func(b *nom.AccountBlock) { b.ToAddress = user.Address }},
		{"receive-from-zero", func(b *nom.AccountBlock) { b.FromBlockHash = types.ZeroHash }},
		{"difficulty-one", func(b *nom.AccountBlock) { b.Difficulty = 1 }},
		{"fused-plasma-one", func(b *nom.AccountBlock) { b.FusedPlasma = 1 }},
	}
	for _, m := range embedded {
		if err := appendRecord("embedded-type-5/"+m.name, "embedded-type-5", m.edit, true); err != nil {
			return err
		}
	}
	for _, name := range []string{"public-key-present", "signature-present", "both-present"} {
		if err := appendRecord("embedded-type-5/"+name, "embedded-type-5", func(b *nom.AccountBlock) {
			if name != "signature-present" {
				b.PublicKey = user.PublicKey
			}
			if name != "public-key-present" {
				b.Signature = user.Signature
			}
		}, false); err != nil {
			return err
		}
	}
	for _, name := range []string{"nil-transaction", "nil-block"} {
		r, err := record(name, "", nil, false, name == "nil-transaction")
		if err != nil {
			return err
		}
		observations = append(observations, r)
	}
	if len(observations) != 58 {
		return fmt.Errorf("incomplete observation sequence")
	}
	out := struct {
		FormatVersion int               `json:"format_version"`
		Source        map[string]string `json:"source"`
		Inputs        map[string]string `json:"input_files_sha256"`
		Observations  []observation     `json:"observations"`
		Scope         map[string]bool   `json:"scope"`
	}{1, map[string]string{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit,
		"module_version": nodeVersion, "module_sum": nodeSum, "function": "verifier.AccountBlockVerifier.AccountBlockTransaction"},
		map[string]string{"account-segments.json": segmentsPin, "account-amounts.json": amountsPin}, observations,
		map[string]bool{"actual_node_transaction_execution": true, "synthetic_opaque_context": true,
			"programmatic_nil_inputs": true, "new_signatures_generated": false, "basic_account_block_execution": false,
			"full_node_validation": false, "network_transport": false, "network_activation": false,
			"authenticated_context": false, "canonicality": false, "consensus_finality": false, "state_value_acceptance": false}}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
