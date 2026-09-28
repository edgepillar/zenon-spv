package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Mainnet genesis trust root for Zenon Network of Momentum (chain_id=1).
//
// Source: ledger.getMomentumByHash on https://my.hc1node.com:35997
// (fetched 2026-04-28). The hash recomputes from the signed envelope —
// see zenon-spv-vault/notes/mainnet-genesis.md for the proof and
// zenon-spv-vault/decisions/0002-genesis-trust-anchor.md for the
// trust-anchor decision.
//
// Mirrors nom.Momentum.ComputeHash with version=1, chain_id=1,
// height=1, previous_hash=zero, timestamp=1637755200 (2021-11-24
// 12:00:00 UTC), the embedded data field, and the SHA3-256 of the
// sorted account-header content.
const (
	MainnetChainID    uint64 = 1
	MainnetHeight     uint64 = 1
	mainnetHeaderHash        = "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0"
)

// mainnetTrustRoot is the parsed embedded mainnet anchor. It is a
// package var (not const) only because chain.Hash isn't a const-able
// type; it's set once at init and never mutated.
var mainnetTrustRoot = mustHash(mainnetHeaderHash)

// MainnetGenesis returns the embedded mainnet trust anchor.
//
// Per zenon-spv-vault/spec/spv-implementation-guide.md §2.1, an SPV
// MUST ship with or be configured with a genesis trust root. The
// embedded value here is the *default*; callers may override at
// runtime via LoadGenesisFromConfig (e.g. for testnet, devnet, or to
// pin a different anchor for stronger weak-subjectivity guarantees).
func MainnetGenesis() (GenesisTrustRoot, error) {
	return GenesisTrustRoot{
		ChainID:    MainnetChainID,
		Height:     MainnetHeight,
		HeaderHash: mainnetTrustRoot,
	}, nil
}

// GenesisTrustRoot is the bootstrap anchor the verifier extends from.
// Per spec/spv-implementation-guide.md §2.1, an SPV MUST ship with or
// be configured with a genesis hash and chain identifier.
type GenesisTrustRoot struct {
	ChainID    uint64     `json:"chain_id"`
	Height     uint64     `json:"height"`
	HeaderHash chain.Hash `json:"header_hash"`
}

// MaxGenesisConfigBytes bounds the entire anchor file, including whitespace.
const MaxGenesisConfigBytes = 16 * 1024

var (
	ErrInvalidGenesis        = errors.New("invalid genesis trust root")
	ErrGenesisConfigTooLarge = errors.New("genesis config exceeds 16 KiB")
)

// Validate checks structural anchor requirements, not provenance or finality.
// Chain ID zero remains available for explicitly configured custom networks.
func (g GenesisTrustRoot) Validate() error {
	if g.Height == 0 || g.HeaderHash.IsZero() {
		return fmt.Errorf("%w: nonzero anchor hash and height required", ErrInvalidGenesis)
	}
	return nil
}

// LoadGenesisFromConfig accepts one bounded JSON object with all three fields
// explicitly present and non-null. Unknown, duplicate, or differently cased
// field names are rejected. Loading an anchor does not authenticate its source.
//
//	{
//	  "chain_id":    1,
//	  "height":      1,
//	  "header_hash": "<64-hex-chars>"
//	}
func LoadGenesisFromConfig(path string) (GenesisTrustRoot, error) {
	f, err := os.Open(path)
	if err != nil {
		return GenesisTrustRoot{}, fmt.Errorf("read genesis config: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return GenesisTrustRoot{}, fmt.Errorf("stat genesis config: %w", err)
	}
	if info.Size() > MaxGenesisConfigBytes {
		return GenesisTrustRoot{}, ErrGenesisConfigTooLarge
	}
	return readGenesisConfig(f)
}

func readGenesisConfig(r io.Reader) (GenesisTrustRoot, error) {
	// The read bound also covers streams and files that grow after Stat.
	raw, err := io.ReadAll(io.LimitReader(r, MaxGenesisConfigBytes+1))
	if err != nil {
		return GenesisTrustRoot{}, fmt.Errorf("read genesis config: %w", err)
	}
	if len(raw) > MaxGenesisConfigBytes {
		return GenesisTrustRoot{}, ErrGenesisConfigTooLarge
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return GenesisTrustRoot{}, fmt.Errorf("%w: expected one JSON object", ErrInvalidGenesis)
	}
	var chainID, height *uint64
	var hash *chain.Hash
	fields := map[string]any{"chain_id": &chainID, "height": &height, "header_hash": &hash}
	seen := make(map[string]bool, len(fields))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return GenesisTrustRoot{}, fmt.Errorf("%w: malformed JSON object", ErrInvalidGenesis)
		}
		key, ok := token.(string)
		target, known := fields[key]
		if !ok || !known || seen[key] {
			return GenesisTrustRoot{}, fmt.Errorf("%w: unknown or duplicate field", ErrInvalidGenesis)
		}
		seen[key] = true
		if err := d.Decode(target); err != nil {
			// Report the known schema field, never the untrusted value.
			return GenesisTrustRoot{}, fmt.Errorf("%w: invalid %s", ErrInvalidGenesis, key)
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return GenesisTrustRoot{}, fmt.Errorf("%w: malformed JSON object", ErrInvalidGenesis)
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return GenesisTrustRoot{}, fmt.Errorf("%w: trailing JSON", ErrInvalidGenesis)
	}
	if chainID == nil || height == nil || hash == nil {
		return GenesisTrustRoot{}, fmt.Errorf("%w: chain_id, height, and header_hash must be explicit and non-null", ErrInvalidGenesis)
	}
	g := GenesisTrustRoot{ChainID: *chainID, Height: *height, HeaderHash: *hash}
	if err := g.Validate(); err != nil {
		return GenesisTrustRoot{}, err
	}
	return g, nil
}

// mustHash decodes a 64-char hex string into a chain.Hash, panicking
// on failure. Used only for embedded constants whose validity is
// asserted at init.
func mustHash(s string) chain.Hash {
	if len(s) != 2*chain.HashSize {
		panic("verify: bad embedded hash length: " + s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic("verify: bad embedded hash hex: " + err.Error())
	}
	var h chain.Hash
	copy(h[:], raw)
	return h
}
