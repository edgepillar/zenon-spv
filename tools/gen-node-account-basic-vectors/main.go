// Command gen-node-account-basic-vectors records two actual node methods using
// actual in-memory account/momentum stores and caller-selected context handles.
// It imports no SPV code, creates no keys/signatures, and opens no network or disk DB.
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
	"runtime/debug"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/account"
	"github.com/zenon-network/go-zenon/chain/momentum"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/chain/store"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/verifier"
)

const (
	nodeModule  = "github.com/zenon-network/go-zenon"
	nodeVersion = "v0.0.8-alphanet.0.20261009223306-c64ed6279ff1"
	nodeCommit  = "c64ed6279ff1d07335dab0ac36156dec8b5b71e9"
	nodeSum     = "h1:3Vyk+6hw2dcWJLg15JEq7ITFOkaYvrVyI+W8Qb3Jlr4="
	segmentsPin = "1faca6715c3865bae726a7a07f56ef2c43bd8a5a5c9816f618373312de43b048"
)

var profiles = []string{"first-exact-ack", "version-zero", "version-two", "chain-zero", "chain-mismatch", "stored-chain-mismatch",
	"type-zero", "type-genesis", "type-unsupported", "type-contract-receive", "amount-negative", "amount-large", "token-zero",
	"send-from-hash-nonzero", "ack-missing", "ack-wrong-hash", "ack-corrupt-entry", "height-two-exact", "height-two-empty",
	"height-two-wrong-frontier", "height-two-corrupt-frontier", "height-two-previous-ack-ahead", "hash-zero", "hash-mutated", "signature-empty"}

type plan struct {
	ChainID      uint64 `json:"chain_id"`
	AccountSeed  string `json:"account_seed"`
	MomentumSeed string `json:"momentum_seed"`
}
type call struct {
	Method     string            `json:"method"`
	Address    string            `json:"address,omitempty"`
	Identifier *types.HashHeight `json:"identifier,omitempty"`
	Height     uint64            `json:"height,omitempty"`
}
type entry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type read struct {
	Store string `json:"store"`
	Key   string `json:"key"`
	Value string `json:"value"`
	Error string `json:"error"`
}
type observation struct {
	Name            string          `json:"name"`
	Profile         string          `json:"profile"`
	Method          string          `json:"method"`
	Plan            plan            `json:"store_plan"`
	Block           json.RawMessage `json:"account_block"`
	ComputedHash    types.Hash      `json:"computed_hash"`
	Result          string          `json:"node_method_result"`
	Error           string          `json:"node_error"`
	Calls           []call          `json:"store_calls"`
	Reads           []read          `json:"database_reads"`
	AccountEntries  []entry         `json:"account_entries"`
	MomentumEntries []entry         `json:"momentum_entries"`
}

// Genesis metadata and historical handle selection are explicit synthetic inputs.
// Only selected methods are forwarded; unselected chain/store methods panic.
type selectedGenesis struct {
	store.Genesis
	chainID uint64
}

func (g selectedGenesis) ChainIdentifier() uint64 { return g.chainID }

type recordingChain struct {
	chain.Chain
	account  store.Account
	momentum store.Momentum
	calls    *[]call
}

func (c recordingChain) GetAccountStore(address types.Address, id types.HashHeight) store.Account {
	*c.calls = append(*c.calls, call{Method: "Chain.GetAccountStore", Address: address.String(), Identifier: &id})
	return c.account
}
func (c recordingChain) GetFrontierMomentumStore() store.Momentum {
	*c.calls = append(*c.calls, call{Method: "Chain.GetFrontierMomentumStore"})
	return c.momentum
}

type recordingAccount struct {
	store.Account
	inner store.Account
	calls *[]call
}

func (a recordingAccount) Frontier() (*nom.AccountBlock, error) {
	*a.calls = append(*a.calls, call{Method: "Account.Frontier"})
	return a.inner.Frontier()
}
func (a recordingAccount) ByHeight(height uint64) (*nom.AccountBlock, error) {
	*a.calls = append(*a.calls, call{Method: "Account.ByHeight", Height: height})
	return a.inner.ByHeight(height)
}

type recordingMomentum struct {
	store.Momentum
	inner store.Momentum
	calls *[]call
}

func (m recordingMomentum) ChainIdentifier() uint64 {
	*m.calls = append(*m.calls, call{Method: "Momentum.ChainIdentifier"})
	return m.inner.ChainIdentifier()
}
func (m recordingMomentum) GetMomentumByHeight(height uint64) (*nom.Momentum, error) {
	*m.calls = append(*m.calls, call{Method: "Momentum.GetMomentumByHeight", Height: height})
	return m.inner.GetMomentumByHeight(height)
}

type recordingDB struct {
	db.DB
	name  string
	reads *[]read
}

func (d recordingDB) Get(key []byte) ([]byte, error) {
	value, err := d.DB.Get(key)
	code := ""
	if errors.Is(err, leveldb.ErrNotFound) {
		code = "not_found"
	} else if err != nil {
		code = "unselected_error"
	}
	*d.reads = append(*d.reads, read{d.name, hex.EncodeToString(key), hex.EncodeToString(value), code})
	return value, err
}
func (d recordingDB) Put([]byte, []byte) error { panic("unselected validation write") }
func (d recordingDB) Delete([]byte) error      { panic("unselected validation write") }
func (d recordingDB) Apply(db.Patch) error     { panic("unselected validation write") }
func entries(database db.DB) ([]entry, error) {
	result := make([]entry, 0)
	iterator := database.NewIterator(nil)
	defer iterator.Release()
	for iterator.Next() {
		result = append(result, entry{hex.EncodeToString(iterator.Key()), hex.EncodeToString(iterator.Value())})
	}
	return result, iterator.Error()
}
func selected(raw json.RawMessage, profile string) (*nom.AccountBlock, plan, error) {
	var b nom.AccountBlock
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, plan{}, err
	}
	p := plan{99, "empty", "exact"}
	switch profile {
	case "first-exact-ack":
	case "version-zero":
		b.Version = 0
	case "version-two":
		b.Version = 2
	case "chain-zero":
		b.ChainIdentifier = 0
	case "chain-mismatch":
		b.ChainIdentifier = 100
	case "stored-chain-mismatch":
		p.ChainID = 100
	case "type-zero":
		b.BlockType = 0
	case "type-genesis":
		b.BlockType = 1
	case "type-unsupported":
		b.BlockType = 6
	case "type-contract-receive":
		b.BlockType = 5
	case "amount-negative":
		b.Amount.Neg(b.Amount)
	case "amount-large":
		b.Amount = new(big.Int).Lsh(big.NewInt(1), 255)
	case "token-zero":
		b.TokenStandard = types.ZeroTokenStandard
	case "send-from-hash-nonzero":
		b.FromBlockHash[0] = 1
	case "ack-missing":
		p.MomentumSeed = "empty"
	case "ack-wrong-hash":
		p.MomentumSeed = "wrong_hash"
	case "ack-corrupt-entry":
		p.MomentumSeed = "corrupt"
	case "height-two-exact", "height-two-empty", "height-two-wrong-frontier", "height-two-corrupt-frontier", "height-two-previous-ack-ahead":
		b.Height = 2
		b.PreviousHash = b.Hash
		p.AccountSeed = map[string]string{"height-two-exact": "exact", "height-two-empty": "empty", "height-two-wrong-frontier": "wrong_hash", "height-two-corrupt-frontier": "corrupt", "height-two-previous-ack-ahead": "ack_ahead"}[profile]
	case "hash-zero":
		b.Hash = types.ZeroHash
	case "hash-mutated":
		b.Hash[0] ^= 1
	case "signature-empty":
		b.Signature = nil
	default:
		return nil, p, fmt.Errorf("unselected profile")
	}
	return &b, p, nil
}
func seed(raw json.RawMessage, p plan) (db.DB, db.DB, error) {
	var original nom.AccountBlock
	if err := json.Unmarshal(raw, &original); err != nil {
		return nil, nil, err
	}
	accountDB, momentumDB := db.NewMemDB(), db.NewMemDB()
	if p.AccountSeed != "empty" {
		if p.AccountSeed == "wrong_hash" {
			original.Hash[0] ^= 1
		}
		if p.AccountSeed == "ack_ahead" {
			original.MomentumAcknowledged.Height++
		}
		data, err := original.Serialize()
		if err != nil {
			return nil, nil, err
		}
		if p.AccountSeed == "corrupt" {
			data = []byte{0xff}
		}
		if err := db.SetFrontier(accountDB, original.Identifier(), data); err != nil {
			return nil, nil, err
		}
	}
	if p.MomentumSeed != "empty" {
		// This unsigned record carries a selected hash; it is never hashed, signed,
		// independently authenticated or passed to momentum validation.
		var baseline nom.AccountBlock
		if err := json.Unmarshal(raw, &baseline); err != nil {
			return nil, nil, err
		}
		m := &nom.Momentum{Version: 1, ChainIdentifier: 99, Hash: baseline.MomentumAcknowledged.Hash, Height: baseline.MomentumAcknowledged.Height}
		if p.MomentumSeed == "wrong_hash" {
			m.Hash[0] ^= 1
		}
		data, err := m.Serialize()
		if err != nil {
			return nil, nil, err
		}
		if p.MomentumSeed == "corrupt" {
			data = []byte{0xff}
		}
		if err := db.SetFrontier(momentumDB, m.Identifier(), data); err != nil {
			return nil, nil, err
		}
	}
	return accountDB, momentumDB, nil
}
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	cases := []struct {
		err  error
		code string
	}{
		{verifier.ErrABVersionMissing, "version_missing"}, {verifier.ErrABVersionInvalid, "version_invalid"},
		{verifier.ErrMChainIdentifierMissing, "chain_missing"}, {verifier.ErrMChainIdentifierMismatch, "chain_mismatch"},
		{verifier.ErrABTypeMissing, "type_missing"}, {verifier.ErrABTypeMustNotBeGenesis, "type_genesis"},
		{verifier.ErrABTypeUnsupported, "type_unsupported"}, {verifier.ErrABTypeMustBeUser, "type_must_be_user"},
		{verifier.ErrABAmountNegative, "amount_negative"}, {verifier.ErrABAmountTooBig, "amount_too_big"},
		{verifier.ErrABZtsMissing, "zts_missing"}, {verifier.ErrABFromBlockHashMustBeZero, "from_hash_must_be_zero"},
		{verifier.ErrABPreviousMissing, "previous_missing"}, {verifier.ErrABMAMissing, "ack_missing"},
		{verifier.ErrABMAGap, "ack_gap"}, {verifier.ErrVerifierInternal, "internal_store_error"},
		{verifier.ErrABHashMissing, "hash_missing"}, {verifier.ErrABHashInvalid, "hash_mismatch"}, {verifier.ErrABSignatureMissing, "signature_missing"},
	}
	for _, c := range cases {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "unselected_error"
}
func invoke(method string, b *nom.AccountBlock, c recordingChain) (err error, panicValue any) {
	defer func() { panicValue = recover() }()
	v := verifier.NewAccountBlockVerifier(c, nil)
	if method == "AccountBlock" {
		err = v.AccountBlock(b)
	} else if method == "AccountBlockTransaction" {
		err = v.AccountBlockTransaction(&nom.AccountBlockTransaction{Block: b})
	} else {
		panic("unselected method")
	}
	return
}
func record(raw json.RawMessage, profile, method string) (observation, error) {
	b, p, err := selected(raw, profile)
	if err != nil {
		return observation{}, err
	}
	wire, err := json.Marshal(b)
	if err != nil {
		return observation{}, err
	}
	r := observation{Name: "user-type-2/" + profile + "/" + method, Profile: profile, Method: method, Plan: p, Block: wire, ComputedHash: b.ComputeHash(), Calls: make([]call, 0), Reads: make([]read, 0)}
	a, m, err := seed(raw, p)
	if err != nil {
		return r, err
	}
	r.AccountEntries, err = entries(a)
	if err != nil {
		return r, err
	}
	r.MomentumEntries, err = entries(m)
	if err != nil {
		return r, err
	}
	accountStore := recordingAccount{inner: account.NewAccountStore(b.Address, recordingDB{a, "account", &r.Reads}), calls: &r.Calls}
	momentumStore := recordingMomentum{inner: momentum.NewStore(selectedGenesis{chainID: p.ChainID}, recordingDB{m, "momentum", &r.Reads}), calls: &r.Calls}
	err, panicValue := invoke(method, b, recordingChain{account: accountStore, momentum: momentumStore, calls: &r.Calls})
	r.Result, r.Error = "MATCH", errorCode(err)
	if err != nil {
		r.Result = "REJECT"
	}
	if panicValue != nil {
		r.Result, r.Error = "PANIC", "unexpected_panic"
	}
	after, e := json.Marshal(b)
	if e != nil || !bytes.Equal(wire, after) {
		return r, fmt.Errorf("node changed selected wire block")
	}
	afterA, e := entries(a)
	if e != nil {
		return r, e
	}
	afterM, e := entries(m)
	if e != nil {
		return r, e
	}
	beforeJSON, _ := json.Marshal([][]entry{r.AccountEntries, r.MomentumEntries})
	afterJSON, _ := json.Marshal([][]entry{afterA, afterM})
	if !bytes.Equal(beforeJSON, afterJSON) {
		return r, fmt.Errorf("node changed seeded records")
	}
	return r, nil
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: gen-node-account-basic-vectors SEGMENTS_FIXTURE")
	}
	if err := checkNodePin(); err != nil {
		return err
	}
	var input struct {
		Segments []struct {
			Vectors []struct {
				Name string          `json:"name"`
				RPC  json.RawMessage `json:"rpc"`
			} `json:"vectors"`
		} `json:"segments"`
	}
	if err := readSelected(os.Args[1], segmentsPin, &input); err != nil {
		return err
	}
	baselines := map[string]json.RawMessage{}
	for _, s := range input.Segments {
		for _, v := range s.Vectors {
			if _, ok := baselines[v.Name]; ok {
				return fmt.Errorf("duplicate baseline")
			}
			baselines[v.Name] = v.RPC
		}
	}
	if len(baselines) != 4 || baselines["user-type-2"] == nil {
		return fmt.Errorf("incomplete baseline inventory")
	}
	observations := make([]observation, 0, 50)
	for _, profile := range profiles {
		for _, method := range []string{"AccountBlock", "AccountBlockTransaction"} {
			r, err := record(baselines["user-type-2"], profile, method)
			if err != nil {
				return err
			}
			observations = append(observations, r)
		}
	}
	out := struct {
		Format       int               `json:"format_version"`
		Source       map[string]any    `json:"source"`
		Inputs       map[string]string `json:"input_files_sha256"`
		Scope        map[string]bool   `json:"scope"`
		Observations []observation     `json:"observations"`
	}{1,
		map[string]any{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit, "module_version": nodeVersion, "module_sum": nodeSum, "methods": []string{"verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}},
		map[string]string{"account-segments.json": segmentsPin},
		map[string]bool{"actual_node_entry_point_execution": true, "actual_memory_account_and_momentum_stores": true, "synthetic_context_handle_selection": true, "synthetic_unsigned_momentum_metadata": true, "basic_account_checks_reached": true, "hash_signature_checks_reached": true, "new_signatures_generated": false, "disk_database_opened": false, "network_transport": false, "full_node_validation": false, "authenticated_context": false, "canonicality": false, "consensus_finality": false, "state_value_acceptance": false}, observations}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		return err
	}
	// Emit every actual observation before checking finite outcome expectations.
	matches, rejects := 0, 0
	for _, r := range observations {
		if r.Result == "MATCH" {
			matches++
		}
		if r.Result == "REJECT" && r.Error != "unselected_error" {
			rejects++
		}
	}
	if len(observations) != 50 || matches != 11 || rejects != 39 {
		return fmt.Errorf("actual finite outcome inventory differs")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
