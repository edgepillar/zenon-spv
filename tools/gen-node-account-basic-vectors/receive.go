// The receive mode is separate from the original immutable first-send corpus.
// It reuses original signatures and executes no mailbox, VM, transaction writer,
// disk database, consensus service or network operation.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/zenon-network/go-zenon/chain/account"
	"github.com/zenon-network/go-zenon/chain/momentum"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/verifier"
)

const receiveEnforcementHeight uint64 = 10109240

var receiveProfiles = []string{"exact", "source-header-missing", "source-body-missing", "source-header-corrupt", "source-body-corrupt",
	"source-index-other-original", "confirmation-missing", "confirmation-before", "confirmation-after", "receiver-before-enforcement",
	"receiver-at-enforcement", "receiver-after-enforcement", "received", "received-empty", "ack-missing", "ack-wrong", "ack-corrupt",
	"previous-ack-after", "receive-amount-nonzero", "receive-token-nonzero", "receive-to-nonzero", "receive-source-zero"}

type receivePlan struct {
	SourceSeed          string `json:"source_seed"`
	ConfirmationSeed    string `json:"confirmation_seed"`
	ReceivedSeed        string `json:"received_seed"`
	AcknowledgementSeed string `json:"acknowledgement_seed"`
	PreviousSeed        string `json:"previous_seed"`
	LedgerFrontier      uint64 `json:"ledger_frontier_height"`
}

type receiveObservation struct {
	Name            string          `json:"name"`
	Profile         string          `json:"profile"`
	Method          string          `json:"method"`
	Plan            receivePlan     `json:"store_plan"`
	Block           json.RawMessage `json:"account_block"`
	ComputedHash    types.Hash      `json:"computed_hash"`
	Result          string          `json:"node_method_result"`
	Error           string          `json:"node_error"`
	Calls           []call          `json:"store_calls"`
	Reads           []read          `json:"database_reads"`
	AccountEntries  []receiveEntry  `json:"account_entries"`
	MomentumEntries []receiveEntry  `json:"momentum_entries"`
}

type receiveEntry struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	ReadError string `json:"read_error"`
}

// NewMemDB keeps deletion tombstones in its iterator. An empty iterator value
// alone cannot distinguish a tombstone from a present empty value. Pin Get's
// status for each seed entry, outside the recorded validation read sequence.
func receiveEntries(database db.DB) ([]receiveEntry, error) {
	result := make([]receiveEntry, 0)
	iterator := database.NewIterator(nil)
	defer iterator.Release()
	for iterator.Next() {
		value, err := database.Get(iterator.Key())
		code := ""
		if errors.Is(err, leveldb.ErrNotFound) {
			code = "not_found"
		} else if err != nil {
			return nil, err
		}
		if !bytes.Equal(value, iterator.Value()) {
			return nil, fmt.Errorf("receive seed iterator/Get bytes differ")
		}
		result = append(result, receiveEntry{hex.EncodeToString(iterator.Key()), hex.EncodeToString(iterator.Value()), code})
	}
	return result, iterator.Error()
}

// Preserve interception through the actual ledger's Subset/Snapshot adapters.
// These wrappers forward reads to real memory databases; no read is synthesized.
type receiveDB struct {
	db.DB
	prefix []byte
	name   string
	reads  *[]read
}

func (d receiveDB) Get(key []byte) ([]byte, error) {
	value, err := d.DB.Get(key)
	code := ""
	if errors.Is(err, leveldb.ErrNotFound) {
		code = "not_found"
	} else if err != nil {
		code = "unselected_error"
	}
	*d.reads = append(*d.reads, read{d.name, hex.EncodeToString(common.JoinBytes(d.prefix, key)), hex.EncodeToString(value), code})
	return value, err
}
func (d receiveDB) Subset(prefix []byte) db.DB {
	return receiveDB{d.DB.Subset(prefix), common.JoinBytes(d.prefix, prefix), d.name, d.reads}
}
func (d receiveDB) Snapshot() db.DB {
	return receiveDB{d.DB.Snapshot(), d.prefix, d.name, d.reads}
}
func (d receiveDB) Put([]byte, []byte) error { panic("unselected receive validation write") }
func (d receiveDB) Delete([]byte) error      { panic("unselected receive validation write") }
func (d receiveDB) Apply(db.Patch) error     { panic("unselected receive validation write") }

type receiveAccount struct{ recordingAccount }

func (a receiveAccount) IsReceived(hash types.Hash) bool {
	*a.calls = append(*a.calls, call{Method: "Account.IsReceived", Hash: &hash})
	return a.inner.IsReceived(hash)
}

type receiveMomentum struct{ recordingMomentum }

func (m receiveMomentum) GetAccountBlockByHash(hash types.Hash) (*nom.AccountBlock, error) {
	*m.calls = append(*m.calls, call{Method: "Momentum.GetAccountBlockByHash", Hash: &hash})
	return m.inner.GetAccountBlockByHash(hash)
}
func (m receiveMomentum) GetBlockConfirmationHeight(hash types.Hash) (uint64, error) {
	*m.calls = append(*m.calls, call{Method: "Momentum.GetBlockConfirmationHeight", Hash: &hash})
	return m.inner.GetBlockConfirmationHeight(hash)
}
func (m receiveMomentum) Identifier() types.HashHeight {
	*m.calls = append(*m.calls, call{Method: "Momentum.Identifier"})
	return m.inner.Identifier()
}

func selectedReceive(raw json.RawMessage, profile string) (*nom.AccountBlock, receivePlan, error) {
	var b nom.AccountBlock
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, receivePlan{}, err
	}
	p := receivePlan{"exact", "exact", "none", "exact", "exact", b.MomentumAcknowledged.Height}
	switch profile {
	case "exact":
	case "source-header-missing", "source-body-missing", "source-header-corrupt", "source-body-corrupt", "source-index-other-original":
		p.SourceSeed = profile
	case "confirmation-missing", "confirmation-before", "confirmation-after":
		p.ConfirmationSeed = profile
	case "receiver-before-enforcement", "receiver-at-enforcement", "receiver-after-enforcement":
		p.SourceSeed = "receiver-mismatch"
		p.LedgerFrontier = map[string]uint64{"receiver-before-enforcement": receiveEnforcementHeight - 1,
			"receiver-at-enforcement": receiveEnforcementHeight, "receiver-after-enforcement": receiveEnforcementHeight + 1}[profile]
	case "received", "received-empty":
		p.ReceivedSeed = profile
	case "ack-missing", "ack-wrong", "ack-corrupt":
		p.AcknowledgementSeed = profile
	case "previous-ack-after":
		p.PreviousSeed = profile
	case "receive-amount-nonzero":
		b.Amount = big.NewInt(1)
	case "receive-token-nonzero":
		b.TokenStandard = types.ZnnTokenStandard
	case "receive-to-nonzero":
		b.ToAddress = b.Address
	case "receive-source-zero":
		b.FromBlockHash = types.ZeroHash
	default:
		return nil, p, fmt.Errorf("unselected receive profile")
	}
	return &b, p, nil
}

func seedReceive(previousRaw, receiveRaw, sourceRaw json.RawMessage, p receivePlan) (db.DB, db.DB, error) {
	var previous, original, source nom.AccountBlock
	for _, selected := range []struct {
		raw  json.RawMessage
		into *nom.AccountBlock
	}{{previousRaw, &previous}, {receiveRaw, &original}, {sourceRaw, &source}} {
		if err := json.Unmarshal(selected.raw, selected.into); err != nil {
			return nil, nil, err
		}
	}
	a, m := db.NewMemDB(), db.NewMemDB()
	if p.PreviousSeed == "previous-ack-after" {
		previous.MomentumAcknowledged.Height++
	}
	payload, err := previous.Serialize()
	if err != nil {
		return nil, nil, err
	}
	if err := db.SetFrontier(a, previous.Identifier(), payload); err != nil {
		return nil, nil, err
	}
	if p.ReceivedSeed == "received" {
		if err := account.NewAccountStore(original.Address, a).MarkAsReceived(original.FromBlockHash); err != nil {
			return nil, nil, err
		}
	} else if p.ReceivedSeed == "received-empty" {
		if err := a.Put(common.JoinBytes([]byte{6}, original.FromBlockHash.Bytes()), nil); err != nil {
			return nil, nil, err
		}
	}
	ack := &nom.Momentum{Version: 1, ChainIdentifier: 99, Hash: original.MomentumAcknowledged.Hash, Height: original.MomentumAcknowledged.Height}
	if p.AcknowledgementSeed == "ack-wrong" {
		ack.Hash[0] ^= 1
	}
	if p.AcknowledgementSeed != "ack-missing" {
		payload, err = ack.Serialize()
		if err != nil {
			return nil, nil, err
		}
		if p.AcknowledgementSeed == "ack-corrupt" {
			payload = []byte{0xff}
		}
		if err := db.SetFrontier(m, ack.Identifier(), payload); err != nil {
			return nil, nil, err
		}
	}
	if p.LedgerFrontier != original.MomentumAcknowledged.Height {
		frontier := &nom.Momentum{Version: 1, ChainIdentifier: 99, Hash: types.Hash{0xfe}, Height: p.LedgerFrontier}
		payload, err = frontier.Serialize()
		if err != nil {
			return nil, nil, err
		}
		if err := db.SetFrontier(m, frontier.Identifier(), payload); err != nil {
			return nil, nil, err
		}
	}
	if p.SourceSeed == "source-index-other-original" {
		// Explicitly incoherent caller-selected index: it is not authenticated history.
		if err := json.Unmarshal(previousRaw, &source); err != nil {
			return nil, nil, err
		}
	} else if p.SourceSeed == "receiver-mismatch" {
		source.ToAddress = source.Address
	}
	payload, err = source.Serialize()
	if err != nil {
		return nil, nil, err
	}
	if p.SourceSeed == "source-body-corrupt" {
		payload = []byte{0xff}
	}
	sourceDB := m.Subset(common.JoinBytes([]byte{3}, source.Address.Bytes()))
	if err := db.SetFrontier(sourceDB, source.Identifier(), payload); err != nil {
		return nil, nil, err
	}
	if p.SourceSeed == "source-body-missing" {
		if err := sourceDB.Delete(common.JoinBytes([]byte{2}, common.Uint64ToBytes(source.Height))); err != nil {
			return nil, nil, err
		}
	}
	if p.SourceSeed != "source-header-missing" {
		header := source.Header()
		payload, err = header.Serialize()
		if err != nil {
			return nil, nil, err
		}
		if p.SourceSeed == "source-header-corrupt" {
			payload = []byte{0xff}
		}
		if err := m.Put(common.JoinBytes([]byte{9}, original.FromBlockHash.Bytes()), payload); err != nil {
			return nil, nil, err
		}
	}
	if p.ConfirmationSeed != "confirmation-missing" {
		height := original.MomentumAcknowledged.Height
		if p.ConfirmationSeed == "confirmation-before" {
			height--
		} else if p.ConfirmationSeed == "confirmation-after" {
			height++
		}
		if err := m.Put(common.JoinBytes([]byte{5}, original.FromBlockHash.Bytes()), common.Uint64ToBytes(height)); err != nil {
			return nil, nil, err
		}
	}
	return a, m, nil
}

func receiveErrorCode(err error) string {
	if code := errorCode(err); code != "unselected_error" {
		return code
	}
	for _, selected := range []struct {
		err  error
		code string
	}{{verifier.ErrABAmountMustBeZero, "receive_amount_must_be_zero"}, {verifier.ErrABZtsMustBeZero, "receive_token_must_be_zero"},
		{verifier.ErrABToAddressMustBeZero, "receive_to_must_be_zero"}, {verifier.ErrABFromBlockHashMissing, "receive_from_hash_missing"},
		{verifier.ErrABFromBlockMissing, "source_block_missing"}, {verifier.ErrABFromBlockReceiverMismatch, "source_receiver_mismatch"},
		{verifier.ErrABFromBlockAlreadyReceived, "source_already_received"}} {
		if errors.Is(err, selected.err) {
			return selected.code
		}
	}
	return "unselected_error"
}

func recordReceive(originals map[string]json.RawMessage, profile, method string) (receiveObservation, error) {
	b, p, err := selectedReceive(originals["user-type-3"], profile)
	if err != nil {
		return receiveObservation{}, err
	}
	wire, err := json.Marshal(b)
	if err != nil {
		return receiveObservation{}, err
	}
	r := receiveObservation{Name: "user-type-3/" + profile + "/" + method, Profile: profile, Method: method, Plan: p,
		Block: wire, ComputedHash: b.ComputeHash(), Calls: make([]call, 0), Reads: make([]read, 0)}
	a, m, err := seedReceive(originals["user-type-2"], originals["user-type-3"], originals["embedded-type-4"], p)
	if err != nil {
		return r, err
	}
	r.AccountEntries, err = receiveEntries(a)
	if err != nil {
		return r, err
	}
	r.MomentumEntries, err = receiveEntries(m)
	if err != nil {
		return r, err
	}
	accountStore := receiveAccount{recordingAccount{inner: account.NewAccountStore(b.Address, receiveDB{DB: a, name: "account", reads: &r.Reads}), calls: &r.Calls}}
	momentumStore := receiveMomentum{recordingMomentum{inner: momentum.NewStore(selectedGenesis{chainID: 99}, receiveDB{DB: m, name: "momentum", reads: &r.Reads}), calls: &r.Calls}}
	err, panicValue := invoke(method, b, recordingChain{account: accountStore, momentum: momentumStore, calls: &r.Calls})
	r.Result, r.Error = "MATCH", receiveErrorCode(err)
	if err != nil {
		r.Result = "REJECT"
	}
	if panicValue != nil {
		r.Result, r.Error = "PANIC", "unexpected_panic"
	}
	after, e := json.Marshal(b)
	if e != nil || !bytes.Equal(wire, after) {
		return r, fmt.Errorf("node changed selected receive bytes")
	}
	afterA, e := receiveEntries(a)
	if e != nil {
		return r, e
	}
	afterM, e := receiveEntries(m)
	if e != nil {
		return r, e
	}
	beforeRecords, _ := json.Marshal([][]receiveEntry{r.AccountEntries, r.MomentumEntries})
	afterRecords, _ := json.Marshal([][]receiveEntry{afterA, afterM})
	if !bytes.Equal(beforeRecords, afterRecords) {
		return r, fmt.Errorf("node changed selected receive stores")
	}
	return r, nil
}

func runReceive(path string) error {
	if err := checkNodePin(); err != nil {
		return err
	}
	if verifier.ReceiverMismatchEnforcementHeight != receiveEnforcementHeight {
		return fmt.Errorf("unselected receiver enforcement height")
	}
	var input struct {
		Segments []struct {
			Vectors []struct {
				Name string          `json:"name"`
				RPC  json.RawMessage `json:"rpc"`
			} `json:"vectors"`
		} `json:"segments"`
	}
	if err := readSelected(path, segmentsPin, &input); err != nil {
		return err
	}
	originals := make(map[string]json.RawMessage)
	for _, s := range input.Segments {
		for _, v := range s.Vectors {
			if _, exists := originals[v.Name]; exists {
				return fmt.Errorf("duplicate receive baseline")
			}
			originals[v.Name] = v.RPC
		}
	}
	if len(originals) != 4 || originals["user-type-2"] == nil || originals["user-type-3"] == nil || originals["embedded-type-4"] == nil {
		return fmt.Errorf("incomplete receive input inventory")
	}
	observations := make([]receiveObservation, 0, 44)
	for _, profile := range receiveProfiles {
		for _, method := range []string{"AccountBlock", "AccountBlockTransaction"} {
			r, err := recordReceive(originals, profile, method)
			if err != nil {
				return err
			}
			observations = append(observations, r)
		}
	}
	out := struct {
		Format       int                  `json:"format_version"`
		Source       map[string]any       `json:"source"`
		Inputs       map[string]string    `json:"input_files_sha256"`
		Scope        map[string]bool      `json:"scope"`
		Observations []receiveObservation `json:"observations"`
	}{1, map[string]any{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit, "module_version": nodeVersion,
		"module_sum": nodeSum, "methods": []string{"verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"},
		"receiver_mismatch_enforcement_height": receiveEnforcementHeight}, map[string]string{"account-segments.json": segmentsPin},
		map[string]bool{"actual_node_entry_point_execution": true, "actual_memory_account_and_momentum_stores": true,
			"synthetic_context_handle_selection": true, "synthetic_unsigned_ledger_records": true, "receive_field_checks_reached": true,
			"source_confirmation_and_received_checks_reached": true, "new_signatures_generated": false, "disk_database_opened": false,
			"mailbox_or_contract_execution": false, "network_transport": false, "full_node_validation": false, "authenticated_context": false,
			"canonicality": false, "consensus_finality": false, "state_value_acceptance": false}, observations}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		return err
	}
	// Retain every actual method result before enforcing the selected inventory.
	matches, rejects := 0, 0
	for _, r := range observations {
		if r.Result == "MATCH" {
			matches++
		}
		if r.Result == "REJECT" && r.Error != "unselected_error" {
			rejects++
		}
	}
	if len(observations) != 44 || matches != 23 || rejects != 21 {
		return fmt.Errorf("actual receive outcome inventory differs: %d matches, %d rejections", matches, rejects)
	}
	return nil
}
