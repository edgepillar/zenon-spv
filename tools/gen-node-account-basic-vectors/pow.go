package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/zenon-network/go-zenon/chain/account"
	"github.com/zenon-network/go-zenon/chain/momentum"
	"github.com/zenon-network/go-zenon/common/crypto"
	"github.com/zenon-network/go-zenon/pow"
	"github.com/zenon-network/go-zenon/verifier"
)

// These finite inputs are selected before any reference call. No nonce search,
// randomness, wallet API or signature generation is used.
var powDifficulties = []uint64{0, 1, 2, 1000, (1 << 63) - 1, 1 << 63, ^uint64(0) - 1, ^uint64(0)}
var powNonces = []string{"0000000000000000", "0100000000000000", "0123456789abcdef", "ffffffffffffffff"}

type powProbe struct {
	Name                    string `json:"name"`
	Difficulty              string `json:"difficulty_decimal"`
	Nonce                   string `json:"nonce_hex"`
	DataPreimage            string `json:"data_preimage_hex"`
	DataHash                string `json:"node_data_hash"`
	NoncePreimage           string `json:"nonce_preimage_hex"`
	CalculatedHash          string `json:"node_calculated_hash"`
	CalculatedUint64        string `json:"calculated_uint64_decimal"`
	ProducerThresholdStatus string `json:"producer_threshold_status"`
	ProducerThreshold       string `json:"node_producer_threshold_decimal"`
	ProducerThresholdBytes  string `json:"node_producer_threshold_le_hex"`
	NonceMatches            bool   `json:"node_nonce_matches"`
}

func recordPoW(raw json.RawMessage, profile, method string, difficulty uint64, nonce []byte) (observation, error) {
	b, p, err := selected(raw, "first-exact-ack")
	if err != nil {
		return observation{}, err
	}
	b.Difficulty = difficulty
	copy(b.Nonce.Data[:], nonce)
	wire, err := json.Marshal(b)
	if err != nil {
		return observation{}, err
	}
	r := observation{Name: "user-type-2/" + profile + "/" + method, Profile: profile, Method: method, Plan: p, Block: wire,
		ComputedHash: b.ComputeHash(), Calls: make([]call, 0), Reads: make([]read, 0)}
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
	if errors.Is(err, verifier.ErrABPoWInvalid) {
		r.Error = "pow_invalid"
	}
	if err != nil {
		r.Result = "REJECT"
	}
	if panicValue != nil {
		r.Result, r.Error = "PANIC", "unexpected_panic"
	}
	after, e := json.Marshal(b)
	if e != nil || !bytes.Equal(wire, after) {
		return r, fmt.Errorf("node changed selected PoW block")
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
		return r, fmt.Errorf("node changed selected PoW stores")
	}
	return r, nil
}

func runPoW(path string) error {
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
	if err := readSelected(path, segmentsPin, &input); err != nil {
		return err
	}
	baselines := map[string]json.RawMessage{}
	for _, s := range input.Segments {
		for _, v := range s.Vectors {
			if _, exists := baselines[v.Name]; exists {
				return fmt.Errorf("duplicate PoW baseline")
			}
			baselines[v.Name] = v.RPC
		}
	}
	raw := baselines["user-type-2"]
	if len(baselines) != 4 || raw == nil {
		return fmt.Errorf("incomplete PoW baseline inventory")
	}
	probes := make([]powProbe, 0, 32)
	observations := make([]observation, 0, 64)
	for _, difficulty := range powDifficulties {
		for _, nonceHex := range powNonces {
			nonce, err := hex.DecodeString(nonceHex)
			if err != nil || len(nonce) != 8 {
				return fmt.Errorf("unselected nonce width")
			}
			b, _, err := selected(raw, "first-exact-ack")
			if err != nil {
				return err
			}
			b.Difficulty = difficulty
			copy(b.Nonce.Data[:], nonce)
			before, err := json.Marshal(b)
			if err != nil {
				return err
			}
			profile := "difficulty-" + strconv.FormatUint(difficulty, 10) + "/nonce-" + nonceHex
			dataPreimage := append(append([]byte{}, b.Address.Bytes()...), b.PreviousHash.Bytes()...)
			dataHash := pow.GetAccountBlockHash(b)
			noncePreimage := append(append([]byte{}, b.Nonce.Serialize()...), dataHash.Bytes()...)
			calculated := crypto.Hash(noncePreimage)
			probe := powProbe{Name: "user-type-2/" + profile, Difficulty: strconv.FormatUint(difficulty, 10), Nonce: nonceHex,
				DataPreimage: hex.EncodeToString(dataPreimage), DataHash: dataHash.String(), NoncePreimage: hex.EncodeToString(noncePreimage),
				CalculatedHash: hex.EncodeToString(calculated), CalculatedUint64: strconv.FormatUint(binary.LittleEndian.Uint64(calculated[:8]), 10),
				ProducerThresholdStatus: "SKIPPED_ZERO_DIFFICULTY", NonceMatches: pow.CheckPoWNonce(b)}
			// The producer helper divides by difficulty. It is only called for the
			// selected nonzero values; this is not a qualification of nil/zero calls.
			if difficulty != 0 {
				threshold := pow.GetThresholdByDifficulty(new(big.Int).SetUint64(difficulty))
				var thresholdBytes [8]byte
				binary.LittleEndian.PutUint64(thresholdBytes[:], threshold)
				probe.ProducerThresholdStatus = "RETURNED"
				probe.ProducerThreshold = strconv.FormatUint(threshold, 10)
				probe.ProducerThresholdBytes = hex.EncodeToString(thresholdBytes[:])
			}
			after, err := json.Marshal(b)
			if err != nil || !bytes.Equal(before, after) {
				return fmt.Errorf("PoW helper changed selected block")
			}
			probes = append(probes, probe)
			for _, method := range []string{"AccountBlock", "AccountBlockTransaction"} {
				r, err := recordPoW(raw, profile, method, difficulty, nonce)
				if err != nil {
					return err
				}
				observations = append(observations, r)
			}
		}
	}
	out := struct {
		Format       int               `json:"format_version"`
		Source       map[string]any    `json:"source"`
		Inputs       map[string]string `json:"input_files_sha256"`
		Scope        map[string]bool   `json:"scope"`
		Probes       []powProbe        `json:"pow_probes"`
		Observations []observation     `json:"observations"`
	}{1, map[string]any{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit,
		"module_version": nodeVersion, "module_sum": nodeSum, "functions": []string{"pow.GetAccountBlockHash", "pow.CheckPoWNonce",
			"pow.GetThresholdByDifficulty", "common/crypto.Hash", "verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}},
		map[string]string{"account-segments.json": segmentsPin}, map[string]bool{"actual_node_entry_point_execution": true,
			"actual_memory_account_and_momentum_stores": true, "actual_pow_helpers": true, "synthetic_context_handle_selection": true,
			"synthetic_unsigned_momentum_metadata": true, "original_claimed_hashes_and_signatures_preserved": true,
			"unsigned_difficulty_selection": true, "zero_difficulty_producer_helper_called": false,
			"nonce_generation": false, "wallet_api_calls": false, "new_signatures_generated": false,
			"disk_database_opened": false, "network_transport": false, "full_node_validation": false,
			"authenticated_context": false, "canonicality": false, "consensus_finality": false, "state_value_acceptance": false}, probes, observations}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		return err
	}
	// Preserve actual observations before checking the selected finite inventory.
	matches, rejects, powMatches := 0, 0, 0
	for _, p := range probes {
		if p.NonceMatches {
			powMatches++
		}
	}
	for _, r := range observations {
		if r.Result == "MATCH" {
			matches++
		}
		if r.Result == "REJECT" && r.Error != "unselected_error" {
			rejects++
		}
	}
	if len(probes) != 32 || powMatches != 10 || len(observations) != 64 || matches != 11 || rejects != 53 {
		return fmt.Errorf("actual finite PoW inventory differs")
	}
	return nil
}
