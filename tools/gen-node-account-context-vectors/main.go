// Command gen-node-account-context-vectors records the shared missing-state
// context gate of two actual node entry points. It imports no SPV code, creates
// no keys or signatures, and opens no database or network connection.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
)

type plan struct {
	AcknowledgementStorePresent bool   `json:"ack_store_present"`
	GlobalMomentumPresent       bool   `json:"global_momentum_present"`
	GlobalAccountPresent        bool   `json:"global_account_present"`
	FrontierPresent             bool   `json:"frontier_present"`
	FrontierHeight              uint64 `json:"frontier_height"`
	FrontierError               bool   `json:"frontier_error"`
	ByHashPresent               bool   `json:"by_hash_present"`
	ByHashError                 bool   `json:"by_hash_error"`
}
type call struct {
	Method     string            `json:"method"`
	Address    string            `json:"address,omitempty"`
	Identifier *types.HashHeight `json:"identifier,omitempty"`
	Hash       *types.Hash       `json:"hash,omitempty"`
}
type observation struct {
	Name         string          `json:"name"`
	Baseline     string          `json:"baseline"`
	Profile      string          `json:"profile"`
	Method       string          `json:"method"`
	Plan         plan            `json:"store_plan"`
	Block        json.RawMessage `json:"account_block"`
	ComputedHash types.Hash      `json:"computed_hash"`
	Result       string          `json:"node_context_result"`
	Error        string          `json:"node_error"`
	Calls        []call          `json:"context_calls"`
}

// Only preselected getContext methods are implemented. Any further validator,
// store or consensus call panics and fails generation rather than inventing state.
type opaqueAcknowledgement struct{ store.Momentum }
type recordingChain struct {
	chain.Chain
	calls *[]call
	plan  plan
}

func (c recordingChain) GetAccountStore(address types.Address, id types.HashHeight) store.Account {
	*c.calls = append(*c.calls, call{Method: "Chain.GetAccountStore", Address: address.String(), Identifier: &id})
	return nil
}
func (c recordingChain) GetMomentumStore(id types.HashHeight) store.Momentum {
	*c.calls = append(*c.calls, call{Method: "Chain.GetMomentumStore", Identifier: &id})
	if !c.plan.AcknowledgementStorePresent {
		return nil
	}
	return opaqueAcknowledgement{}
}
func (c recordingChain) GetFrontierMomentumStore() store.Momentum {
	*c.calls = append(*c.calls, call{Method: "Chain.GetFrontierMomentumStore"})
	if !c.plan.GlobalMomentumPresent {
		return nil
	}
	return recordingMomentum{calls: c.calls, plan: c.plan}
}

type recordingMomentum struct {
	store.Momentum
	calls *[]call
	plan  plan
}

func (m recordingMomentum) GetAccountStore(address types.Address) store.Account {
	*m.calls = append(*m.calls, call{Method: "Momentum.GetAccountStore", Address: address.String()})
	if !m.plan.GlobalAccountPresent {
		return nil
	}
	return recordingAccount{calls: m.calls, plan: m.plan}
}

type recordingAccount struct {
	store.Account
	calls *[]call
	plan  plan
}

func (a recordingAccount) Frontier() (*nom.AccountBlock, error) {
	*a.calls = append(*a.calls, call{Method: "Account.Frontier"})
	if a.plan.FrontierError {
		return nil, errors.New("selected frontier error")
	}
	if !a.plan.FrontierPresent {
		return nil, nil
	}
	return &nom.AccountBlock{Height: a.plan.FrontierHeight}, nil
}
func (a recordingAccount) ByHash(hash types.Hash) (*nom.AccountBlock, error) {
	*a.calls = append(*a.calls, call{Method: "Account.ByHash", Hash: &hash})
	if a.plan.ByHashError {
		return nil, errors.New("selected by-hash error")
	}
	if !a.plan.ByHashPresent {
		return nil, nil
	}
	return &nom.AccountBlock{Height: 1, Hash: hash}, nil
}

func invoke(method string, b *nom.AccountBlock, p plan, calls *[]call) (err error, panicValue any) {
	defer func() { panicValue = recover() }()
	v := verifier.NewAccountBlockVerifier(recordingChain{calls: calls, plan: p}, nil)
	switch method {
	case "AccountBlock":
		err = v.AccountBlock(b)
	case "AccountBlockTransaction":
		err = v.AccountBlockTransaction(&nom.AccountBlockTransaction{Block: b})
	default:
		panic("unselected method")
	}
	return
}
func record(baseline, profile, method string, b *nom.AccountBlock, p plan) (observation, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return observation{}, err
	}
	r := observation{Name: baseline + "/" + profile + "/" + method, Baseline: baseline, Profile: profile, Method: method,
		Plan: p, Block: raw, ComputedHash: b.ComputeHash(), Calls: make([]call, 0)}
	err, panicValue := invoke(method, b, p, &r.Calls)
	after, e := json.Marshal(b)
	if e != nil || !bytes.Equal(raw, after) {
		return r, fmt.Errorf("node changed selected block")
	}
	expectedPanic := profile == "global-momentum-nil" || profile == "global-account-nil" || profile == "global-frontier-nil"
	if panicValue != nil {
		_, isRuntime := panicValue.(runtime.Error)
		if !expectedPanic || !isRuntime || !strings.Contains(fmt.Sprint(panicValue), "nil pointer dereference") {
			return r, fmt.Errorf("unexpected context panic")
		}
		r.Result, r.Error = "PANIC", "nil_pointer"
		return r, nil
	}
	if expectedPanic {
		return r, fmt.Errorf("selected nil context did not panic")
	}
	r.Result = "REJECT"
	switch {
	case err == nil:
		return r, fmt.Errorf("context-only selection reached validator success")
	case errors.Is(err, verifier.ErrABMHeightMissing):
		r.Error = "height_missing"
	case errors.Is(err, verifier.ErrABPrevHashMustBeZero):
		r.Error = "previous_must_be_zero"
	case errors.Is(err, verifier.ErrABPrevHashMissing):
		r.Error = "previous_missing"
	case errors.Is(err, verifier.ErrABMAMustNotBeZero):
		r.Error = "ack_zero"
	case errors.Is(err, verifier.ErrABMAMissing):
		r.Error = "ack_store_missing"
	case errors.Is(err, verifier.ErrABPreviousMissing):
		r.Error = "account_previous_missing"
	case errors.Is(err, verifier.ErrABPrevHeightExists):
		r.Error = "previous_height_exists"
	case errors.Is(err, verifier.ErrABPrevHasCementedOnTop):
		r.Error = "previous_cemented"
	case errors.Is(err, verifier.ErrVerifierInternal):
		r.Error = "internal_store_error"
	default:
		return r, fmt.Errorf("unselected context error")
	}
	return r, nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: gen-node-account-context-vectors SEGMENTS_FIXTURE")
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
			if _, exists := baselines[v.Name]; exists {
				return fmt.Errorf("duplicate baseline")
			}
			baselines[v.Name] = v.RPC
		}
	}
	if len(baselines) != 4 {
		return fmt.Errorf("incomplete input inventory")
	}
	observations := make([]observation, 0, 50)
	for _, baseline := range []string{"user-type-2", "embedded-type-5"} {
		profiles := []string{"height-zero", "previous-nonzero-at-one", "previous-zero-at-two", "ack-zero",
			"previous-missing", "previous-height-exists", "previous-cemented", "frontier-error", "by-hash-error",
			"global-momentum-nil", "global-account-nil", "global-frontier-nil"}
		if baseline == "embedded-type-5" {
			profiles = append(profiles, "ack-store-missing")
		}
		for _, profile := range profiles {
			for _, method := range []string{"AccountBlock", "AccountBlockTransaction"} {
				var b nom.AccountBlock
				if err := json.Unmarshal(baselines[baseline], &b); err != nil {
					return err
				}
				p := plan{AcknowledgementStorePresent: true, GlobalMomentumPresent: true, GlobalAccountPresent: true, FrontierPresent: true}
				switch profile {
				case "height-zero":
					b.Height = 0
				case "previous-nonzero-at-one":
					b.PreviousHash[0] ^= 1
				case "previous-zero-at-two":
					b.Height = 2
				case "ack-zero":
					b.MomentumAcknowledged = types.HashHeight{}
				case "previous-missing":
				case "previous-height-exists":
					p.FrontierHeight = 1
				case "previous-cemented":
					p.FrontierHeight = 1
					p.ByHashPresent = true
				case "frontier-error":
					p.FrontierError = true
				case "by-hash-error":
					p.FrontierHeight = 1
					p.ByHashError = true
				case "global-momentum-nil":
					p.GlobalMomentumPresent = false
				case "global-account-nil":
					p.GlobalAccountPresent = false
				case "global-frontier-nil":
					p.FrontierPresent = false
				case "ack-store-missing":
					p.AcknowledgementStorePresent = false
				default:
					return fmt.Errorf("unselected profile")
				}
				r, err := record(baseline, profile, method, &b, p)
				if err != nil {
					return err
				}
				observations = append(observations, r)
			}
		}
	}
	if len(observations) != 50 {
		return fmt.Errorf("incomplete actual method observations")
	}
	rejects, panics := 0, 0
	for _, r := range observations {
		if r.Result == "PANIC" {
			panics++
		} else {
			rejects++
		}
	}
	if rejects != 38 || panics != 12 {
		return fmt.Errorf("selected outcome inventory differs")
	}
	out := struct {
		FormatVersion int               `json:"format_version"`
		Source        map[string]any    `json:"source"`
		InputFiles    map[string]string `json:"input_files_sha256"`
		Observations  []observation     `json:"observations"`
		Scope         map[string]bool   `json:"scope"`
	}{1, map[string]any{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit, "module_version": nodeVersion, "module_sum": nodeSum,
		"methods": []string{"verifier.AccountBlockVerifier.AccountBlock", "verifier.AccountBlockVerifier.AccountBlockTransaction"}},
		map[string]string{"account-segments.json": segmentsPin}, observations,
		map[string]bool{"actual_node_entry_point_execution": true, "synthetic_recording_store": true, "context_failure_only": true, "programmatic_nil_store_inputs": true,
			"basic_account_checks_reached": false, "hash_signature_checks_reached": false, "new_signatures_generated": false, "database_opened": false,
			"network_transport": false, "full_node_validation": false, "authenticated_context": false, "canonicality": false, "consensus_finality": false, "state_value_acceptance": false}}
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
