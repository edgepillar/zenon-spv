// Command gen-node-static-vectors records actual node MomentumStatic results.
// It reads only preserved synthetic fixtures. It creates no keys or signatures,
// opens no chain, and imports no SPV verifier code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/verifier"
)

const (
	nodeModule  = "github.com/zenon-network/go-zenon"
	nodeVersion = "v0.0.8-alphanet.0.20261009223306-c64ed6279ff1"
	nodeCommit  = "c64ed6279ff1d07335dab0ac36156dec8b5b71e9"
	nodeSum     = "h1:3Vyk+6hw2dcWJLg15JEq7ITFOkaYvrVyI+W8Qb3Jlr4="
	momentumPin = "91747c6b7adba4e256fcb397d64348117edc9df874df7f25e2c56b776426dec9"
	genesisPin  = "c43c63adecc5e0ccbca5a0be40070ac911d71b7466f998801c84aebc23d7f89b"
)

type vector struct {
	Name     string          `json:"name"`
	Momentum json.RawMessage `json:"momentum"`
}

type header struct {
	Version         uint64     `json:"version"`
	ChainIdentifier uint64     `json:"chainIdentifier"`
	Hash            types.Hash `json:"hash"`
	PreviousHash    types.Hash `json:"previousHash"`
	Height          uint64     `json:"height"`
	Timestamp       uint64     `json:"timestamp"`
	DataHash        types.Hash `json:"dataHash"`
	ContentHash     types.Hash `json:"contentHash"`
	ChangesHash     types.Hash `json:"changesHash"`
	PublicKey       []byte     `json:"publicKey"`
	Signature       []byte     `json:"signature"`
	NextFusionPrice uint64     `json:"nextFusionPrice"`
	NextWorkPrice   uint64     `json:"nextWorkPrice"`
}

type observation struct {
	Name         string        `json:"name"`
	Baseline     string        `json:"baseline"`
	Momentum     *nom.Momentum `json:"momentum"`
	Header       *header       `json:"header"`
	ComputedHash *types.Hash   `json:"computed_hash"`
	NodeResult   string        `json:"node_static_result"`
	NodeError    string        `json:"node_error"`
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

func record(name, baseline string, m *nom.Momentum) (observation, error) {
	r := observation{Name: name, Baseline: baseline, Momentum: m}
	if m != nil {
		hash := m.ComputeHash()
		r.ComputedHash = &hash
		r.Header = &header{m.Version, m.ChainIdentifier, m.Hash, m.PreviousHash, m.Height, m.TimestampUnix,
			types.NewHash(m.Data), m.Content.Hash(), m.ChangesHash, m.PublicKey, m.Signature, m.NextFusionPrice, m.NextWorkPrice}
	}
	err := verifier.MomentumStatic(m)
	r.NodeResult = "REJECT"
	switch {
	case err == nil:
		r.NodeResult = "MATCH"
	case m == nil && err.Error() == "missing momentum":
		r.NodeError = "missing_momentum"
	case errors.Is(err, verifier.ErrMHashInvalid):
		r.NodeError = "hash_mismatch"
	case errors.Is(err, verifier.ErrMSignatureMissing):
		r.NodeError = "signature_missing"
	case errors.Is(err, verifier.ErrMPublicKeyMissing):
		r.NodeError = "public_key_missing"
	case errors.Is(err, verifier.ErrMSignatureInvalid):
		r.NodeError = "signature_invalid"
	case errors.Is(err, verifier.ErrVerifierInternal):
		r.NodeError = "internal_signature_format"
	default:
		return r, fmt.Errorf("unselected static error")
	}
	return r, nil
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: gen-node-static-vectors MOMENTUM_FIXTURE GENESIS_FIXTURE")
	}
	if err := checkNodePin(); err != nil {
		return err
	}
	var input struct {
		Vectors []vector `json:"vectors"`
		Chain   struct {
			Vectors []vector `json:"vectors"`
		} `json:"chain"`
		Transition struct {
			Vectors []vector `json:"vectors"`
		} `json:"transition"`
	}
	if err := readSelected(os.Args[1], momentumPin, &input); err != nil {
		return err
	}
	var genesis struct {
		Vector vector `json:"vector"`
	}
	if err := readSelected(os.Args[2], genesisPin, &genesis); err != nil {
		return err
	}
	all := append(append(input.Vectors, input.Chain.Vectors...), input.Transition.Vectors...)
	if len(all) != 21 {
		return fmt.Errorf("incomplete selected fixture")
	}
	observations := make([]observation, 0, 55)
	appendRecord := func(name, baseline string, m *nom.Momentum) error {
		r, err := record(name, baseline, m)
		if err == nil {
			observations = append(observations, r)
		}
		return err
	}
	baselines := make(map[string]json.RawMessage)
	for _, v := range all {
		var m nom.Momentum
		if err := json.Unmarshal(v.Momentum, &m); err != nil {
			return err
		}
		if err := appendRecord("baseline/"+v.Name, v.Name, &m); err != nil {
			return err
		}
		baselines[v.Name] = v.Momentum
	}
	if err := appendRecord("nil", "", nil); err != nil {
		return err
	}
	var g nom.Momentum
	if err := json.Unmarshal(genesis.Vector.Momentum, &g); err != nil {
		return err
	}
	if err := appendRecord("historical-unsigned-genesis", genesis.Vector.Name, &g); err != nil {
		return err
	}
	mutations := []struct {
		name string
		edit func(*nom.Momentum)
	}{
		{"hash", func(m *nom.Momentum) { m.Hash[0] ^= 1 }},
		{"data", func(m *nom.Momentum) { m.Data = append(m.Data, 255) }},
		{"chain", func(m *nom.Momentum) { m.ChainIdentifier ^= 1 }},
		{"height", func(m *nom.Momentum) { m.Height++ }},
		{"previous", func(m *nom.Momentum) { m.PreviousHash[0] ^= 1 }},
		{"signature-empty", func(m *nom.Momentum) { m.Signature = []byte{} }},
		{"public-key-empty", func(m *nom.Momentum) { m.PublicKey = []byte{} }},
		{"both-empty", func(m *nom.Momentum) { m.PublicKey = []byte{}; m.Signature = []byte{} }},
		{"public-key-short", func(m *nom.Momentum) { m.PublicKey = m.PublicKey[:31] }},
		{"public-key-long", func(m *nom.Momentum) { m.PublicKey = append(m.PublicKey, 0) }},
		{"signature-short", func(m *nom.Momentum) { m.Signature = m.Signature[:63] }},
		{"signature-long", func(m *nom.Momentum) { m.Signature = append(m.Signature, 0) }},
		{"signature-bit", func(m *nom.Momentum) { m.Signature[0] ^= 1 }},
		{"public-key-bit", func(m *nom.Momentum) { m.PublicKey[0] ^= 1 }},
		{"prices", func(m *nom.Momentum) { m.NextFusionPrice++; m.NextWorkPrice++ }},
		{"hash-and-empty", func(m *nom.Momentum) { m.Hash[0] ^= 1; m.PublicKey = []byte{}; m.Signature = []byte{} }},
	}
	for _, baseline := range []string{"v1-empty", "v2-nonzero-prices"} {
		for _, mutation := range mutations {
			var m nom.Momentum
			if err := json.Unmarshal(baselines[baseline], &m); err != nil {
				return err
			}
			mutation.edit(&m)
			if err := appendRecord(baseline+"/"+mutation.name, baseline, &m); err != nil {
				return err
			}
		}
	}
	if len(observations) != 55 {
		return fmt.Errorf("incomplete static observation sequence")
	}
	out := struct {
		FormatVersion int               `json:"format_version"`
		Source        map[string]string `json:"source"`
		InputFiles    map[string]string `json:"input_files_sha256"`
		Observations  []observation     `json:"observations"`
		Scope         map[string]bool   `json:"scope"`
	}{1, map[string]string{"repository": "https://github.com/zenon-network/go-zenon", "commit": nodeCommit,
		"module_version": nodeVersion, "module_sum": nodeSum, "function": "verifier.MomentumStatic"},
		map[string]string{"momentum-v1-v2.json": momentumPin, "historical-testnet-genesis.json": genesisPin},
		observations, map[string]bool{"actual_node_static_execution": true, "new_signatures_generated": false,
			"full_node_validation": false, "network_transport": false, "network_activation": false,
			"producer_authorization": false, "canonicality": false, "consensus_finality": false, "state_value_acceptance": false}}
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
