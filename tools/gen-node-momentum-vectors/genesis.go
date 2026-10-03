package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

const (
	historicalGenesisRepository = "https://github.com/HyperCore-Team/dockerized-testnet"
	historicalGenesisCommit     = "a8db3e7e42718fc025e604dcb45e4690fd2f3d7a"
	historicalGenesisPath       = "data/configs/genesis.json"
	historicalGenesisSHA256     = "a293ee85c4273e5119f18e23f5929f8382981be904109b53070f0fe6a89e1240"
)

type historicalGenesisCorpus struct {
	FormatVersion int    `json:"format_version"`
	Source        source `json:"source"`
	GenesisConfig struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Path       string `json:"path"`
		SHA256     string `json:"sha256"`
	} `json:"genesis_config"`
	Anchor anchor `json:"anchor"`
	Vector vector `json:"vector"`
}

// This reconstructs an unchanged historical configuration through the node's
// complete genesis/account-pool/VM path for offline compatibility checks. The
// caller supplies the exact source file; this command does not fetch it, observe
// a running network, or establish a current testnet or canonical anchor.
func writeHistoricalTestnetGenesisVector(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read the historical testnet genesis configuration")
	}
	sum := sha256.Sum256(raw)
	configSHA256 := hex.EncodeToString(sum[:])
	if configSHA256 != historicalGenesisSHA256 {
		return fmt.Errorf("historical testnet genesis configuration differs from the pinned source")
	}
	var config genesis.GenesisConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return fmt.Errorf("pinned historical testnet genesis configuration cannot be decoded: %w", err)
	}
	// Configure the logger once before node construction. Its synchronized
	// handler also covers child loggers created during package initialization;
	// no temporary stdout or handler swap can mix node logs with fixture JSON
	// or expose the caller's private file path in node-loader diagnostics.
	log15.Root().SetHandler(log15.DiscardHandler())
	if err := genesis.CheckGenesis(&config); err != nil {
		return fmt.Errorf("pinned historical testnet genesis configuration fails node validation: %w", err)
	}
	// The node loader takes a file path. Give it a private snapshot of the
	// bytes whose fixed source hash was checked, so a concurrent replacement
	// of the caller's input cannot produce evidence from a different config.
	file, err := os.CreateTemp("", "zenon-spv-genesis-*.json")
	if err != nil {
		return fmt.Errorf("cannot prepare the validated genesis configuration")
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return fmt.Errorf("cannot prepare the validated genesis configuration")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot prepare the validated genesis configuration")
	}
	// The node loader validates the config and calls NewGenesis. NewGenesis
	// builds genesis account blocks, their contract changes and the momentum
	// transaction using the node's account pool and genesis VM implementation.
	store, err := genesis.ReadGenesisConfigFromFile(file.Name())
	if err != nil || store == nil {
		return fmt.Errorf("pinned node could not construct the historical testnet genesis")
	}
	momentum := store.GetGenesisMomentum()
	transaction := store.GetGenesisTransaction()
	if momentum == nil || transaction == nil || transaction.Momentum != momentum || transaction.Changes == nil {
		return fmt.Errorf("pinned node returned incomplete genesis evidence")
	}
	if momentum.ChainIdentifier != config.ChainIdentifier || momentum.ChainIdentifier != store.ChainIdentifier() ||
		momentum.ChainIdentifier != 3 || momentum.Height != 1 || momentum.Version != 1 ||
		momentum.PreviousHash != (types.Hash{}) || len(momentum.PublicKey) != 0 || len(momentum.Signature) != 0 {
		return fmt.Errorf("pinned node returned an unexpected genesis envelope")
	}
	if db.PatchHash(transaction.Changes) != momentum.ChangesHash || momentum.ComputeHash() != momentum.Hash {
		return fmt.Errorf("pinned node genesis hashes are internally inconsistent")
	}
	c := historicalGenesisCorpus{FormatVersion: 1, Source: source{
		Repository: "https://github.com/zenon-network/go-zenon", Commit: nodeCommit,
		ModuleVersion: nodeVersion, ModuleSum: nodeSum,
	}, Anchor: anchor{ChainID: momentum.ChainIdentifier, Height: momentum.Height, Hash: momentum.Hash.String()},
		Vector: projectVector("historical-testnet-genesis", momentum)}
	c.GenesisConfig.Repository, c.GenesisConfig.Commit = historicalGenesisRepository, historicalGenesisCommit
	c.GenesisConfig.Path, c.GenesisConfig.SHA256 = historicalGenesisPath, configSHA256
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
