//go:build candidate_core_init_failure

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/inconshreveable/log15"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/common"
	"github.com/zenon-network/go-zenon/zenon"
)

func main() {
	root := flag.String("root", "", "new caller-owned empty physical directory")
	mode := flag.String("case", "", "selected real-manager Init failure condition")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" {
		fmt.Fprintln(os.Stderr, "explicit owned case required")
		os.Exit(64)
	}
	output := os.Stdout
	os.Stdout = os.Stderr
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Init failure observation UNKNOWN: unhandled probe panic")
			os.Exit(2)
		}
	}()
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	g, err := genesis.MakeEmbeddedGenesisConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "source genesis preparation failed")
		os.Exit(2)
	}
	cfg := &zenon.Config{MinPeers: 1, MinConnectedPeers: 1, DataDir: *root,
		GenesisConfig: g, StateTreeArchive: false}
	observation, captureErr := zenon.CandidateCoreInitFailureCapture(cfg, *mode)
	status := "OBSERVED"
	if captureErr != nil {
		status = "UNKNOWN"
	}
	err = json.NewEncoder(output).Encode(map[string]any{
		"schema": "experimental-core-Init-failure-observation-v1", "status": status,
		"genesis": g.GetGenesisMomentum().Identifier(), "observation": observation,
		"core_Start_selected": false, "network_or_wallet_or_signing_selected": false,
		"accepted_header_binding": false, "production_state_value_accepted": false,
	})
	if err != nil || captureErr != nil {
		fmt.Fprintln(os.Stderr, "Init failure observation UNKNOWN")
		os.Exit(2)
	}
}
