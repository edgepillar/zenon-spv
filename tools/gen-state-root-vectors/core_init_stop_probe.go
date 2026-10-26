//go:build candidate_core_init_stop

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
	root := flag.String("root", "", "new caller-owned empty directory")
	mode := flag.String("case", "", "explicit finite lifecycle case")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" { panic("explicit owned case required") }
	info, err := os.Lstat(*root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { panic("owned directory required") }
	entries, err := os.ReadDir(*root)
	if err != nil || len(entries) != 0 { panic("new empty directory required") }
	output := os.Stdout
	os.Stdout = os.Stderr
	log15.Root().SetHandler(log15.DiscardHandler())
	common.ChainLogger.SetHandler(log15.DiscardHandler())
	g, err := genesis.MakeEmbeddedGenesisConfig()
	if err != nil { panic(err) }
	cfg := &zenon.Config{MinPeers:1, MinConnectedPeers:1, DataDir:*root, GenesisConfig:g, StateTreeArchive:false}
	result, err := zenon.CandidateCoreInitStopCapture(cfg, *mode)
	if err != nil { panic(err) }
	err = json.NewEncoder(output).Encode(map[string]any{
		"schema":"experimental-core-Init-Stop-observation-v1",
		"genesis":g.GetGenesisMomentum().Identifier(), "observation":result,
		"core_Start_selected":false, "network_or_wallet_or_signing_selected":false,
		"accepted_header_binding":false, "production_state_value_accepted":false,
	})
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
