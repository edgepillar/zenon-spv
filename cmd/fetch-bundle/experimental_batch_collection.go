// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const experimentalCollectionCommand = "experimental-batch-entry"
const experimentalCollectionUsage = "Usage: fetch-bundle experimental-batch-entry --rpc <url> --chain-id <n> --anchor-height <n> --anchor-hash <64-hex> --height <n> --header-hash <64-hex> --tip-height <n> --tip-hash <64-hex> --domain-id <u32> --batch-id <u64> [--compare-gateway] [--timeout <duration>]\n"

type collectionFlag struct {
	flag.Value
	supplied bool
	invalid  bool
}

func (f *collectionFlag) String() string {
	if f.Value == nil {
		return ""
	}
	return f.Value.String()
}

func (f *collectionFlag) Set(raw string) error {
	if f.supplied {
		f.invalid = true
		return nil
	}
	f.supplied = true
	f.invalid = f.Value.Set(raw) != nil
	return nil // Do not let flag echo private arguments in parse errors.
}

func (f *collectionFlag) IsBoolFlag() bool {
	v, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && v.IsBoolFlag()
}

func collectionHash(value string) (chain.Hash, bool) {
	if len(value) != 64 {
		return chain.Hash{}, false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return chain.Hash{}, false
		}
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return chain.Hash{}, false
	}
	h := chain.Hash(raw)
	return h, !h.IsZero()
}

// This explicit mode is dispatched before the native environment/default flow.
// Collection has no checkpoint export, state writer or acceptance guarantee.
func runExperimentalCollection(parent context.Context, args []string, stdout, stderr io.Writer, clientFor func(string) *fetch.Client) int {
	fail := func(code int, category string) int {
		_, _ = fmt.Fprintln(stderr, "fetch-bundle experimental collection:", category)
		return code
	}
	fs := flag.NewFlagSet(experimentalCollectionCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rpc := fs.String("rpc", "", "explicit RPC endpoint")
	chainID := fs.Uint64("chain-id", 0, "locally selected non-mainnet chain")
	anchorHeight := fs.Uint64("anchor-height", 0, "locally selected anchor height")
	anchorHash := fs.String("anchor-hash", "", "locally selected anchor hash")
	height := fs.Uint64("height", 0, "locally selected proof height")
	headerHash := fs.String("header-hash", "", "locally selected proof header hash")
	tipHeight := fs.Uint64("tip-height", 0, "locally selected exact tip")
	tipHash := fs.String("tip-hash", "", "locally selected tip hash")
	domain := fs.Uint64("domain-id", 0, "locally selected domain (uint32)")
	batch := fs.Uint64("batch-id", 0, "locally selected batch (uint64)")
	compare := fs.Bool("compare-gateway", false, "also collect the selected frontier DTO")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout (positive, at most 10m)")
	guards := make(map[string]*collectionFlag)
	fs.VisitAll(func(f *flag.Flag) { guard := &collectionFlag{Value: f.Value}; f.Value = guard; guards[f.Name] = guard })
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		n, err := io.WriteString(stdout, experimentalCollectionUsage)
		if err != nil || n != len(experimentalCollectionUsage) {
			return fail(70, "output failed")
		}
		return 0
	} else if err != nil || fs.NArg() != 0 {
		return fail(64, "invalid arguments")
	}
	for name, guard := range guards {
		if guard.invalid || !guard.supplied && name != "timeout" && name != "compare-gateway" {
			return fail(64, "invalid arguments")
		}
	}
	selected := fetch.CandidateBatchCollectionSelection{ChainID: *chainID, AnchorHeight: *anchorHeight, Height: *height,
		TipHeight: *tipHeight, Settlement: verify.ExperimentalBatchEntrySettlementAddress(), BatchID: *batch}
	var ok bool
	if selected.AnchorHash, ok = collectionHash(*anchorHash); !ok {
		return fail(64, "invalid arguments")
	}
	if selected.HeaderHash, ok = collectionHash(*headerHash); !ok {
		return fail(64, "invalid arguments")
	}
	if selected.TipHash, ok = collectionHash(*tipHash); !ok {
		return fail(64, "invalid arguments")
	}
	endpoint, err := url.Parse(*rpc)
	if err != nil || endpoint.Host == "" || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.Fragment != "" ||
		*chainID == verify.MainnetChainID || *domain > math.MaxUint32 || *timeout <= 0 || *timeout > 10*time.Minute {
		return fail(64, "invalid arguments")
	}
	selected.DomainID = uint32(*domain)
	if selected.Validate() != nil {
		return fail(64, "invalid arguments")
	}
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	client := clientFor(*rpc)
	data, err := client.FetchCandidateBatchEntryBundle(ctx, selected, *compare)
	if err != nil {
		return fail(1, "candidate acquisition failed")
	}
	n, err := stdout.Write(data)
	if err != nil || n != len(data) {
		return fail(70, "output failed")
	}
	return 0
}
