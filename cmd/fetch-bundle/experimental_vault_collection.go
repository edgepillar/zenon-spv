// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
)

const experimentalVaultCollectionCommand = "experimental-vault-balance"
const experimentalVaultCollectionUsage = "Usage: fetch-bundle experimental-vault-balance --rpc <url> --domain-id <u32> --batch-id <u64> --contract-id <64-hex> --account-hex <40-hex> --token-standard-hex <20-hex> [--timeout <duration>]\n"

func runExperimentalVaultCollection(parent context.Context, args []string, stdout, stderr io.Writer, clientFor func(string) *fetch.Client) int {
	fail := func(code int, message string) int {
		_, _ = fmt.Fprintln(stderr, "fetch-bundle experimental vault balance:", message)
		return code
	}
	fs := flag.NewFlagSet(experimentalVaultCollectionCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rpc := fs.String("rpc", "", "explicit read-only gateway endpoint")
	domain := fs.Uint64("domain-id", 0, "selected domain (uint32)")
	batch := fs.Uint64("batch-id", 0, "selected numeric batch (uint64)")
	contract := fs.String("contract-id", "", "selected vault contract ID")
	account := fs.String("account-hex", "", "selected L1 account bytes")
	token := fs.String("token-standard-hex", "", "selected token standard bytes")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout (positive, at most 10m)")
	guards := make(map[string]*collectionFlag)
	fs.VisitAll(func(f *flag.Flag) {
		guard := &collectionFlag{Value: f.Value}
		f.Value, guards[f.Name] = guard, guard
	})
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		if err := writeComplete(stdout, []byte(experimentalVaultCollectionUsage)); err != nil {
			return fail(70, "output failed")
		}
		return 0
	} else if err != nil || fs.NArg() != 0 {
		return fail(64, "invalid arguments")
	}
	for name, guard := range guards {
		if guard.invalid || !guard.supplied && name != "timeout" {
			return fail(64, "invalid arguments")
		}
	}
	endpoint, err := url.Parse(*rpc)
	if err != nil || endpoint.Host == "" || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.Fragment != "" ||
		*domain == 0 || *domain > math.MaxUint32 || *timeout <= 0 || *timeout > 10*time.Minute {
		return fail(64, "invalid arguments")
	}
	vault, err := proof.ParseCandidatePhase1VaultSelection(*contract, *account, *token)
	if err != nil {
		return fail(64, "invalid arguments")
	}
	key := vault.LocalKey()
	selection := fetch.CandidateZenoStorageSelection{DomainID: uint32(*domain), BatchID: *batch,
		Path: proof.CandidatePhase1StoragePath(vault.ContractID, key[:])}

	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	raw, err := clientFor(*rpc).FetchCandidateZenoStorage(ctx, selection)
	if errors.Is(err, fetch.ErrCandidateZenoStorageUnavailable) {
		return fail(2, "proof unavailable")
	}
	if err != nil {
		return fail(1, "candidate acquisition failed")
	}
	if err := writeComplete(stdout, append(raw, '\n')); err != nil {
		return fail(70, "output failed")
	}
	return 0
}
