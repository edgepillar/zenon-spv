// Command verify-mainnet-genesis is a maintainer-side cross-check
// for the embedded mainnet genesis trust root.
//
// Usage:
//
//	verify-mainnet-genesis --peers <url1>,<url2>,<url3> [--expected <hex>]
//
// What it does:
//
//  1. Fetches height 1 from every distinct configured endpoint using
//     ledger.getMomentumsByHeight(1, 1).
//  2. Recomputes each claimed hash from the genesis envelope and
//     requires complete peer agreement through the shared RPC client.
//  3. Requires the mainnet genesis shape and the embedded mainnet hash,
//     or an explicitly supplied nonzero --expected hash.
//
// Output: a human-readable report only after every check succeeds.
//
// This tool is NOT linked into the zenon-spv binary. It runs at
// release time when the maintainer wants to bump or re-verify the
// embedded mainnet anchor. Peer agreement is an observation cross-check;
// endpoint independence and anchor provenance remain external trust inputs.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "verify-mainnet-genesis:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return runWithOutput(args, os.Stdout, os.Stderr)
}

func runWithOutput(args []string, stdout, diagnostics io.Writer) error {
	anchor, err := verify.MainnetGenesis()
	if err != nil {
		return errors.New("cannot load embedded mainnet anchor")
	}
	fs := flag.NewFlagSet("verify-mainnet-genesis", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS)")
	fs.Lookup("peers").DefValue = ""
	expected := fs.String("expected", hex.EncodeToString(anchor.HeaderHash[:]), "expected nonzero 64-hex hash (defaults to the embedded mainnet anchor)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall RPC timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	urls := splitPeers(*peersFlag)
	if len(urls) < 2 {
		return errors.New("at least two --peers required (single-peer means no cross-check)")
	}
	var expectedHash chain.Hash
	s := strings.TrimPrefix(*expected, "0x")
	if len(s) != 2*chain.HashSize {
		return errors.New("--expected requires a nonzero 64-hex hash")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return errors.New("--expected requires a nonzero 64-hex hash")
	}
	copy(expectedHash[:], raw)
	if expectedHash.IsZero() {
		return errors.New("--expected requires a nonzero 64-hex hash")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	multi := fetch.NewMultiClient(urls)
	headers, err := multi.FetchByHeight(ctx, verify.MainnetHeight, 1)
	if err != nil {
		return err
	}
	header := headers[0]
	if header.ChainIdentifier != verify.MainnetChainID || header.Version != 1 || !header.PreviousHash.IsZero() {
		return errors.New("observation does not match the mainnet genesis shape")
	}
	if header.HeaderHash != expectedHash {
		return errors.New("genesis observation differs from the expected hash")
	}

	label := "the embedded mainnet anchor"
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expected" {
			label = "the explicit expected hash"
		}
	})
	var output bytes.Buffer
	fmt.Fprintf(&output, "OK: %d/%d configured peers match %s.\n", len(urls), len(urls), label)
	fmt.Fprintln(&output, "OK: chain_id=1 height=1 version=1; hash recomputed from the genesis envelope.")
	fmt.Fprintf(&output, "Observed hash: %x\n", header.HeaderHash)
	fmt.Fprintln(&output, "Peer agreement does not establish operator independence, canonical history, or finality.")
	n, err := stdout.Write(output.Bytes())
	if err == nil && n != output.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &genesisOutputError{cause: err}
	}
	return nil
}

type genesisOutputError struct{ cause error }

func (e *genesisOutputError) Error() string { return "genesis report failed; stdout may be incomplete" }
func (e *genesisOutputError) Unwrap() error { return e.cause }

func splitPeers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
