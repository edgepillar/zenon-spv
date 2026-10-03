// Command verify-mainnet-genesis is a maintainer-side cross-check
// for the embedded mainnet genesis trust root or an explicitly selected
// height-1 custom genesis configuration.
//
// Usage:
//
//	verify-mainnet-genesis --peers <url1>,<url2>,<url3> [--expected <hex>]
//	verify-mainnet-genesis --peers <url1>,<url2>,<url3> --genesis-config <file>
//
// What it does:
//
//  1. Fetches height 1 from every distinct configured endpoint using
//     ledger.getMomentumsByHeight(1, 1).
//  2. Recomputes each claimed hash from the genesis envelope and
//     requires complete peer agreement through the shared RPC client.
//  3. Requires the mainnet genesis shape and the embedded mainnet hash,
//     or an explicitly supplied nonzero --expected hash. The opt-in
//     --genesis-config mode selects both chain ID and hash from a strict file.
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
	var genesisConfig string
	var genesisConfigCount int
	fs.Func("genesis-config", "strict custom genesis file with explicit chain_id, height=1 and header_hash; conflicts with --expected", func(value string) error {
		genesisConfig, genesisConfigCount = value, genesisConfigCount+1
		return nil
	})
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
	explicitExpected := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expected" {
			explicitExpected = true
		}
	})
	if genesisConfigCount > 1 {
		return errors.New("duplicate --genesis-config option")
	}
	if genesisConfigCount > 0 && explicitExpected {
		return errors.New("--genesis-config and --expected are mutually exclusive")
	}
	if genesisConfigCount > 0 {
		custom, err := verify.LoadGenesisFromConfig(genesisConfig)
		if err != nil {
			return errors.New("invalid --genesis-config")
		}
		if custom.Height != verify.MainnetHeight {
			return errors.New("--genesis-config requires a height-1 genesis anchor")
		}
		anchor = custom
	}
	urls := splitPeers(*peersFlag)
	if len(urls) < 2 {
		return errors.New("at least two --peers required (single-peer means no cross-check)")
	}
	expectedHash := anchor.HeaderHash
	if genesisConfigCount == 0 {
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
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	multi := fetch.NewMultiClient(urls)
	headers, err := multi.FetchByHeight(ctx, verify.MainnetHeight, 1)
	if err != nil {
		return err
	}
	header := headers[0]
	if header.ChainIdentifier != anchor.ChainID || header.Height != anchor.Height || header.Version != 1 || !header.PreviousHash.IsZero() {
		if genesisConfigCount > 0 {
			return errors.New("observation does not match the explicit genesis shape")
		}
		return errors.New("observation does not match the mainnet genesis shape")
	}
	if header.HeaderHash != expectedHash {
		return errors.New("genesis observation differs from the expected hash")
	}

	label := "the embedded mainnet anchor"
	if genesisConfigCount > 0 {
		label = "the explicit genesis configuration"
	} else if explicitExpected {
		label = "the explicit expected hash"
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "OK: %d/%d configured peers match %s.\n", len(urls), len(urls), label)
	fmt.Fprintf(&output, "OK: chain_id=%d height=%d version=1; hash recomputed from the genesis envelope.\n", anchor.ChainID, anchor.Height)
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
