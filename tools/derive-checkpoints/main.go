// Command derive-checkpoints fetches Momentums at the requested
// heights from N peers, recomputes each from its signed envelope,
// and asserts unanimous agreement. The output is a Go literal block
// suitable for pasting into internal/verify/checkpoints.go's
// mainnetCheckpoints list.
//
// Usage:
//
//	derive-checkpoints --peers <url1>,<url2>,...  --heights 1000000,5000000,...
//
// The tool runs at release time, not at SPV runtime. The maintainer
// re-runs it against fresh peers before each release that bumps
// the embedded checkpoint list, and pastes the output into source.
//
// A checkpoint is a hard-coded weak-subjectivity defense per
// spec/spv-implementation-guide.md §2.5 — the verifier rejects any
// header at a checkpoint height whose hash differs from the
// embedded entry.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "derive-checkpoints:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return runWithOutput(args, os.Stdout, os.Stderr)
}

func runWithOutput(args []string, stdout, diagnostics io.Writer) error {
	fs := flag.NewFlagSet("derive-checkpoints", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS)")
	fs.Lookup("peers").DefValue = ""
	heightsFlag := fs.String("heights", "", "comma-separated heights to derive checkpoints for")
	timeout := fs.Duration("timeout", 60*time.Second, "overall RPC timeout for all requested heights")
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
	heights, err := parseHeights(*heightsFlag)
	if err != nil {
		return err
	}
	if len(heights) == 0 {
		return errors.New("--heights required (e.g. 1000000,5000000,10000000)")
	}
	if err := fetch.NewMultiClient(urls).Validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	type derivedCP struct {
		Height uint64
		Hash   chain.Hash
	}
	derived := make([]derivedCP, 0, len(heights))

	for _, h := range heights {
		hash, err := crossCheckAtHeight(ctx, urls, h)
		if err != nil {
			return fmt.Errorf("height %d: %w", h, err)
		}
		derived = append(derived, derivedCP{Height: h, Hash: hash})
	}

	// Publish only after the entire request succeeds. Hash agreement and valid
	// signatures do not authenticate operator independence or canonical history.
	var output bytes.Buffer
	fmt.Fprintln(&output, "// Mainnet (chain_id=1) observations; external provenance review required.")
	fmt.Fprintln(&output, "// Peer agreement does not prove elected producers, canonicality, or finality.")
	fmt.Fprintln(&output, "var mainnetCheckpoints = []Checkpoint{")
	for _, d := range derived {
		fmt.Fprintf(&output, "\t{Height: %d, HeaderHash: mustHash(%q)},\n", d.Height, hex.EncodeToString(d.Hash[:]))
	}
	fmt.Fprintln(&output, "}")
	n, err := stdout.Write(output.Bytes())
	if err == nil && n != output.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &checkpointOutputError{cause: err}
	}
	return nil
}

// crossCheckAtHeight fetches the Momentum at h from each peer in
// parallel and requires every configured endpoint to return the same signed
// envelope. It returns a hash only for a valid post-genesis mainnet signature.
func crossCheckAtHeight(ctx context.Context, urls []string, h uint64) (chain.Hash, error) {
	if len(urls) < 2 {
		return chain.Hash{}, errors.New("at least two distinct peers required")
	}
	if h < 2 {
		return chain.Hash{}, errors.New("checkpoint height must be after genesis")
	}
	// The shared client validates unique configured URLs, exact requested
	// height/count, local hashes, and agreement on the hash, key, and signature.
	multi := fetch.NewMultiClient(urls)
	headers, err := multi.FetchByHeight(ctx, h, 1)
	if err != nil {
		return chain.Hash{}, err
	}
	header := headers[0]
	if header.ChainIdentifier != 1 {
		return chain.Hash{}, errors.New("checkpoint observation is not mainnet chain_id=1")
	}
	if len(header.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(header.PublicKey, header.HeaderHash[:], header.Signature) {
		return chain.Hash{}, errors.New("invalid checkpoint signature")
	}
	return header.HeaderHash, nil
}

type checkpointOutputError struct{ cause error }

func (e *checkpointOutputError) Error() string {
	return "checkpoint output failed; stdout may be incomplete"
}

func (e *checkpointOutputError) Unwrap() error { return e.cause }

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

func parseHeights(s string) ([]uint64, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint64, 0, len(parts))
	seen := make(map[uint64]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, errors.New("invalid checkpoint height")
		}
		if v < 2 {
			return nil, errors.New("checkpoint heights must be after genesis")
		}
		if _, dup := seen[v]; dup {
			return nil, fmt.Errorf("duplicate height %d", v)
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
