package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// flag prints untrusted names and values before returning a syntax error.
// Keep that text private, including before JSON output has been selected.
// Explicit help keeps its existing usage text and exit-code contract.
func parsePrivateFlags(fs *flag.FlagSet, args []string, diagnostics io.Writer) error {
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	fs.SetOutput(diagnostics)
	if errors.Is(err, flag.ErrHelp) {
		fs.Usage()
	} else if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "arguments: invalid command syntax")
	}
	return err
}
